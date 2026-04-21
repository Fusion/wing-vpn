package daemon

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"slices"
	"strings"
	"time"

	"wing/config"
	"wing/rendezvous"
	"wing/stun"
	"wing/wireguard"
)

type State struct {
	cfgPath    string
	osIface    string
	cfg        *config.Config
	peerState  map[string]*peerAttemptState
	Candidates []rendezvous.Candidate
}

type peerAttemptState struct {
	backoff      time.Duration
	nextAttempt  time.Time
	lastSequence uint64
	lastEndpoint string
}

func NewState(cfgPath, osIface string, cfg *config.Config, initialCandidates []rendezvous.Candidate) *State {
	state := &State{
		cfgPath:    cfgPath,
		osIface:    osIface,
		cfg:        cfg,
		peerState:  make(map[string]*peerAttemptState, len(cfg.Peers)),
		Candidates: initialCandidates,
	}
	for _, peer := range cfg.Peers {
		state.peerState[peer.PublicKey] = &peerAttemptState{
			backoff: time.Duration(cfg.Daemon.RetryInitial) * time.Second,
		}
	}
	return state
}

func RuntimeConfig(cfg *config.Config) *config.Config {
	cloned := *cfg
	cloned.Peers = append([]config.Peer(nil), cfg.Peers...)
	for i := range cloned.Peers {
		if cloned.Peers[i].DynamicEndpoint && cloned.Peers[i].Endpoint == "" {
			cloned.Peers[i].DynamicEndpoint = true
		}
		if keepalive := config.EffectiveKeepalive(cloned.Peers[i], cloned.Daemon.AutoKeepalive); keepalive > 0 {
			cloned.Peers[i].Keepalive = keepalive
		}
	}
	return &cloned
}

func (d *State) Publish(ctx context.Context, candidates []rendezvous.Candidate) error {
	urls := config.EffectiveRendezvousURLs(d.cfg)
	if len(urls) == 0 {
		return nil
	}
	record, err := rendezvous.NewRecord(d.cfg, candidates, time.Now())
	if err != nil {
		return err
	}
	return rendezvous.PublishAll(ctx, urls, record)
}

// RefreshPeers consumes the merged rendezvous directory, updates trusted known
// peers, and can adopt previously unknown peers only when their identity chains
// to the local trusted root.
func (d *State) RefreshPeers(ctx context.Context) error {
	urls := config.EffectiveRendezvousURLs(d.cfg)
	if len(urls) == 0 {
		return nil
	}
	records, err := fetchMergedRecords(ctx, urls)
	if err != nil {
		return err
	}
	peerIndex := make(map[string]int, len(d.cfg.Peers))
	for i, peer := range d.cfg.Peers {
		peerIndex[peer.PublicKey] = i
	}
	dirty := false
	keys := make([]string, 0, len(records))
	for key := range records {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	for _, key := range keys {
		record := records[key]
		if record.WGPublicKey == d.cfg.PublicKey {
			continue
		}

		idx, known := peerIndex[record.WGPublicKey]
		var peer config.Peer
		if known {
			peer = d.cfg.Peers[idx]
		}
		resolvedPeer, added, err := d.resolvePeerFromRecord(peer, known, &record)
		if err != nil {
			label := record.Name
			if strings.TrimSpace(label) == "" {
				label = record.WGPublicKey
			}
			fmt.Fprintf(os.Stderr, "daemon peer %s: %v\n", label, err)
			continue
		}
		if added {
			d.cfg.Peers = append(d.cfg.Peers, resolvedPeer)
			idx = len(d.cfg.Peers) - 1
			peerIndex[resolvedPeer.PublicKey] = idx
			peer = config.Peer{}
			dirty = true
		}
		updatedPeer, metadataChanged, runtimeChanged := reconcilePeerFromRecord(resolvedPeer, &record)
		endpoint := updatedPeer.Endpoint
		attempt := d.peerState[updatedPeer.PublicKey]
		if attempt == nil {
			attempt = &peerAttemptState{backoff: time.Duration(d.cfg.Daemon.RetryInitial) * time.Second}
			d.peerState[updatedPeer.PublicKey] = attempt
		}
		if !metadataChanged && record.Sequence <= attempt.lastSequence && endpoint == attempt.lastEndpoint {
			continue
		}
		if runtimeChanged || endpoint != "" || added {
			if err := d.applyPeerUpdate(peer, updatedPeer); err != nil {
				return err
			}
		}
		d.cfg.Peers[idx] = updatedPeer
		if metadataChanged {
			dirty = true
		}
		attempt.lastSequence = record.Sequence
		attempt.lastEndpoint = endpoint
		attempt.nextAttempt = time.Now()
		if endpoint != "" {
			if err := wireguard.TriggerPeerHandshake(updatedPeer, d.cfg.Daemon.ProbePort); err != nil {
				fmt.Fprintf(os.Stderr, "daemon handshake trigger for %s: %v\n", updatedPeer.Name, err)
			}
		}
	}
	if dirty {
		if err := config.Write(d.cfgPath, d.cfg); err != nil {
			return err
		}
	}
	return nil
}

// applyPeerUpdate pushes the peer into live WireGuard state. For newly adopted
// peers, previous is empty, so route removal intentionally becomes a no-op.
func (d *State) applyPeerUpdate(previous, updated config.Peer) error {
	if !sameAllowedIPs(previous.AllowedIPs, updated.AllowedIPs) && !d.cfg.DisableRoutes {
		wireguard.RemovePeerRoutes(d.osIface, []config.Peer{previous})
		if err := wireguard.AddPeerRoutes(d.osIface, []config.Peer{updated}); err != nil {
			return err
		}
	}
	return wireguard.UpdatePeer(d.cfg.Interface, updated, config.EffectiveKeepalive(updated, d.cfg.Daemon.AutoKeepalive))
}

func (d *State) RetryPeers() error {
	states, err := wireguard.PeerStates(d.cfg.Interface)
	if err != nil {
		return err
	}
	now := time.Now()
	for _, peer := range d.cfg.Peers {
		attempt := d.peerState[peer.PublicKey]
		if attempt == nil {
			attempt = &peerAttemptState{backoff: time.Duration(d.cfg.Daemon.RetryInitial) * time.Second}
			d.peerState[peer.PublicKey] = attempt
		}
		if connected(states[peer.PublicKey], now) {
			attempt.backoff = time.Duration(d.cfg.Daemon.RetryInitial) * time.Second
			attempt.nextAttempt = time.Time{}
			continue
		}
		if !attempt.nextAttempt.IsZero() && now.Before(attempt.nextAttempt) {
			continue
		}
		endpoint := attempt.lastEndpoint
		if endpoint == "" {
			endpoint = peer.Endpoint
		}
		if endpoint != "" {
			if err := wireguard.UpdatePeerEndpoint(d.cfg.Interface, peer, endpoint, config.EffectiveKeepalive(peer, d.cfg.Daemon.AutoKeepalive)); err != nil {
				return err
			}
		}
		if err := wireguard.TriggerPeerHandshake(peer, d.cfg.Daemon.ProbePort); err != nil {
			fmt.Fprintf(os.Stderr, "daemon retry trigger for %s: %v\n", peer.Name, err)
		}
		if attempt.backoff <= 0 {
			attempt.backoff = time.Duration(d.cfg.Daemon.RetryInitial) * time.Second
		}
		attempt.nextAttempt = now.Add(attempt.backoff)
		attempt.backoff *= 2
		maxBackoff := time.Duration(d.cfg.Daemon.RetryMax) * time.Second
		if attempt.backoff > maxBackoff {
			attempt.backoff = maxBackoff
		}
	}
	return nil
}

func connected(state wireguard.PeerState, now time.Time) bool {
	if state.PublicKey == "" || state.LastHandshake.IsZero() {
		return false
	}
	window := 90 * time.Second
	if state.Keepalive > 0 {
		window = 3 * state.Keepalive
	}
	return now.Sub(state.LastHandshake) <= window
}

// DiscoverCandidates prefers exact-port reflexive discovery at startup. Later
// refreshes may only be able to publish guessed-port candidates while the WG
// socket already owns the listen port.
func DiscoverCandidates(ctx context.Context, cfg *config.Config, exactPort bool) []rendezvous.Candidate {
	var candidates []rendezvous.Candidate
	if endpoint := strings.TrimSpace(cfg.MyEndpoint); endpoint != "" {
		candidates = append(candidates, rendezvous.Candidate{Type: "configured", Address: endpoint, Source: "config"})
	}
	candidates = append(candidates, hostCandidates(cfg.ListenPort)...)
	stunPort := 0
	if exactPort {
		stunPort = cfg.ListenPort
	}
	results, err := stun.ProbeServers(ctx, cfg.Daemon.STUNServers, stunPort)
	if err == nil {
		for _, result := range results {
			if exactPort && result.Reflexive != "" {
				candidates = append(candidates, rendezvous.Candidate{Type: "srflx", Address: result.Reflexive, Source: result.Server})
			}
			if !exactPort && result.GuessedPort != "" {
				candidates = append(candidates, rendezvous.Candidate{Type: "srflx-guess", Address: result.GuessedPort, Source: result.Server})
			}
		}
	}
	return candidates
}

func hostCandidates(listenPort int) []rendezvous.Candidate {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var candidates []rendezvous.Candidate
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() || ip.To4() == nil {
				continue
			}
			candidates = append(candidates, rendezvous.Candidate{
				Type:    "host",
				Address: net.JoinHostPort(ip.String(), fmt.Sprintf("%d", listenPort)),
				Source:  iface.Name,
			})
		}
	}
	return candidates
}

// Redundant rendezvous servers act as untrusted replicas; the freshest signed
// record wins by sequence across the set.
func fetchMergedRecords(ctx context.Context, urls []string) (map[string]rendezvous.Record, error) {
	merged := make(map[string]rendezvous.Record)
	var errs []string
	successes := 0
	for _, baseURL := range urls {
		records, err := rendezvous.FetchAll(ctx, baseURL)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", baseURL, err))
			continue
		}
		successes++
		for _, record := range records {
			current, ok := merged[record.WGPublicKey]
			if !ok || record.Sequence > current.Sequence {
				merged[record.WGPublicKey] = record
			}
		}
	}
	if successes == 0 && len(urls) > 0 {
		return nil, fmt.Errorf("rendezvous fetch failed: %s", strings.Join(errs, "; "))
	}
	return merged, nil
}

// resolvePeerFromRecord enforces the trust policy before any endpoint or route
// update happens. Known peers prefer their existing identity binding; unknown
// peers are adopted only when the record chains to the local trusted root.
func (d *State) resolvePeerFromRecord(peer config.Peer, known bool, record *rendezvous.Record) (config.Peer, bool, error) {
	if record == nil {
		return config.Peer{}, false, errors.New("record is nil")
	}
	if err := record.Verify(); err != nil {
		return config.Peer{}, false, err
	}
	trustedRoot := strings.TrimSpace(d.cfg.RootPublicKey)
	if known {
		if strings.TrimSpace(peer.RootPublicKey) != "" {
			trustedRoot = strings.TrimSpace(peer.RootPublicKey)
		}
		if peer.PublicKey != record.WGPublicKey {
			return config.Peer{}, false, fmt.Errorf("record wg_public_key mismatch: %s", record.WGPublicKey)
		}
		if peer.ControlPublicKey != "" && peer.ControlPublicKey == record.ControlPublicKey && (peer.RootPublicKey == "" || peer.RootPublicKey == record.RootPublicKey) {
			return reconcilePeerIdentity(peer, record), false, nil
		}
		if trustedRoot == "" {
			return config.Peer{}, false, errors.New("peer control_public_key mismatch and no trusted root is available")
		}
		if record.RootPublicKey != trustedRoot {
			return config.Peer{}, false, errors.New("record root_public_key mismatch")
		}
		return reconcilePeerIdentity(peer, record), false, nil
	}

	if trustedRoot == "" {
		return config.Peer{}, false, errors.New("cannot adopt unknown peer without local root_public_key")
	}
	if record.RootPublicKey != trustedRoot {
		return config.Peer{}, false, errors.New("unknown peer root_public_key is not trusted locally")
	}
	return peerFromRecord(record), true, nil
}

// reconcilePeerIdentity refreshes the trusted identity material only. Live
// endpoint and route changes are applied later after trust is established.
func reconcilePeerIdentity(peer config.Peer, record *rendezvous.Record) config.Peer {
	if record == nil {
		return peer
	}
	peer.ControlPublicKey = record.ControlPublicKey
	peer.RootPublicKey = record.RootPublicKey
	peer.IdentitySignature = record.IdentitySignature
	if strings.TrimSpace(record.Name) != "" {
		peer.Name = strings.TrimSpace(record.Name)
	}
	if peer.Keepalive <= 0 {
		peer.Keepalive = 25
	}
	peer.DynamicEndpoint = true
	return peer
}

func peerFromRecord(record *rendezvous.Record) config.Peer {
	peer := config.Peer{
		Name:              strings.TrimSpace(record.Name),
		PublicKey:         record.WGPublicKey,
		ControlPublicKey:  record.ControlPublicKey,
		RootPublicKey:     record.RootPublicKey,
		IdentitySignature: record.IdentitySignature,
		Endpoint:          strings.TrimSpace(record.Endpoint),
		DynamicEndpoint:   true,
		AllowedIPs:        append([]string(nil), record.AllowedIPs...),
		Keepalive:         25,
	}
	if peer.Name == "" {
		peer.Name = record.WGPublicKey
	}
	if peer.Endpoint == "" {
		peer.Endpoint = rendezvous.BestEndpoint(record)
	}
	return peer
}

// reconcilePeerFromRecord applies signed peer metadata to runtime state after
// the record has already passed identity and root verification.
func reconcilePeerFromRecord(peer config.Peer, record *rendezvous.Record) (config.Peer, bool, bool) {
	updated := peer
	metadataChanged := false
	runtimeChanged := false

	if record == nil {
		return updated, false, false
	}
	if name := strings.TrimSpace(record.Name); name != "" && name != updated.Name {
		updated.Name = name
		metadataChanged = true
	}

	desiredEndpoint := strings.TrimSpace(record.Endpoint)
	if desiredEndpoint == "" {
		desiredEndpoint = rendezvous.BestEndpoint(record)
	}
	if desiredEndpoint != "" && desiredEndpoint != updated.Endpoint {
		updated.Endpoint = desiredEndpoint
		metadataChanged = true
		runtimeChanged = true
	}

	if len(record.AllowedIPs) > 0 && !sameAllowedIPs(updated.AllowedIPs, record.AllowedIPs) {
		updated.AllowedIPs = append([]string(nil), record.AllowedIPs...)
		metadataChanged = true
		runtimeChanged = true
	}

	return updated, metadataChanged, runtimeChanged
}

func sameAllowedIPs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
