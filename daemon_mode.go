package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"wing/config"
	"wing/rendezvous"
	"wing/stun"
	"wing/wireguard"
)

type daemonState struct {
	cfg        *config.Config
	peerState  map[string]*peerAttemptState
	candidates []rendezvous.Candidate
}

type peerAttemptState struct {
	backoff      time.Duration
	nextAttempt  time.Time
	lastSequence uint64
	lastEndpoint string
}

func runDaemon(cfgPath string, cfg *config.Config, wgGoPath string, reuse bool) error {
	if err := persistRuntimeIdentity(cfgPath, cfg); err != nil {
		return err
	}
	runtimeCfg := daemonRuntimeConfig(cfg)
	initialCandidates := discoverCandidates(context.Background(), cfg, true)
	sess, err := startSession(runtimeCfg, wgGoPath, reuse, false)
	if err != nil {
		return err
	}
	defer sess.cleanup()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	state := &daemonState{
		cfg:        runtimeCfg,
		peerState:  make(map[string]*peerAttemptState, len(runtimeCfg.Peers)),
		candidates: initialCandidates,
	}
	for _, peer := range runtimeCfg.Peers {
		state.peerState[peer.PublicKey] = &peerAttemptState{
			backoff: time.Duration(runtimeCfg.Daemon.RetryInitial) * time.Second,
		}
	}

	fmt.Printf("daemon: up %s (os=%s, addr=%s)\n", runtimeCfg.Interface, sess.osIface, runtimeCfg.Address)
	_ = state.publish(ctx, initialCandidates)
	_ = state.refreshPeers(ctx)

	reconcileTicker := time.NewTicker(time.Second)
	defer reconcileTicker.Stop()
	publishTicker := time.NewTicker(time.Duration(runtimeCfg.Daemon.PublishInterval) * time.Second)
	defer publishTicker.Stop()
	fetchTicker := time.NewTicker(time.Duration(runtimeCfg.Daemon.FetchInterval) * time.Second)
	defer fetchTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-publishTicker.C:
			candidates := discoverCandidates(ctx, runtimeCfg, false)
			state.candidates = candidates
			if err := state.publish(ctx, candidates); err != nil {
				fmt.Fprintf(os.Stderr, "daemon publish: %v\n", err)
			}
		case <-fetchTicker.C:
			if err := state.refreshPeers(ctx); err != nil {
				fmt.Fprintf(os.Stderr, "daemon fetch: %v\n", err)
			}
		case <-reconcileTicker.C:
			if err := state.retryPeers(); err != nil {
				fmt.Fprintf(os.Stderr, "daemon retry: %v\n", err)
			}
		}
	}
}

func daemonRuntimeConfig(cfg *config.Config) *config.Config {
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

func (d *daemonState) publish(ctx context.Context, candidates []rendezvous.Candidate) error {
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

func (d *daemonState) refreshPeers(ctx context.Context) error {
	urls := config.EffectiveRendezvousURLs(d.cfg)
	if len(urls) == 0 {
		return nil
	}
	for _, peer := range d.cfg.Peers {
		if !peer.DynamicEndpoint {
			continue
		}
		record, err := rendezvous.FetchLatest(ctx, urls, peer.PublicKey)
		if err != nil {
			return err
		}
		if record == nil {
			continue
		}
		if err := record.VerifyForPeer(peer); err != nil {
			fmt.Fprintf(os.Stderr, "daemon peer %s: %v\n", peer.Name, err)
			continue
		}
		endpoint := rendezvous.BestEndpoint(record)
		if endpoint == "" {
			continue
		}
		attempt := d.peerState[peer.PublicKey]
		if attempt == nil {
			attempt = &peerAttemptState{backoff: time.Duration(d.cfg.Daemon.RetryInitial) * time.Second}
			d.peerState[peer.PublicKey] = attempt
		}
		if record.Sequence <= attempt.lastSequence && endpoint == attempt.lastEndpoint {
			continue
		}
		if err := wireguard.UpdatePeerEndpoint(d.cfg.Interface, peer, endpoint, config.EffectiveKeepalive(peer, d.cfg.Daemon.AutoKeepalive)); err != nil {
			return err
		}
		attempt.lastSequence = record.Sequence
		attempt.lastEndpoint = endpoint
		attempt.nextAttempt = time.Now()
		if err := wireguard.TriggerPeerHandshake(peer, d.cfg.Daemon.ProbePort); err != nil {
			fmt.Fprintf(os.Stderr, "daemon handshake trigger for %s: %v\n", peer.Name, err)
		}
	}
	return nil
}

func (d *daemonState) retryPeers() error {
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

func discoverCandidates(ctx context.Context, cfg *config.Config, exactPort bool) []rendezvous.Candidate {
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

func persistRuntimeIdentity(cfgPath string, cfg *config.Config) error {
	before := *cfg
	if err := config.EnsureRuntimeIdentity(cfg); err != nil {
		return err
	}
	if before.MyPublicKey == cfg.MyPublicKey &&
		before.ControlPrivateKey == cfg.ControlPrivateKey &&
		before.ControlPublicKey == cfg.ControlPublicKey {
		return nil
	}
	return config.Write(cfgPath, cfg)
}
