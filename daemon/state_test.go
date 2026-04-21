package daemon

import (
	"testing"
	"time"

	"wing/config"
	"wing/rendezvous"
)

func newIssuedRecord(t *testing.T, rootPrivateKey, name, address, endpoint string) *rendezvous.Record {
	t.Helper()

	issued, err := config.IssuePeerIdentity(rootPrivateKey)
	if err != nil {
		t.Fatalf("IssuePeerIdentity error: %v", err)
	}
	cfg := &config.Config{
		Name:              name,
		PrivateKey:        issued.PrivateKey,
		PublicKey:         issued.PublicKey,
		ControlPrivateKey: issued.ControlPrivateKey,
		ControlPublicKey:  issued.ControlPublicKey,
		RootPublicKey:     issued.RootPublicKey,
		IdentitySignature: issued.IdentitySignature,
		MyEndpoint:        endpoint,
		Address:           address,
		ListenPort:        51821,
		Daemon: config.DaemonConfig{
			RecordTTL: 90,
		},
	}
	record, err := rendezvous.NewRecord(cfg, []rendezvous.Candidate{{
		Type:    "configured",
		Address: endpoint,
		Source:  "config",
	}}, time.Now())
	if err != nil {
		t.Fatalf("NewRecord error: %v", err)
	}
	return record
}

func TestReconcilePeerFromRecordUpdatesMetadata(t *testing.T) {
	peer := config.Peer{
		Name:             "old",
		PublicKey:        "peer-pub",
		Endpoint:         "1.1.1.1:51821",
		AllowedIPs:       []string{"10.7.0.2/32"},
		DynamicEndpoint:  true,
		ControlPublicKey: "control-pub",
	}
	record := &rendezvous.Record{
		Name:             "new",
		WGPublicKey:      "peer-pub",
		ControlPublicKey: "control-pub",
		Endpoint:         "2.2.2.2:51821",
		AllowedIPs:       []string{"10.7.0.9/32"},
		Candidates:       []rendezvous.Candidate{{Type: "configured", Address: "2.2.2.2:51821"}},
	}

	updated, metadataChanged, runtimeChanged := reconcilePeerFromRecord(peer, record)
	if !metadataChanged {
		t.Fatalf("expected metadata change")
	}
	if !runtimeChanged {
		t.Fatalf("expected runtime change")
	}
	if updated.Name != "new" {
		t.Fatalf("Name = %q, want %q", updated.Name, "new")
	}
	if updated.Endpoint != "2.2.2.2:51821" {
		t.Fatalf("Endpoint = %q, want %q", updated.Endpoint, "2.2.2.2:51821")
	}
	if len(updated.AllowedIPs) != 1 || updated.AllowedIPs[0] != "10.7.0.9/32" {
		t.Fatalf("AllowedIPs = %v, want [10.7.0.9/32]", updated.AllowedIPs)
	}
}

func TestReconcilePeerFromRecordFallsBackToBestCandidate(t *testing.T) {
	peer := config.Peer{
		Name:             "oak",
		PublicKey:        "peer-pub",
		Endpoint:         "1.1.1.1:51821",
		AllowedIPs:       []string{"10.7.0.2/32"},
		DynamicEndpoint:  true,
		ControlPublicKey: "control-pub",
	}
	record := &rendezvous.Record{
		Name:             "oak",
		WGPublicKey:      "peer-pub",
		ControlPublicKey: "control-pub",
		AllowedIPs:       []string{"10.7.0.2/32"},
		Candidates: []rendezvous.Candidate{
			{Type: "host", Address: "192.168.1.10:51821"},
			{Type: "srflx", Address: "203.0.113.10:51821"},
		},
	}

	updated, metadataChanged, runtimeChanged := reconcilePeerFromRecord(peer, record)
	if !metadataChanged || !runtimeChanged {
		t.Fatalf("expected endpoint update from best candidate")
	}
	if updated.Endpoint != "203.0.113.10:51821" {
		t.Fatalf("Endpoint = %q, want %q", updated.Endpoint, "203.0.113.10:51821")
	}
}

func TestReconcilePeerFromRecordNoChange(t *testing.T) {
	peer := config.Peer{
		Name:             "oak",
		PublicKey:        "peer-pub",
		Endpoint:         "1.1.1.1:51821",
		AllowedIPs:       []string{"10.7.0.2/32"},
		DynamicEndpoint:  true,
		ControlPublicKey: "control-pub",
	}
	record := &rendezvous.Record{
		Name:             "oak",
		WGPublicKey:      "peer-pub",
		ControlPublicKey: "control-pub",
		Endpoint:         "1.1.1.1:51821",
		AllowedIPs:       []string{"10.7.0.2/32"},
		Candidates:       []rendezvous.Candidate{{Type: "configured", Address: "1.1.1.1:51821"}},
	}

	updated, metadataChanged, runtimeChanged := reconcilePeerFromRecord(peer, record)
	if metadataChanged || runtimeChanged {
		t.Fatalf("expected no change, got metadata=%t runtime=%t", metadataChanged, runtimeChanged)
	}
	if updated.Name != peer.Name || updated.PublicKey != peer.PublicKey || updated.Endpoint != peer.Endpoint || !sameAllowedIPs(updated.AllowedIPs, peer.AllowedIPs) {
		t.Fatalf("expected unchanged peer, got %+v", updated)
	}
}

func TestResolvePeerFromRecordAdoptsUnknownTrustedPeer(t *testing.T) {
	rootPriv, rootPub, err := config.GenerateRootKeypair()
	if err != nil {
		t.Fatalf("GenerateRootKeypair error: %v", err)
	}
	record := newIssuedRecord(t, rootPriv, "maple", "10.7.0.9/32", "203.0.113.20:51821")
	d := &State{
		cfg: &config.Config{
			RootPublicKey: rootPub,
			Daemon: config.DaemonConfig{
				RetryInitial: 1,
			},
		},
	}

	peer, added, err := d.resolvePeerFromRecord(config.Peer{}, false, record)
	if err != nil {
		t.Fatalf("resolvePeerFromRecord error: %v", err)
	}
	if !added {
		t.Fatalf("expected unknown peer to be adopted")
	}
	if peer.Name != "maple" {
		t.Fatalf("Name = %q, want %q", peer.Name, "maple")
	}
	if peer.PublicKey != record.WGPublicKey {
		t.Fatalf("PublicKey = %q, want %q", peer.PublicKey, record.WGPublicKey)
	}
	if peer.ControlPublicKey != record.ControlPublicKey {
		t.Fatalf("ControlPublicKey = %q, want %q", peer.ControlPublicKey, record.ControlPublicKey)
	}
	if peer.RootPublicKey != rootPub {
		t.Fatalf("RootPublicKey = %q, want %q", peer.RootPublicKey, rootPub)
	}
	if peer.Endpoint != "203.0.113.20:51821" {
		t.Fatalf("Endpoint = %q, want %q", peer.Endpoint, "203.0.113.20:51821")
	}
	if !sameAllowedIPs(peer.AllowedIPs, []string{"10.7.0.9/32"}) {
		t.Fatalf("AllowedIPs = %v, want [10.7.0.9/32]", peer.AllowedIPs)
	}
	if !peer.DynamicEndpoint {
		t.Fatalf("expected DynamicEndpoint to be true")
	}
	if peer.Keepalive != 25 {
		t.Fatalf("Keepalive = %d, want 25", peer.Keepalive)
	}
}

func TestResolvePeerFromRecordRejectsUnknownPeerFromAnotherRoot(t *testing.T) {
	_, trustedRootPub, err := config.GenerateRootKeypair()
	if err != nil {
		t.Fatalf("GenerateRootKeypair trusted root error: %v", err)
	}
	otherRootPriv, _, err := config.GenerateRootKeypair()
	if err != nil {
		t.Fatalf("GenerateRootKeypair other root error: %v", err)
	}
	record := newIssuedRecord(t, otherRootPriv, "birch", "10.7.0.8/32", "198.51.100.40:51821")
	d := &State{
		cfg: &config.Config{
			RootPublicKey: trustedRootPub,
			Daemon: config.DaemonConfig{
				RetryInitial: 1,
			},
		},
	}

	_, added, err := d.resolvePeerFromRecord(config.Peer{}, false, record)
	if err == nil {
		t.Fatalf("expected resolvePeerFromRecord to reject mismatched root")
	}
	if added {
		t.Fatalf("expected unknown peer not to be adopted")
	}
}
