package main

import (
	"testing"

	"wing/config"
)

func TestResolveRendezvousTargetSelf(t *testing.T) {
	cfg := &config.Config{
		MyPublicKey: "self-pub",
	}
	label, pub, err := resolveRendezvousTarget(cfg, "self")
	if err != nil {
		t.Fatalf("resolveRendezvousTarget error: %v", err)
	}
	if label != "self" || pub != "self-pub" {
		t.Fatalf("got (%q, %q), want (%q, %q)", label, pub, "self", "self-pub")
	}
}

func TestResolveRendezvousTargetPeerByName(t *testing.T) {
	cfg := &config.Config{
		MyPublicKey: "self-pub",
		Peers: []config.Peer{
			{Name: "oak", PublicKey: "peer-pub"},
		},
	}
	label, pub, err := resolveRendezvousTarget(cfg, "oak")
	if err != nil {
		t.Fatalf("resolveRendezvousTarget error: %v", err)
	}
	if label != "oak" || pub != "peer-pub" {
		t.Fatalf("got (%q, %q), want (%q, %q)", label, pub, "oak", "peer-pub")
	}
}

func TestResolveRendezvousTargetMissingPeer(t *testing.T) {
	cfg := &config.Config{
		MyPublicKey: "self-pub",
	}
	if _, _, err := resolveRendezvousTarget(cfg, "missing"); err == nil {
		t.Fatalf("expected error for missing peer")
	}
}
