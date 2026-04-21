package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"wing/config"
)

func TestSelfConfigPathUsesEnv(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("WING_STATE_DIR", dir)
	path, err := config.SelfPath()
	if err != nil {
		t.Fatalf("selfConfigPath error: %v", err)
	}
	want := filepath.Join(dir, "self.json")
	if path != want {
		t.Fatalf("selfConfigPath = %q, want %q", path, want)
	}
}

func TestInitConfigAtCreatesPeersArray(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "self.json")
	created, err := config.InitAt(path)
	if err != nil {
		t.Fatalf("initConfigAt error: %v", err)
	}
	if !created {
		t.Fatalf("initConfigAt expected created=true")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read file error: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	v, ok := m["peers"]
	if !ok {
		t.Fatalf("missing peers key")
	}
	if _, ok := v.([]any); !ok {
		t.Fatalf("peers is not array, got %T", v)
	}
	if _, ok := m["control_public_key"].(string); !ok {
		t.Fatalf("control_public_key missing or not a string")
	}
	if daemon, ok := m["daemon"].(map[string]any); !ok {
		t.Fatalf("daemon missing or wrong type: %T", m["daemon"])
	} else if _, ok := daemon["stun_servers"].([]any); !ok {
		t.Fatalf("daemon.stun_servers missing or wrong type")
	}
}

func TestWriteConfigPeersNotNull(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "c.json")
	priv, pub, err := config.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair error: %v", err)
	}
	cpriv, cpub, err := config.GenerateControlKeypair()
	if err != nil {
		t.Fatalf("GenerateControlKeypair error: %v", err)
	}
	cfg := &config.Config{
		Interface:         "wgwing0",
		PrivateKey:        priv,
		PublicKey:         pub,
		ControlPrivateKey: cpriv,
		ControlPublicKey:  cpub,
		Peers:             nil,
	}
	if err := config.Write(path, cfg); err != nil {
		t.Fatalf("writeConfig error: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read file error: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	v, ok := m["peers"]
	if !ok {
		t.Fatalf("missing peers key")
	}
	if _, ok := v.([]any); !ok {
		t.Fatalf("peers is not array, got %T", v)
	}
}

func TestEnsureRuntimeIdentityBackfillsControlKeys(t *testing.T) {
	cfg := &config.Config{Interface: "wgwing0"}
	if err := config.EnsureRuntimeIdentity(cfg); err != nil {
		t.Fatalf("EnsureRuntimeIdentity error: %v", err)
	}
	if cfg.ControlPrivateKey == "" {
		t.Fatalf("expected control private key")
	}
	if cfg.ControlPublicKey == "" {
		t.Fatalf("expected control public key")
	}
}

func TestIssuePeerIdentityProducesVerifiableBundle(t *testing.T) {
	rootPriv, rootPub, err := config.GenerateRootKeypair()
	if err != nil {
		t.Fatalf("GenerateRootKeypair error: %v", err)
	}
	issued, err := config.IssuePeerIdentity(rootPriv)
	if err != nil {
		t.Fatalf("IssuePeerIdentity error: %v", err)
	}
	if issued.RootPublicKey != rootPub {
		t.Fatalf("root public key mismatch: %q vs %q", issued.RootPublicKey, rootPub)
	}
	if err := config.VerifyIdentityBinding(issued.RootPublicKey, issued.PublicKey, issued.ControlPublicKey, issued.IdentitySignature); err != nil {
		t.Fatalf("VerifyIdentityBinding error: %v", err)
	}
}

func TestEffectiveRendezvousURLsDedupesConfiguredList(t *testing.T) {
	cfg := &config.Config{}
	cfg.Rendezvous.URLs = []string{
		"http://rv1.example.com:8787",
		"http://rv2.example.com:8787",
		"http://rv1.example.com:8787",
		"  ",
	}
	got := config.EffectiveRendezvousURLs(cfg)
	if len(got) != 2 {
		t.Fatalf("expected 2 urls, got %v", got)
	}
	if got[0] != "http://rv1.example.com:8787" || got[1] != "http://rv2.example.com:8787" {
		t.Fatalf("unexpected urls: %v", got)
	}
}
