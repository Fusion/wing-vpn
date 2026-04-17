package main

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"wing/config"
)

func TestExportImportRoundTrip(t *testing.T) {
	_, pub, err := config.GenerateKeypair()
	if err != nil {
		t.Fatalf("generateKeypair error: %v", err)
	}

	cfg := &config.Config{
		Interface:   "wgwing0",
		MyPublicKey: pub,
		MyEndpoint:  "1.2.3.4:51821",
		Address:     "10.7.0.1",
		Peers:       []config.Peer{},
	}

	out := captureStdout(t, func() {
		if err := handleExport(cfg); err != nil {
			t.Fatalf("handleExport error: %v", err)
		}
	})

	out = strings.TrimSpace(out)
	if out == "" {
		t.Fatalf("export output empty")
	}

	var peer config.Peer
	if err := json.Unmarshal([]byte(out), &peer); err != nil {
		t.Fatalf("export json invalid: %v", err)
	}

	path := filepath.Join(t.TempDir(), "self.json")
	cfg2 := &config.Config{Interface: "wgwing0", Peers: []config.Peer{}}
	if err := config.Write(path, cfg2); err != nil {
		t.Fatalf("writeConfig error: %v", err)
	}

	withStdin(t, out, func() {
		if err := handleImport(path, cfg2); err != nil {
			t.Fatalf("handleImport error: %v", err)
		}
	})

	cfg3, err := config.Load(path)
	if err != nil {
		t.Fatalf("loadConfig error: %v", err)
	}
	if len(cfg3.Peers) != 1 {
		t.Fatalf("expected 1 peer, got %d", len(cfg3.Peers))
	}
	p := cfg3.Peers[0]
	if p.PublicKey != peer.PublicKey {
		t.Fatalf("public_key mismatch: %q vs %q", p.PublicKey, peer.PublicKey)
	}
	if p.Endpoint != peer.Endpoint {
		t.Fatalf("endpoint mismatch: %q vs %q", p.Endpoint, peer.Endpoint)
	}
	if len(p.AllowedIPs) != 1 || p.AllowedIPs[0] != "10.7.0.1/32" {
		t.Fatalf("allowed_ips mismatch: %v", p.AllowedIPs)
	}
}

func captureStdout(t *testing.T, fn func()) string {
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe error: %v", err)
	}
	os.Stdout = w
	fn()
	_ = w.Close()
	os.Stdout = old
	b, _ := io.ReadAll(r)
	return string(b)
}

func withStdin(t *testing.T, input string, fn func()) {
	old := os.Stdin
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe error: %v", err)
	}
	_, _ = w.Write([]byte(input))
	_ = w.Close()
	os.Stdin = r
	fn()
	os.Stdin = old
}

func TestImportRejectsDuplicateName(t *testing.T) {
	_, pub, err := config.GenerateKeypair()
	if err != nil {
		t.Fatalf("generateKeypair error: %v", err)
	}
	cfg := &config.Config{Interface: "wgwing0", Peers: []config.Peer{{Name: "dup", PublicKey: pub, Endpoint: "1.1.1.1:1", AllowedIPs: []string{"10.0.0.1/32"}, Keepalive: 25}}}
	path := filepath.Join(t.TempDir(), "self.json")
	if err := config.Write(path, cfg); err != nil {
		t.Fatalf("writeConfig error: %v", err)
	}

	_, pub2, err := config.GenerateKeypair()
	if err != nil {
		t.Fatalf("generateKeypair error: %v", err)
	}
	peerJSON := `{
  "name": "dup",
  "public_key": "` + pub2 + `",
  "endpoint": "1.2.3.4:51821",
  "allowed_ips": ["10.7.0.2/32"],
  "keepalive": 25
}`

	withStdin(t, peerJSON, func() {
		err := handleImport(path, cfg)
		if err == nil {
			t.Fatalf("expected duplicate name error")
		}
	})
}
