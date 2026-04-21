package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"

	"wing/config"
	"wing/rendezvous"
)

func captureOutput(t *testing.T, fn func()) string {
	t.Helper()
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
	return string(bytes.TrimSpace(b))
}

func TestResolveRendezvousTargetSelf(t *testing.T) {
	cfg := &config.Config{
		PublicKey: "self-pub",
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
		PublicKey: "self-pub",
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
		PublicKey: "self-pub",
	}
	if _, _, err := resolveRendezvousTarget(cfg, "missing"); err == nil {
		t.Fatalf("expected error for missing peer")
	}
}

func TestResolveRendezvousTargetAllHandledSeparately(t *testing.T) {
	cfg := &config.Config{
		PublicKey: "self-pub",
	}
	if _, _, err := resolveRendezvousTarget(cfg, "all"); err == nil {
		t.Fatalf("expected HandleRendezvousStatus to treat all specially before resolve")
	}
}

func TestWriteJSONProducesIndentedObject(t *testing.T) {
	out := captureOutput(t, func() {
		if err := writeJSON(map[string]string{"mode": "json"}); err != nil {
			t.Fatalf("writeJSON error: %v", err)
		}
	})
	if !strings.Contains(out, "\"mode\": \"json\"") {
		t.Fatalf("expected json output, got %q", out)
	}
	var decoded map[string]string
	if err := json.Unmarshal([]byte(out), &decoded); err != nil {
		t.Fatalf("json unmarshal error: %v", err)
	}
	if decoded["mode"] != "json" {
		t.Fatalf("decoded mode = %q, want %q", decoded["mode"], "json")
	}
}

func TestPrintRendezvousRecordWithIndent(t *testing.T) {
	record := &rendezvous.Record{
		Name:             "oak",
		WGPublicKey:      "peer-pub",
		ControlPublicKey: "ctrl-pub",
		Endpoint:         "1.2.3.4:51821",
		AllowedIPs:       []string{"10.7.0.2/32"},
		Sequence:         42,
		ObservedAt:       "2026-04-20T23:00:00Z",
		ExpiresAt:        "2026-04-20T23:01:00Z",
		Candidates: []rendezvous.Candidate{
			{Type: "configured", Address: "1.2.3.4:51821", Source: "config"},
		},
	}
	out := captureOutput(t, func() {
		printRendezvousRecordWithIndent(record, "xx")
	})
	if !strings.Contains(out, "xxsequence: 42") {
		t.Fatalf("expected custom indent, got %q", out)
	}
	if !strings.Contains(out, "xxname: oak") {
		t.Fatalf("expected name line, got %q", out)
	}
	if !strings.Contains(out, "xxendpoint: 1.2.3.4:51821") {
		t.Fatalf("expected endpoint line, got %q", out)
	}
	if !strings.Contains(out, "xxallowed_ips: 10.7.0.2/32") {
		t.Fatalf("expected allowed_ips line, got %q", out)
	}
	if !strings.Contains(out, "xx  - configured 1.2.3.4:51821 (config)") {
		t.Fatalf("expected candidate line, got %q", out)
	}
}
