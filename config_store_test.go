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
}

func TestWriteConfigPeersNotNull(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "c.json")
	cfg := &config.Config{Interface: "wgwing0", PrivateKey: "x", Peers: nil}
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
