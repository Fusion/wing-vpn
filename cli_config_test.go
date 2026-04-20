package main

import (
	"testing"

	"wing/config"
)

func TestNormalizeAddress(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"10.0.0.1", "10.0.0.1/32", true},
		{"10.0.0.1/32", "10.0.0.1/32", true},
		{"", "", false},
		{"nope", "", false},
		{"10.0.0.1/33", "", false},
	}

	for _, c := range cases {
		got, err := config.NormalizeAddress(c.in)
		if c.ok && err != nil {
			t.Fatalf("normalizeAddress(%q) error: %v", c.in, err)
		}
		if !c.ok && err == nil {
			t.Fatalf("normalizeAddress(%q) expected error", c.in)
		}
		if c.ok && got != c.want {
			t.Fatalf("normalizeAddress(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestNormalizeEndpointHostPort(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"1.2.3.4:51821", "1.2.3.4:51821", true},
		{"example.com:123", "example.com:123", true},
		{"example.com/123", "", false},
		{"example.com:0", "", false},
		{"example.com", "", false},
	}

	for _, c := range cases {
		got, err := config.NormalizeEndpointHostPort(c.in)
		if c.ok && err != nil {
			t.Fatalf("normalizeEndpointHostPort(%q) error: %v", c.in, err)
		}
		if !c.ok && err == nil {
			t.Fatalf("normalizeEndpointHostPort(%q) expected error", c.in)
		}
		if c.ok && got != c.want {
			t.Fatalf("normalizeEndpointHostPort(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestNormalizeImportPeerAllowsDynamicEndpointWithoutStaticEndpoint(t *testing.T) {
	_, pub, err := config.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair error: %v", err)
	}
	_, controlPub, err := config.GenerateControlKeypair()
	if err != nil {
		t.Fatalf("GenerateControlKeypair error: %v", err)
	}
	peer, err := config.NormalizeImportPeer(config.Peer{
		Name:             "peer1",
		PublicKey:        pub,
		ControlPublicKey: controlPub,
		DynamicEndpoint:  true,
		AllowedIPs:       []string{"10.0.0.2"},
	})
	if err != nil {
		t.Fatalf("NormalizeImportPeer error: %v", err)
	}
	if peer.Endpoint != "" {
		t.Fatalf("expected empty endpoint, got %q", peer.Endpoint)
	}
}
