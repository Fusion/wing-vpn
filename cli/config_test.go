package cli

import (
	"bufio"
	"path/filepath"
	"strings"
	"testing"

	"wing/config"
)

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

func TestParseIssuedIdentityBlockParsesBareOutput(t *testing.T) {
	rootPriv, _, err := config.GenerateRootKeypair()
	if err != nil {
		t.Fatalf("GenerateRootKeypair error: %v", err)
	}
	issued, err := config.IssuePeerIdentity(rootPriv)
	if err != nil {
		t.Fatalf("IssuePeerIdentity error: %v", err)
	}
	block := "" +
		"\"private_key\": \"" + issued.PrivateKey + "\",\n" +
		"\"public_key\": \"" + issued.PublicKey + "\",\n" +
		"\"control_private_key\": \"" + issued.ControlPrivateKey + "\",\n" +
		"\"control_public_key\": \"" + issued.ControlPublicKey + "\",\n" +
		"\"root_public_key\": \"" + issued.RootPublicKey + "\",\n" +
		"\"identity_signature\": \"" + issued.IdentitySignature + "\",\n"
	got, err := parseIssuedIdentityBlock(block)
	if err != nil {
		t.Fatalf("parseIssuedIdentityBlock error: %v", err)
	}
	if got.PublicKey != issued.PublicKey {
		t.Fatalf("public_key = %q, want %q", got.PublicKey, issued.PublicKey)
	}
	if got.IdentitySignature != issued.IdentitySignature {
		t.Fatalf("identity_signature mismatch")
	}
}

func TestHandleSetupReplacesIdentityWhenPasted(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "self.json")
	created, err := config.InitAt(path)
	if err != nil {
		t.Fatalf("InitAt error: %v", err)
	}
	if !created {
		t.Fatalf("expected InitAt to create config")
	}
	before, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load before error: %v", err)
	}

	rootPriv, _, err := config.GenerateRootKeypair()
	if err != nil {
		t.Fatalf("GenerateRootKeypair error: %v", err)
	}
	issued, err := config.IssuePeerIdentity(rootPriv)
	if err != nil {
		t.Fatalf("IssuePeerIdentity error: %v", err)
	}
	input := "\n" +
		"\n" +
		"http://rv1.example.com:8787, http://rv2.example.com:8787\n" +
		"y\n" +
		"\"private_key\": \"" + issued.PrivateKey + "\",\n" +
		"\"public_key\": \"" + issued.PublicKey + "\",\n" +
		"\"control_private_key\": \"" + issued.ControlPrivateKey + "\",\n" +
		"\"control_public_key\": \"" + issued.ControlPublicKey + "\",\n" +
		"\"root_public_key\": \"" + issued.RootPublicKey + "\",\n" +
		"\"identity_signature\": \"" + issued.IdentitySignature + "\",\n" +
		"\n"

	withStdin(t, input, func() {
		if err := HandleSetup(path, "10.7.0.9", 51830, 1500); err != nil {
			t.Fatalf("HandleSetup error: %v", err)
		}
	})

	after, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load after error: %v", err)
	}
	if after.PrivateKey != issued.PrivateKey || after.PublicKey != issued.PublicKey {
		t.Fatalf("wireguard identity not replaced")
	}
	if after.ControlPrivateKey != issued.ControlPrivateKey || after.ControlPublicKey != issued.ControlPublicKey {
		t.Fatalf("control identity not replaced")
	}
	if after.RootPublicKey != issued.RootPublicKey || after.IdentitySignature != issued.IdentitySignature {
		t.Fatalf("root-issued identity not replaced")
	}
	if len(after.Rendezvous.URLs) != 2 ||
		after.Rendezvous.URLs[0] != "http://rv1.example.com:8787" ||
		after.Rendezvous.URLs[1] != "http://rv2.example.com:8787" {
		t.Fatalf("rendezvous urls not updated: %v", after.Rendezvous.URLs)
	}
	if after.Address != "10.7.0.9/32" || after.ListenPort != 51830 || after.MTU != 1500 {
		t.Fatalf("setup values not applied: %+v", after)
	}
	if before.PrivateKey == after.PrivateKey {
		t.Fatalf("expected private_key to change")
	}
}

func TestHandleSetupKeepsIdentityWhenNothingPasted(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "self.json")
	created, err := config.InitAt(path)
	if err != nil {
		t.Fatalf("InitAt error: %v", err)
	}
	if !created {
		t.Fatalf("expected InitAt to create config")
	}
	before, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load before error: %v", err)
	}
	before.Rendezvous.URLs = []string{"http://existing.example.com:8787"}
	if err := config.Write(path, before); err != nil {
		t.Fatalf("Write before error: %v", err)
	}
	before, err = config.Load(path)
	if err != nil {
		t.Fatalf("Reload before error: %v", err)
	}

	withStdin(t, "\n\n\nn\n", func() {
		if err := HandleSetup(path, "10.7.0.10", 51831, 1501); err != nil {
			t.Fatalf("HandleSetup error: %v", err)
		}
	})

	after, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load after error: %v", err)
	}
	if after.Address != "10.7.0.10/32" || after.ListenPort != 51831 || after.MTU != 1501 {
		t.Fatalf("setup values not applied: %+v", after)
	}
	if before.PrivateKey != after.PrivateKey || before.PublicKey != after.PublicKey {
		t.Fatalf("expected wireguard identity to stay unchanged")
	}
	if before.ControlPrivateKey != after.ControlPrivateKey || before.ControlPublicKey != after.ControlPublicKey {
		t.Fatalf("expected control identity to stay unchanged")
	}
	if before.RootPublicKey != after.RootPublicKey || before.IdentitySignature != after.IdentitySignature {
		t.Fatalf("expected root-issued identity to stay unchanged")
	}
	if len(after.Rendezvous.URLs) != 1 || after.Rendezvous.URLs[0] != "http://existing.example.com:8787" {
		t.Fatalf("expected rendezvous urls to stay unchanged, got %v", after.Rendezvous.URLs)
	}
}

func TestHandleSetupAddsRendezvousURLsWithoutIdentityPaste(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "self.json")
	created, err := config.InitAt(path)
	if err != nil {
		t.Fatalf("InitAt error: %v", err)
	}
	if !created {
		t.Fatalf("expected InitAt to create config")
	}

	withStdin(t, "\n\nhttp://rv1.example.com:8787, http://rv2.example.com:8787\nn\n", func() {
		if err := HandleSetup(path, "10.7.0.11", 51832, 1502); err != nil {
			t.Fatalf("HandleSetup error: %v", err)
		}
	})

	after, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load after error: %v", err)
	}
	if len(after.Rendezvous.URLs) != 2 ||
		after.Rendezvous.URLs[0] != "http://rv1.example.com:8787" ||
		after.Rendezvous.URLs[1] != "http://rv2.example.com:8787" {
		t.Fatalf("unexpected rendezvous urls: %v", after.Rendezvous.URLs)
	}
}

func TestPromptYesNoUsesDefaultNo(t *testing.T) {
	reader := bufio.NewReader(strings.NewReader("\n"))
	got, err := promptYesNo(reader, "edit issued rendezvous identity", false)
	if err != nil {
		t.Fatalf("promptYesNo error: %v", err)
	}
	if got {
		t.Fatalf("expected default no")
	}
}
