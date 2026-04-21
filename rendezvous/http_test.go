package rendezvous

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"wing/config"
)

func newRootIssuedConfig(t *testing.T) (*config.Config, string, string) {
	t.Helper()
	_, wgPub, err := config.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair error: %v", err)
	}
	controlPriv, controlPub, err := config.GenerateControlKeypair()
	if err != nil {
		t.Fatalf("GenerateControlKeypair error: %v", err)
	}
	rootPriv, rootPub, err := config.GenerateRootKeypair()
	if err != nil {
		t.Fatalf("GenerateRootKeypair error: %v", err)
	}
	identitySig, err := config.SignIdentityBinding(rootPriv, wgPub, controlPub)
	if err != nil {
		t.Fatalf("SignIdentityBinding error: %v", err)
	}
	cfg := &config.Config{
		Name:              "oak",
		PublicKey:         wgPub,
		ControlPrivateKey: controlPriv,
		ControlPublicKey:  controlPub,
		RootPublicKey:     rootPub,
		IdentitySignature: identitySig,
		MyEndpoint:        "198.51.100.10:51821",
		Address:           "10.7.0.1/32",
		ListenPort:        51821,
	}
	config.ApplyDefaults(cfg)
	return cfg, rootPriv, rootPub
}

func TestRecordRoundTripOverHTTP(t *testing.T) {
	cfg, _, _ := newRootIssuedConfig(t)
	wgPub := cfg.PublicKey

	record, err := NewRecord(cfg, []Candidate{{Type: "configured", Address: "1.2.3.4:51821"}}, time.Now().UTC())
	if err != nil {
		t.Fatalf("NewRecord error: %v", err)
	}

	srv := httptest.NewServer(NewHandler(nil))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := Publish(ctx, srv.URL, record); err != nil {
		t.Fatalf("Publish error: %v", err)
	}
	got, err := Fetch(ctx, srv.URL, wgPub)
	if err != nil {
		t.Fatalf("Fetch error: %v", err)
	}
	if got == nil {
		t.Fatalf("expected record")
	}
	if got.WGPublicKey != record.WGPublicKey {
		t.Fatalf("WGPublicKey = %q, want %q", got.WGPublicKey, record.WGPublicKey)
	}
	if got.Name != "oak" {
		t.Fatalf("Name = %q, want %q", got.Name, "oak")
	}
	if got.Endpoint != "198.51.100.10:51821" {
		t.Fatalf("Endpoint = %q, want %q", got.Endpoint, "198.51.100.10:51821")
	}
	if len(got.AllowedIPs) != 1 || got.AllowedIPs[0] != "10.7.0.1/32" {
		t.Fatalf("AllowedIPs = %v, want [10.7.0.1/32]", got.AllowedIPs)
	}
}

func TestFetchAllReturnsSortedRecords(t *testing.T) {
	cfgA, _, _ := newRootIssuedConfig(t)
	recordA, err := NewRecord(cfgA, []Candidate{{Type: "configured", Address: "1.2.3.4:51821"}}, time.Now().UTC())
	if err != nil {
		t.Fatalf("NewRecord A error: %v", err)
	}

	cfgB, _, _ := newRootIssuedConfig(t)
	recordB, err := NewRecord(cfgB, []Candidate{{Type: "configured", Address: "5.6.7.8:51821"}}, time.Now().UTC())
	if err != nil {
		t.Fatalf("NewRecord B error: %v", err)
	}
	if recordA.WGPublicKey > recordB.WGPublicKey {
		recordA, recordB = recordB, recordA
	}

	srv := httptest.NewServer(NewHandler(nil))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := Publish(ctx, srv.URL, recordB); err != nil {
		t.Fatalf("Publish B error: %v", err)
	}
	if err := Publish(ctx, srv.URL, recordA); err != nil {
		t.Fatalf("Publish A error: %v", err)
	}

	records, err := FetchAll(ctx, srv.URL)
	if err != nil {
		t.Fatalf("FetchAll error: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("expected 2 records, got %d", len(records))
	}
	if records[0].WGPublicKey != recordA.WGPublicKey || records[1].WGPublicKey != recordB.WGPublicKey {
		t.Fatalf("records not sorted by wg_public_key: %q, %q", records[0].WGPublicKey, records[1].WGPublicKey)
	}
}

func TestTrustedHandlerRejectsRecordWithoutRootIdentity(t *testing.T) {
	_, wgPub, err := config.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair error: %v", err)
	}
	controlPriv, controlPub, err := config.GenerateControlKeypair()
	if err != nil {
		t.Fatalf("GenerateControlKeypair error: %v", err)
	}
	_, trustedRootPub, err := config.GenerateRootKeypair()
	if err != nil {
		t.Fatalf("GenerateRootKeypair error: %v", err)
	}
	cfg := &config.Config{
		PublicKey:         wgPub,
		ControlPrivateKey: controlPriv,
		ControlPublicKey:  controlPub,
		Address:           "10.7.0.2/32",
		ListenPort:        51821,
	}
	config.ApplyDefaults(cfg)

	record, err := NewRecord(cfg, []Candidate{{Type: "configured", Address: "1.2.3.4:51821"}}, time.Now().UTC())
	if err != nil {
		t.Fatalf("NewRecord error: %v", err)
	}
	handler, err := NewHandlerWithOptions(nil, HandlerOptions{TrustedRootPublicKeys: []string{trustedRootPub}})
	if err != nil {
		t.Fatalf("NewHandlerWithOptions error: %v", err)
	}
	srv := httptest.NewServer(handler)
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := Publish(ctx, srv.URL, record); err == nil {
		t.Fatalf("expected Publish to fail for record without root identity")
	}
}

func TestTrustedHandlerRejectsRecordFromUntrustedRoot(t *testing.T) {
	cfg, _, _ := newRootIssuedConfig(t)
	record, err := NewRecord(cfg, []Candidate{{Type: "configured", Address: "1.2.3.4:51821"}}, time.Now().UTC())
	if err != nil {
		t.Fatalf("NewRecord error: %v", err)
	}
	_, otherRootPub, err := config.GenerateRootKeypair()
	if err != nil {
		t.Fatalf("GenerateRootKeypair error: %v", err)
	}
	handler, err := NewHandlerWithOptions(nil, HandlerOptions{TrustedRootPublicKeys: []string{otherRootPub}})
	if err != nil {
		t.Fatalf("NewHandlerWithOptions error: %v", err)
	}
	srv := httptest.NewServer(handler)
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := Publish(ctx, srv.URL, record); err == nil {
		t.Fatalf("expected Publish to fail for record from untrusted root")
	}
}

func TestTrustedHandlerRejectsIdentityBindingChanges(t *testing.T) {
	cfg, rootPriv, rootPub := newRootIssuedConfig(t)
	record, err := NewRecord(cfg, []Candidate{{Type: "configured", Address: "1.2.3.4:51821"}}, time.Now().UTC())
	if err != nil {
		t.Fatalf("NewRecord error: %v", err)
	}

	handler, err := NewHandlerWithOptions(nil, HandlerOptions{TrustedRootPublicKeys: []string{rootPub}})
	if err != nil {
		t.Fatalf("NewHandlerWithOptions error: %v", err)
	}
	srv := httptest.NewServer(handler)
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := Publish(ctx, srv.URL, record); err != nil {
		t.Fatalf("initial Publish error: %v", err)
	}

	replacementCfg, err := config.IssuePeerIdentity(rootPriv)
	if err != nil {
		t.Fatalf("IssuePeerIdentity error: %v", err)
	}
	replacement := &Record{
		Name:              "birch",
		WGPublicKey:       record.WGPublicKey,
		ControlPublicKey:  replacementCfg.ControlPublicKey,
		RootPublicKey:     replacementCfg.RootPublicKey,
		IdentitySignature: replacementCfg.IdentitySignature,
		Endpoint:          "5.6.7.8:51821",
		AllowedIPs:        []string{"10.7.0.3/32"},
		ListenPort:        51821,
		Sequence:          record.Sequence + 1,
		ObservedAt:        time.Now().UTC().Format(time.RFC3339),
		ExpiresAt:         time.Now().UTC().Add(2 * time.Minute).Format(time.RFC3339),
		Candidates:        []Candidate{{Type: "configured", Address: "5.6.7.8:51821"}},
	}
	if err := replacement.Sign(replacementCfg.ControlPrivateKey); err != nil {
		t.Fatalf("replacement Sign error: %v", err)
	}

	if err := Publish(ctx, srv.URL, replacement); err == nil {
		t.Fatalf("expected Publish to fail for identity-binding change")
	}
}

func TestDebugLoggingReportsRegistrationAndQueryEvents(t *testing.T) {
	cfg, _, rootPub := newRootIssuedConfig(t)
	record, err := NewRecord(cfg, []Candidate{{Type: "configured", Address: "1.2.3.4:51821"}}, time.Now().UTC())
	if err != nil {
		t.Fatalf("NewRecord error: %v", err)
	}

	var logs bytes.Buffer
	handler, err := NewHandlerWithOptions(nil, HandlerOptions{
		TrustedRootPublicKeys: []string{rootPub},
		Debug:                 true,
		Logf: func(format string, args ...any) {
			logs.WriteString(strings.TrimSpace(fmt.Sprintf(format, args...)))
			logs.WriteByte('\n')
		},
	})
	if err != nil {
		t.Fatalf("NewHandlerWithOptions error: %v", err)
	}
	srv := httptest.NewServer(handler)
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := Publish(ctx, srv.URL, record); err != nil {
		t.Fatalf("Publish error: %v", err)
	}
	if _, err := Fetch(ctx, srv.URL, record.WGPublicKey); err != nil {
		t.Fatalf("Fetch error: %v", err)
	}

	output := logs.String()
	if !strings.Contains(output, "rendezvous register accepted") {
		t.Fatalf("expected register acceptance log, got %q", output)
	}
	if !strings.Contains(output, "rendezvous query hit") {
		t.Fatalf("expected query hit log, got %q", output)
	}
	if !strings.Contains(output, "best=1.2.3.4:51821") {
		t.Fatalf("expected endpoint summary in log, got %q", output)
	}
}

func TestDebugLoggingReportsRejectedRegistration(t *testing.T) {
	cfg, _, _ := newRootIssuedConfig(t)
	record, err := NewRecord(cfg, []Candidate{{Type: "configured", Address: "1.2.3.4:51821"}}, time.Now().UTC())
	if err != nil {
		t.Fatalf("NewRecord error: %v", err)
	}

	var logs bytes.Buffer
	handler, err := NewHandlerWithOptions(nil, HandlerOptions{
		TrustedRootPublicKeys: []string{},
		Debug:                 true,
		Logf: func(format string, args ...any) {
			logs.WriteString(strings.TrimSpace(fmt.Sprintf(format, args...)))
			logs.WriteByte('\n')
		},
	})
	if err != nil {
		t.Fatalf("NewHandlerWithOptions error: %v", err)
	}
	srv := httptest.NewServer(handler)
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	badRecord := *record
	badRecord.WGPublicKey = "wrong-key"
	body, err := json.Marshal(&badRecord)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, recordURL(srv.URL, record.WGPublicKey), bytes.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest error: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do error: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for path mismatch, got %d", resp.StatusCode)
	}

	output := logs.String()
	if !strings.Contains(output, "rendezvous register rejected") {
		t.Fatalf("expected rejection log, got %q", output)
	}
	if !strings.Contains(output, "reason=path_mismatch") {
		t.Fatalf("expected path mismatch reason in log, got %q", output)
	}
}

func TestVerifyForPeerRejectsWrongControlKey(t *testing.T) {
	_, wgPub, err := config.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair error: %v", err)
	}
	controlPriv, controlPub, err := config.GenerateControlKeypair()
	if err != nil {
		t.Fatalf("GenerateControlKeypair error: %v", err)
	}
	_, wrongControlPub, err := config.GenerateControlKeypair()
	if err != nil {
		t.Fatalf("GenerateControlKeypair error: %v", err)
	}
	cfg := &config.Config{
		PublicKey:         wgPub,
		ControlPrivateKey: controlPriv,
		ControlPublicKey:  controlPub,
		Address:           "10.7.0.2/32",
		ListenPort:        51821,
	}
	config.ApplyDefaults(cfg)
	record, err := NewRecord(cfg, []Candidate{{Type: "configured", Address: "1.2.3.4:51821"}}, time.Now().UTC())
	if err != nil {
		t.Fatalf("NewRecord error: %v", err)
	}
	peer := config.Peer{PublicKey: wgPub, ControlPublicKey: wrongControlPub}
	if err := record.VerifyForPeer(peer); err == nil {
		t.Fatalf("expected VerifyForPeer to reject mismatched control key")
	}
}

func TestPublishAllSucceedsWhenOneServerFails(t *testing.T) {
	_, wgPub, err := config.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair error: %v", err)
	}
	controlPriv, controlPub, err := config.GenerateControlKeypair()
	if err != nil {
		t.Fatalf("GenerateControlKeypair error: %v", err)
	}
	cfg := &config.Config{
		PublicKey:         wgPub,
		ControlPrivateKey: controlPriv,
		ControlPublicKey:  controlPub,
		Address:           "10.7.0.2/32",
		ListenPort:        51821,
	}
	config.ApplyDefaults(cfg)
	record, err := NewRecord(cfg, []Candidate{{Type: "configured", Address: "1.2.3.4:51821"}}, time.Now().UTC())
	if err != nil {
		t.Fatalf("NewRecord error: %v", err)
	}

	good := httptest.NewServer(NewHandler(nil))
	defer good.Close()
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusBadGateway)
	}))
	defer bad.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := PublishAll(ctx, []string{bad.URL, good.URL}, record); err != nil {
		t.Fatalf("PublishAll error: %v", err)
	}
}

func TestFetchLatestReturnsNewestRecordAcrossServers(t *testing.T) {
	_, wgPub, err := config.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair error: %v", err)
	}
	controlPriv, controlPub, err := config.GenerateControlKeypair()
	if err != nil {
		t.Fatalf("GenerateControlKeypair error: %v", err)
	}
	cfg := &config.Config{
		PublicKey:         wgPub,
		ControlPrivateKey: controlPriv,
		ControlPublicKey:  controlPub,
		Address:           "10.7.0.2/32",
		ListenPort:        51821,
	}
	config.ApplyDefaults(cfg)

	base := time.Now().UTC().Add(30 * time.Second)
	older, err := NewRecord(cfg, []Candidate{{Type: "configured", Address: "1.2.3.4:51821"}}, base)
	if err != nil {
		t.Fatalf("NewRecord older error: %v", err)
	}
	newer, err := NewRecord(cfg, []Candidate{{Type: "configured", Address: "5.6.7.8:51821"}}, base.Add(10*time.Second))
	if err != nil {
		t.Fatalf("NewRecord newer error: %v", err)
	}

	srvA := httptest.NewServer(NewHandler(nil))
	defer srvA.Close()
	srvB := httptest.NewServer(NewHandler(nil))
	defer srvB.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := Publish(ctx, srvA.URL, older); err != nil {
		t.Fatalf("Publish older error: %v", err)
	}
	if err := Publish(ctx, srvB.URL, newer); err != nil {
		t.Fatalf("Publish newer error: %v", err)
	}

	got, err := FetchLatest(ctx, []string{srvA.URL, srvB.URL}, wgPub)
	if err != nil {
		t.Fatalf("FetchLatest error: %v", err)
	}
	if got == nil {
		t.Fatalf("expected record")
	}
	if got.Sequence != newer.Sequence {
		t.Fatalf("expected newest sequence %d, got %d", newer.Sequence, got.Sequence)
	}
	if BestEndpoint(got) != "5.6.7.8:51821" {
		t.Fatalf("expected newest endpoint, got %q", BestEndpoint(got))
	}
}

func TestFetchLatestReturnsWithinWindowUsingFastResponses(t *testing.T) {
	_, wgPub, err := config.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair error: %v", err)
	}
	controlPriv, controlPub, err := config.GenerateControlKeypair()
	if err != nil {
		t.Fatalf("GenerateControlKeypair error: %v", err)
	}
	cfg := &config.Config{
		PublicKey:         wgPub,
		ControlPrivateKey: controlPriv,
		ControlPublicKey:  controlPub,
		Address:           "10.7.0.2/32",
		ListenPort:        51821,
	}
	config.ApplyDefaults(cfg)

	base := time.Now().UTC().Add(30 * time.Second)
	record, err := NewRecord(cfg, []Candidate{{Type: "configured", Address: "9.9.9.9:51821"}}, base)
	if err != nil {
		t.Fatalf("NewRecord error: %v", err)
	}

	fast := httptest.NewServer(NewHandler(nil))
	defer fast.Close()
	if err := Publish(context.Background(), fast.URL, record); err != nil {
		t.Fatalf("Publish error: %v", err)
	}

	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(fetchLatestWindow + 500*time.Millisecond)
		http.NotFound(w, r)
	}))
	defer slow.Close()

	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	got, err := FetchLatest(ctx, []string{slow.URL, fast.URL}, wgPub)
	if err != nil {
		t.Fatalf("FetchLatest error: %v", err)
	}
	if got == nil {
		t.Fatalf("expected record")
	}
	if elapsed := time.Since(start); elapsed >= fetchLatestWindow+400*time.Millisecond {
		t.Fatalf("FetchLatest waited too long: %v", elapsed)
	}
	if BestEndpoint(got) != "9.9.9.9:51821" {
		t.Fatalf("expected fast endpoint, got %q", BestEndpoint(got))
	}
}
