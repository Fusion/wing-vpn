package rendezvous

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"wing/config"
)

func TestRecordRoundTripOverHTTP(t *testing.T) {
	_, wgPub, err := config.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair error: %v", err)
	}
	controlPriv, controlPub, err := config.GenerateControlKeypair()
	if err != nil {
		t.Fatalf("GenerateControlKeypair error: %v", err)
	}
	cfg := &config.Config{
		MyPublicKey:       wgPub,
		ControlPrivateKey: controlPriv,
		ControlPublicKey:  controlPub,
		ListenPort:        51821,
	}
	config.ApplyDefaults(cfg)

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
		MyPublicKey:       wgPub,
		ControlPrivateKey: controlPriv,
		ControlPublicKey:  controlPub,
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
		MyPublicKey:       wgPub,
		ControlPrivateKey: controlPriv,
		ControlPublicKey:  controlPub,
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
		MyPublicKey:       wgPub,
		ControlPrivateKey: controlPriv,
		ControlPublicKey:  controlPub,
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
		MyPublicKey:       wgPub,
		ControlPrivateKey: controlPriv,
		ControlPublicKey:  controlPub,
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
