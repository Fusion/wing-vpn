package rendezvous

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"wing/config"
)

type Candidate struct {
	Type    string `json:"type"`
	Address string `json:"address"`
	Source  string `json:"source,omitempty"`
}

type Record struct {
	Name              string      `json:"name,omitempty"`
	WGPublicKey       string      `json:"wg_public_key"`
	ControlPublicKey  string      `json:"control_public_key"`
	RootPublicKey     string      `json:"root_public_key,omitempty"`
	IdentitySignature string      `json:"identity_signature,omitempty"`
	Endpoint          string      `json:"endpoint,omitempty"`
	AllowedIPs        []string    `json:"allowed_ips,omitempty"`
	ListenPort        int         `json:"listen_port"`
	Sequence          uint64      `json:"sequence"`
	ObservedAt        string      `json:"observed_at"`
	ExpiresAt         string      `json:"expires_at"`
	Candidates        []Candidate `json:"candidates"`
	Signature         string      `json:"signature"`
}

func NewRecord(cfg *config.Config, candidates []Candidate, now time.Time) (*Record, error) {
	if cfg == nil {
		return nil, errors.New("config is nil")
	}
	if err := config.EnsureRuntimeIdentity(cfg); err != nil {
		return nil, err
	}
	record := &Record{
		Name:             strings.TrimSpace(cfg.Name),
		WGPublicKey:      strings.TrimSpace(cfg.PublicKey),
		ControlPublicKey: strings.TrimSpace(cfg.ControlPublicKey),
		RootPublicKey:    strings.TrimSpace(cfg.RootPublicKey),
		IdentitySignature: strings.TrimSpace(cfg.IdentitySignature),
		Endpoint:         strings.TrimSpace(cfg.MyEndpoint),
		AllowedIPs:       recordAllowedIPs(cfg.Address),
		ListenPort:       cfg.ListenPort,
		Sequence:         uint64(now.UTC().UnixNano()),
		ObservedAt:       now.UTC().Format(time.RFC3339),
		ExpiresAt:        now.UTC().Add(time.Duration(cfg.Daemon.RecordTTL) * time.Second).Format(time.RFC3339),
		Candidates:       dedupeCandidates(candidates),
	}
	if err := record.Sign(cfg.ControlPrivateKey); err != nil {
		return nil, err
	}
	return record, nil
}

func (r *Record) canonicalJSON() ([]byte, error) {
	if r == nil {
		return nil, errors.New("record is nil")
	}
	// This is the exact payload authenticated by the control key. Signature is
	// intentionally excluded so the signed body is stable.
	payload := struct {
		Name             string      `json:"name,omitempty"`
		WGPublicKey      string      `json:"wg_public_key"`
		ControlPublicKey string      `json:"control_public_key"`
		RootPublicKey    string      `json:"root_public_key,omitempty"`
		IdentitySignature string     `json:"identity_signature,omitempty"`
		Endpoint         string      `json:"endpoint,omitempty"`
		AllowedIPs       []string    `json:"allowed_ips,omitempty"`
		ListenPort       int         `json:"listen_port"`
		Sequence         uint64      `json:"sequence"`
		ObservedAt       string      `json:"observed_at"`
		ExpiresAt        string      `json:"expires_at"`
		Candidates       []Candidate `json:"candidates"`
	}{
		Name:             strings.TrimSpace(r.Name),
		WGPublicKey:      strings.TrimSpace(r.WGPublicKey),
		ControlPublicKey: strings.TrimSpace(r.ControlPublicKey),
		RootPublicKey:    strings.TrimSpace(r.RootPublicKey),
		IdentitySignature: strings.TrimSpace(r.IdentitySignature),
		Endpoint:         strings.TrimSpace(r.Endpoint),
		AllowedIPs:       dedupeAllowedIPs(r.AllowedIPs),
		ListenPort:       r.ListenPort,
		Sequence:         r.Sequence,
		ObservedAt:       r.ObservedAt,
		ExpiresAt:        r.ExpiresAt,
		Candidates:       dedupeCandidates(r.Candidates),
	}
	return json.Marshal(payload)
}

func (r *Record) Sign(priv string) error {
	msg, err := r.canonicalJSON()
	if err != nil {
		return err
	}
	sig, err := config.SignControlMessage(priv, msg)
	if err != nil {
		return err
	}
	r.Signature = sig
	return nil
}

func (r *Record) Verify() error {
	if r == nil {
		return errors.New("record is nil")
	}
	if strings.TrimSpace(r.WGPublicKey) == "" {
		return errors.New("wg_public_key is required")
	}
	if err := config.ValidatePublicKey(r.WGPublicKey); err != nil {
		return fmt.Errorf("invalid wg_public_key: %v", err)
	}
	if err := config.ValidateControlPublicKey(r.ControlPublicKey); err != nil {
		return fmt.Errorf("invalid control_public_key: %v", err)
	}
	// The root signature binds the WireGuard and control identities together,
	// while the control signature below authenticates this live record body.
	if strings.TrimSpace(r.RootPublicKey) != "" || strings.TrimSpace(r.IdentitySignature) != "" {
		if err := config.ValidateControlPublicKey(r.RootPublicKey); err != nil {
			return fmt.Errorf("invalid root_public_key: %v", err)
		}
		if err := config.VerifyIdentityBinding(r.RootPublicKey, r.WGPublicKey, r.ControlPublicKey, r.IdentitySignature); err != nil {
			return fmt.Errorf("invalid identity signature: %v", err)
		}
	}
	if strings.TrimSpace(r.Endpoint) != "" {
		if _, err := config.NormalizeEndpointHostPort(r.Endpoint); err != nil {
			return fmt.Errorf("invalid endpoint: %v", err)
		}
	}
	if len(r.AllowedIPs) == 0 {
		return errors.New("allowed_ips are required")
	}
	for _, allowed := range r.AllowedIPs {
		if _, err := config.NormalizeAddress(allowed); err != nil {
			return fmt.Errorf("invalid allowed_ip %q: %v", allowed, err)
		}
	}
	if r.ListenPort <= 0 || r.ListenPort > 65535 {
		return errors.New("listen_port must be between 1 and 65535")
	}
	if _, err := time.Parse(time.RFC3339, r.ObservedAt); err != nil {
		return fmt.Errorf("invalid observed_at: %v", err)
	}
	expiresAt, err := time.Parse(time.RFC3339, r.ExpiresAt)
	if err != nil {
		return fmt.Errorf("invalid expires_at: %v", err)
	}
	if !expiresAt.After(time.Now().UTC()) {
		return errors.New("record expired")
	}
	if len(r.Candidates) == 0 {
		return errors.New("candidates are required")
	}
	for _, candidate := range r.Candidates {
		if err := validateCandidate(candidate); err != nil {
			return err
		}
	}
	msg, err := r.canonicalJSON()
	if err != nil {
		return err
	}
	return config.VerifyControlMessage(r.ControlPublicKey, msg, r.Signature)
}

func (r *Record) VerifyForPeer(peer config.Peer) error {
	if err := r.Verify(); err != nil {
		return err
	}
	if strings.TrimSpace(peer.PublicKey) != "" && peer.PublicKey != r.WGPublicKey {
		return fmt.Errorf("record wg_public_key mismatch: %s", r.WGPublicKey)
	}
	if strings.TrimSpace(peer.ControlPublicKey) == "" {
		return errors.New("peer control_public_key is required for dynamic endpoint verification")
	}
	if peer.ControlPublicKey != r.ControlPublicKey {
		return errors.New("record control_public_key mismatch")
	}
	if strings.TrimSpace(peer.RootPublicKey) != "" && peer.RootPublicKey != r.RootPublicKey {
		return errors.New("record root_public_key mismatch")
	}
	if strings.TrimSpace(peer.IdentitySignature) != "" && peer.IdentitySignature != r.IdentitySignature {
		return errors.New("record identity_signature mismatch")
	}
	return nil
}

func BestEndpoint(record *Record) string {
	if record == nil {
		return ""
	}
	// Prefer globally reachable candidates first, then static hints, then best
	// effort guesses, and only fall back to raw host addresses last.
	for _, candidate := range record.Candidates {
		if candidate.Type == "srflx" {
			return candidate.Address
		}
	}
	for _, candidate := range record.Candidates {
		if candidate.Type == "configured" {
			return candidate.Address
		}
	}
	for _, candidate := range record.Candidates {
		if candidate.Type == "srflx-guess" {
			return candidate.Address
		}
	}
	for _, candidate := range record.Candidates {
		if candidate.Type == "host" {
			return candidate.Address
		}
	}
	return ""
}

func validateCandidate(candidate Candidate) error {
	if strings.TrimSpace(candidate.Type) == "" {
		return errors.New("candidate type is required")
	}
	if _, err := config.NormalizeEndpointHostPort(candidate.Address); err != nil {
		return fmt.Errorf("invalid candidate address %q: %v", candidate.Address, err)
	}
	return nil
}

func recordAllowedIPs(addr string) []string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return nil
	}
	// Rendezvous currently publishes only the node's own tunnel address, not a
	// broader route set.
	norm, err := config.NormalizeAddress(addr)
	if err != nil {
		return nil
	}
	return []string{norm}
}

func dedupeAllowedIPs(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	var out []string
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		norm, err := config.NormalizeAddress(value)
		if err != nil {
			continue
		}
		if _, ok := seen[norm]; ok {
			continue
		}
		seen[norm] = struct{}{}
		out = append(out, norm)
	}
	return out
}

func dedupeCandidates(candidates []Candidate) []Candidate {
	seen := make(map[string]struct{}, len(candidates))
	var out []Candidate
	for _, candidate := range candidates {
		address, err := config.NormalizeEndpointHostPort(candidate.Address)
		if err != nil {
			continue
		}
		candidate.Address = address
		key := candidate.Type + "|" + candidate.Address
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, candidate)
	}
	return out
}
