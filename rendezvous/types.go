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
	WGPublicKey       string      `json:"wg_public_key"`
	ControlPublicKey  string      `json:"control_public_key"`
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
		WGPublicKey:      strings.TrimSpace(cfg.MyPublicKey),
		ControlPublicKey: strings.TrimSpace(cfg.ControlPublicKey),
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
	payload := struct {
		WGPublicKey      string      `json:"wg_public_key"`
		ControlPublicKey string      `json:"control_public_key"`
		ListenPort       int         `json:"listen_port"`
		Sequence         uint64      `json:"sequence"`
		ObservedAt       string      `json:"observed_at"`
		ExpiresAt        string      `json:"expires_at"`
		Candidates       []Candidate `json:"candidates"`
	}{
		WGPublicKey:      strings.TrimSpace(r.WGPublicKey),
		ControlPublicKey: strings.TrimSpace(r.ControlPublicKey),
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
	return nil
}

func BestEndpoint(record *Record) string {
	if record == nil {
		return ""
	}
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
