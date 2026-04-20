package config

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

const (
	DefaultSTUNServer       = "stun.l.google.com:19302"
	DefaultPublishInterval  = 30
	DefaultFetchInterval    = 15
	DefaultRetryInitial     = 1
	DefaultRetryMax         = 30
	DefaultRecordTTL        = 90
	DefaultProbePort        = 9
	DefaultRendezvousListen = ":8787"
)

func GenerateControlKeypair() (string, string, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(priv), base64.StdEncoding.EncodeToString(pub), nil
}

func ParseControlPrivateKey(priv string) (ed25519.PrivateKey, error) {
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(priv))
	if err != nil {
		return nil, err
	}
	if len(decoded) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid control private key length %d", len(decoded))
	}
	return ed25519.PrivateKey(decoded), nil
}

func ParseControlPublicKey(pub string) (ed25519.PublicKey, error) {
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(pub))
	if err != nil {
		return nil, err
	}
	if len(decoded) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid control public key length %d", len(decoded))
	}
	return ed25519.PublicKey(decoded), nil
}

func ValidateControlPublicKey(pub string) error {
	_, err := ParseControlPublicKey(pub)
	return err
}

func SignControlMessage(priv string, msg []byte) (string, error) {
	key, err := ParseControlPrivateKey(priv)
	if err != nil {
		return "", err
	}
	sig := ed25519.Sign(key, msg)
	return base64.StdEncoding.EncodeToString(sig), nil
}

func VerifyControlMessage(pub string, msg []byte, sig string) error {
	key, err := ParseControlPublicKey(pub)
	if err != nil {
		return err
	}
	decodedSig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(sig))
	if err != nil {
		return err
	}
	if len(decodedSig) != ed25519.SignatureSize {
		return fmt.Errorf("invalid signature length %d", len(decodedSig))
	}
	if !ed25519.Verify(key, msg, decodedSig) {
		return errors.New("invalid signature")
	}
	return nil
}

func ApplyDefaults(cfg *Config) {
	if cfg == nil {
		return
	}
	if cfg.Peers == nil {
		cfg.Peers = []Peer{}
	}
	if cfg.ListenPort == 0 {
		cfg.ListenPort = 51821
	}
	if cfg.MTU == 0 {
		cfg.MTU = 1420
	}
	if len(cfg.Daemon.STUNServers) == 0 {
		cfg.Daemon.STUNServers = []string{DefaultSTUNServer}
	}
	if cfg.Daemon.PublishInterval <= 0 {
		cfg.Daemon.PublishInterval = DefaultPublishInterval
	}
	if cfg.Daemon.FetchInterval <= 0 {
		cfg.Daemon.FetchInterval = DefaultFetchInterval
	}
	if cfg.Daemon.RetryInitial <= 0 {
		cfg.Daemon.RetryInitial = DefaultRetryInitial
	}
	if cfg.Daemon.RetryMax <= 0 {
		cfg.Daemon.RetryMax = DefaultRetryMax
	}
	if cfg.Daemon.RecordTTL <= 0 {
		cfg.Daemon.RecordTTL = DefaultRecordTTL
	}
	if cfg.Daemon.ProbePort <= 0 {
		cfg.Daemon.ProbePort = DefaultProbePort
	}
	cfg.Rendezvous.URLs = dedupeStrings(cfg.Rendezvous.URLs)
	if len(cfg.Rendezvous.URLs) == 0 && strings.TrimSpace(cfg.Rendezvous.URL) != "" {
		cfg.Rendezvous.URLs = []string{strings.TrimSpace(cfg.Rendezvous.URL)}
	}
	if strings.TrimSpace(cfg.Rendezvous.URL) == "" && len(cfg.Rendezvous.URLs) > 0 {
		cfg.Rendezvous.URL = cfg.Rendezvous.URLs[0]
	}
	if strings.TrimSpace(cfg.Rendezvous.Listen) == "" {
		cfg.Rendezvous.Listen = DefaultRendezvousListen
	}
}

func EnsureControlKeys(cfg *Config) error {
	if cfg == nil {
		return errors.New("config is nil")
	}
	if strings.TrimSpace(cfg.ControlPrivateKey) == "" {
		priv, pub, err := GenerateControlKeypair()
		if err != nil {
			return err
		}
		cfg.ControlPrivateKey = priv
		cfg.ControlPublicKey = pub
	}
	if strings.TrimSpace(cfg.ControlPublicKey) == "" && strings.TrimSpace(cfg.ControlPrivateKey) != "" {
		priv, err := ParseControlPrivateKey(cfg.ControlPrivateKey)
		if err != nil {
			return err
		}
		cfg.ControlPublicKey = base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))
	}
	return nil
}

func EnsureRuntimeIdentity(cfg *Config) error {
	if cfg == nil {
		return errors.New("config is nil")
	}
	ApplyDefaults(cfg)
	if strings.TrimSpace(cfg.MyPublicKey) == "" && strings.TrimSpace(cfg.PrivateKey) != "" {
		pub, err := PublicKeyFromPrivate(cfg.PrivateKey)
		if err != nil {
			return err
		}
		cfg.MyPublicKey = pub
	}
	return EnsureControlKeys(cfg)
}

func EffectiveKeepalive(peer Peer, auto bool) int {
	if peer.Keepalive > 0 {
		return peer.Keepalive
	}
	if auto && (peer.DynamicEndpoint || peer.Endpoint != "") {
		return 25
	}
	return 0
}

func EffectiveRendezvousURLs(cfg *Config) []string {
	if cfg == nil {
		return nil
	}
	var urls []string
	if strings.TrimSpace(cfg.Rendezvous.URL) != "" {
		urls = append(urls, strings.TrimSpace(cfg.Rendezvous.URL))
	}
	urls = append(urls, cfg.Rendezvous.URLs...)
	return dedupeStrings(urls)
}

func dedupeStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	var out []string
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}
