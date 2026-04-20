package config

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func NormalizeAddress(addr string) (string, error) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return "", errors.New("address is empty")
	}
	if strings.Contains(addr, "/") {
		if _, _, err := net.ParseCIDR(addr); err != nil {
			return "", fmt.Errorf("invalid address %q", addr)
		}
		return addr, nil
	}
	ip := net.ParseIP(addr)
	if ip == nil {
		return "", fmt.Errorf("invalid address %q", addr)
	}
	return ip.String() + "/32", nil
}

func NormalizeEndpointHostPort(input string) (string, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return "", nil
	}
	if strings.Contains(input, "/") {
		return "", fmt.Errorf("invalid endpoint %q (use host:port)", input)
	}

	// Keep this strict to avoid ambiguous multi-colon parsing (no IPv6 here).
	if host, portStr, err := net.SplitHostPort(input); err == nil {
		port, err := strconv.Atoi(portStr)
		if err != nil || port <= 0 || port > 65535 {
			return "", fmt.Errorf("invalid endpoint port %q", portStr)
		}
		if host == "" {
			return "", fmt.Errorf("invalid endpoint host in %q", input)
		}
		return host + ":" + strconv.Itoa(port), nil
	}

	if strings.Count(input, ":") == 1 {
		parts := strings.SplitN(input, ":", 2)
		host := strings.TrimSpace(parts[0])
		portStr := strings.TrimSpace(parts[1])
		port, err := strconv.Atoi(portStr)
		if err != nil || port <= 0 || port > 65535 {
			return "", fmt.Errorf("invalid endpoint port %q", portStr)
		}
		if host == "" {
			return "", fmt.Errorf("invalid endpoint host in %q", input)
		}
		return host + ":" + strconv.Itoa(port), nil
	}

	return "", fmt.Errorf("invalid endpoint %q (use host:port)", input)
}

func PublicKeyFromPrivate(priv string) (string, error) {
	key, err := wgtypes.ParseKey(strings.TrimSpace(priv))
	if err != nil {
		return "", err
	}
	return key.PublicKey().String(), nil
}

func ValidatePublicKey(pub string) error {
	_, err := wgtypes.ParseKey(strings.TrimSpace(pub))
	return err
}

func PeerExists(cfg *Config, name, pubKey string) bool {
	name = strings.TrimSpace(name)
	pubKey = strings.TrimSpace(pubKey)
	for _, p := range cfg.Peers {
		if name != "" && p.Name == name {
			return true
		}
		if pubKey != "" && p.PublicKey == pubKey {
			return true
		}
	}
	return false
}

func BuildExportPeer(cfg *Config, name string) (Peer, error) {
	pub := strings.TrimSpace(cfg.MyPublicKey)
	if pub == "" && cfg.PrivateKey != "" {
		if p, err := PublicKeyFromPrivate(cfg.PrivateKey); err == nil {
			pub = p
		}
	}
	if pub == "" {
		return Peer{}, errors.New("my_public_key is empty")
	}
	if cfg.Address == "" {
		return Peer{}, errors.New("address is empty")
	}
	addr, err := NormalizeAddress(cfg.Address)
	if err != nil {
		return Peer{}, err
	}
	endpoint := ""
	if cfg.MyEndpoint != "" {
		endpoint, err = NormalizeEndpointHostPort(cfg.MyEndpoint)
		if err != nil {
			return Peer{}, err
		}
	}
	peer := Peer{
		Name:             name,
		PublicKey:        pub,
		ControlPublicKey: strings.TrimSpace(cfg.ControlPublicKey),
		Endpoint:         endpoint,
		DynamicEndpoint:  true,
		AllowedIPs:       []string{addr},
		Keepalive:        25,
	}
	return peer, nil
}

func NormalizeImportPeer(peer Peer) (Peer, error) {
	peer.Name = strings.TrimSpace(peer.Name)
	peer.PublicKey = strings.TrimSpace(peer.PublicKey)
	peer.Endpoint = strings.TrimSpace(peer.Endpoint)

	if peer.Name == "" {
		return Peer{}, errors.New("peer name is required")
	}
	if peer.PublicKey == "" {
		return Peer{}, errors.New("public_key is required")
	}
	if err := ValidatePublicKey(peer.PublicKey); err != nil {
		return Peer{}, fmt.Errorf("invalid public_key: %v", err)
	}
	if peer.ControlPublicKey != "" {
		if err := ValidateControlPublicKey(peer.ControlPublicKey); err != nil {
			return Peer{}, fmt.Errorf("invalid control_public_key: %v", err)
		}
	}
	if peer.Endpoint != "" {
		endpoint, err := NormalizeEndpointHostPort(peer.Endpoint)
		if err != nil {
			return Peer{}, err
		}
		peer.Endpoint = endpoint
	}
	if len(peer.AllowedIPs) == 0 {
		return Peer{}, errors.New("allowed_ips is required")
	}
	var allowed []string
	for _, a := range peer.AllowedIPs {
		norm, err := NormalizeAddress(a)
		if err != nil {
			return Peer{}, fmt.Errorf("invalid allowed_ip %q: %v", a, err)
		}
		allowed = append(allowed, norm)
	}
	peer.AllowedIPs = allowed
	if peer.Keepalive <= 0 {
		peer.Keepalive = 25
	}
	return peer, nil
}
