package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	"wing/config"
)

func handleInit() error {
	path, err := config.SelfPath()
	if err != nil {
		return err
	}
	created, err := config.InitAt(path)
	if err != nil {
		return err
	}
	if !created {
		return fmt.Errorf("%s already exists", path)
	}
	fmt.Printf("created %s\n", path)
	fmt.Printf("edit address + peers, then rerun wing\n")
	return nil
}

func handleSetup(cfgPath, addr string, port int, mtu int) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	if cfg.Peers == nil {
		cfg.Peers = []config.Peer{}
	}

	if cfg.PrivateKey != "" && cfg.MyPublicKey == "" {
		// Backfill my_public_key when only private_key is set, so exports work.
		if pub, err := config.PublicKeyFromPrivate(cfg.PrivateKey); err == nil {
			cfg.MyPublicKey = pub
		}
	}

	defAddr := cfg.Address
	if defAddr == "" {
		defAddr = "10.7.0.1"
	}
	defPort := cfg.ListenPort
	if defPort == 0 {
		defPort = 51821
	}
	defMTU := cfg.MTU
	if defMTU == 0 {
		defMTU = 1420
	}
	defEndpoint := strings.TrimSpace(cfg.MyEndpoint)

	reader := bufio.NewReader(os.Stdin)
	if addr == "" {
		var err error
		addr, err = promptString(reader, "address", defAddr)
		if err != nil {
			return err
		}
	}
	if port <= 0 {
		var err error
		port, err = promptInt(reader, "listen port", defPort)
		if err != nil {
			return err
		}
	}
	if mtu <= 0 {
		var err error
		mtu, err = promptInt(reader, "mtu", defMTU)
		if err != nil {
			return err
		}
	}
	endpoint, err := promptString(reader, "my endpoint (host:port)", defEndpoint)
	if err != nil {
		return err
	}
	endpoint, err = config.NormalizeEndpointHostPort(endpoint)
	if err != nil {
		return err
	}

	normAddr, err := config.NormalizeAddress(addr)
	if err != nil {
		return err
	}
	cfg.Address = normAddr
	cfg.ListenPort = port
	cfg.MTU = mtu
	if endpoint != "" {
		cfg.MyEndpoint = endpoint
	}

	if err := config.Write(cfgPath, cfg); err != nil {
		return err
	}
	fmt.Printf("updated %s\n", cfgPath)
	return nil
}

func handleListPeers(cfg *config.Config) error {
	if len(cfg.Peers) == 0 {
		fmt.Printf("peers: (none)\n")
		return nil
	}
	fmt.Printf("peers:\n")
	for _, p := range cfg.Peers {
		name := p.Name
		if name == "" {
			name = "(unnamed)"
		}
		fmt.Printf("- name: %s\n", name)
		fmt.Printf("  public_key: %s\n", p.PublicKey)
		if p.Endpoint != "" {
			fmt.Printf("  endpoint: %s\n", p.Endpoint)
		} else {
			fmt.Printf("  endpoint: (none)\n")
		}
		if len(p.AllowedIPs) > 0 {
			fmt.Printf("  allowed_ips: %s\n", strings.Join(p.AllowedIPs, ", "))
		} else {
			fmt.Printf("  allowed_ips: (none)\n")
		}
		if p.Keepalive > 0 {
			fmt.Printf("  keepalive: %ds\n", p.Keepalive)
		}
	}
	return nil
}

func handleAddPeer(cfgPath string, cfg *config.Config) error {
	if cfg.Peers == nil {
		cfg.Peers = []config.Peer{}
	}
	reader := bufio.NewReader(os.Stdin)

	defName := fmt.Sprintf("peer%d", len(cfg.Peers)+1)
	name, err := promptString(reader, "peer name", defName)
	if err != nil {
		return err
	}

	pubKey, err := promptRequiredString(reader, "peer public key")
	if err != nil {
		return err
	}
	if err := config.ValidatePublicKey(strings.TrimSpace(pubKey)); err != nil {
		return fmt.Errorf("invalid public key: %v", err)
	}

	endpoint, err := promptString(reader, "peer endpoint (host:port)", "")
	if err != nil {
		return err
	}
	if endpoint != "" {
		if _, err := net.ResolveUDPAddr("udp", endpoint); err != nil {
			return fmt.Errorf("invalid endpoint: %v", err)
		}
	}

	allowed, err := promptRequiredString(reader, "allowed ip (CIDR)")
	if err != nil {
		return err
	}
	allowed, err = config.NormalizeAddress(allowed)
	if err != nil {
		return err
	}

	keepalive, err := promptInt(reader, "keepalive (seconds)", 25)
	if err != nil {
		return err
	}

	if config.PeerExists(cfg, name, pubKey) {
		return fmt.Errorf("peer already exists with same name or public key")
	}

	cfg.Peers = append(cfg.Peers, config.Peer{
		Name:       name,
		PublicKey:  strings.TrimSpace(pubKey),
		Endpoint:   strings.TrimSpace(endpoint),
		AllowedIPs: []string{allowed},
		Keepalive:  keepalive,
	})

	if err := config.Write(cfgPath, cfg); err != nil {
		return err
	}
	fmt.Printf("updated %s\n", cfgPath)
	return nil
}

func handleRemovePeer(cfgPath string, cfg *config.Config) error {
	if cfg.Peers == nil {
		cfg.Peers = []config.Peer{}
	}
	if len(cfg.Peers) == 0 {
		return errors.New("no peers in config")
	}
	reader := bufio.NewReader(os.Stdin)
	id, err := promptRequiredString(reader, "peer name or public key")
	if err != nil {
		return err
	}
	id = strings.TrimSpace(id)

	var kept []config.Peer
	var removed int
	for _, p := range cfg.Peers {
		if p.Name == id || p.PublicKey == id {
			removed++
			continue
		}
		kept = append(kept, p)
	}
	if removed == 0 {
		return fmt.Errorf("no peer matched %q", id)
	}
	cfg.Peers = kept
	if err := config.Write(cfgPath, cfg); err != nil {
		return err
	}
	fmt.Printf("removed %d peer(s)\n", removed)
	return nil
}

func handleExport(cfg *config.Config) error {
	name, err := os.Hostname()
	if err != nil || strings.TrimSpace(name) == "" {
		// Keep export JSON valid even if hostname lookup fails.
		name = "peer"
	}
	peer, err := config.BuildExportPeer(cfg, name)
	if err != nil {
		return err
	}
	b, err := json.MarshalIndent(peer, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(b))
	return nil
}

func handleImport(cfgPath string, cfg *config.Config) error {
	if cfg.Peers == nil {
		cfg.Peers = []config.Peer{}
	}
	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("paste peer JSON and press Ctrl+D:\n")
	data, err := io.ReadAll(reader)
	if err != nil {
		return err
	}
	input := strings.TrimSpace(string(data))
	if input == "" {
		return errors.New("no input provided")
	}

	var peer config.Peer
	if err := json.Unmarshal([]byte(input), &peer); err != nil {
		return fmt.Errorf("invalid json: %v", err)
	}

	peer, err = config.NormalizeImportPeer(peer)
	if err != nil {
		return err
	}

	if config.PeerExists(cfg, peer.Name, "") {
		return fmt.Errorf("peer name %q already exists", peer.Name)
	}

	cfg.Peers = append(cfg.Peers, peer)
	if err := config.Write(cfgPath, cfg); err != nil {
		return err
	}
	fmt.Printf("updated %s\n", cfgPath)
	return nil
}
