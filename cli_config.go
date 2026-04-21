package main

import (
	"bufio"
	"crypto/ed25519"
	"encoding/base64"
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
	if err := config.EnsureRuntimeIdentity(cfg); err != nil {
		return err
	}
	if cfg.Peers == nil {
		cfg.Peers = []config.Peer{}
	}

	if cfg.PrivateKey != "" && cfg.PublicKey == "" {
		// Derive public_key from private_key when it is absent so exports work.
		if pub, err := config.PublicKeyFromPrivate(cfg.PrivateKey); err == nil {
			cfg.PublicKey = pub
		}
	}

	defAddr := cfg.Address
	if defAddr == "" {
		defAddr = "10.7.0.1"
	}
	defName := strings.TrimSpace(cfg.Name)
	if defName == "" {
		if hostname, err := os.Hostname(); err == nil {
			defName = strings.TrimSpace(hostname)
		}
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
	defRendezvousURLs := strings.Join(config.EffectiveRendezvousURLs(cfg), ", ")

	reader := bufio.NewReader(os.Stdin)
	name, err := promptString(reader, "name (optional)", defName)
	if err != nil {
		return err
	}
	if addr == "" {
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
	rendezvousInput, err := promptString(reader, "rendezvous urls (comma-separated; optional)", defRendezvousURLs)
	if err != nil {
		return err
	}
	var issued *config.IssuedPeerIdentity
	editIssuedIdentity, err := promptYesNo(reader, "edit issued rendezvous identity", false)
	if err != nil {
		return err
	}
	if editIssuedIdentity {
		issued, err = promptIssuedIdentityBlock(reader)
		if err != nil {
			return err
		}
	}

	normAddr, err := config.NormalizeAddress(addr)
	if err != nil {
		return err
	}
	cfg.Address = normAddr
	cfg.Name = strings.TrimSpace(name)
	cfg.ListenPort = port
	cfg.MTU = mtu
	if endpoint != "" {
		cfg.MyEndpoint = endpoint
	}
	if strings.TrimSpace(rendezvousInput) != "" {
		cfg.Rendezvous.URLs = splitCommaSeparated(rendezvousInput)
	}
	if issued != nil {
		cfg.PrivateKey = issued.PrivateKey
		cfg.PublicKey = issued.PublicKey
		cfg.ControlPrivateKey = issued.ControlPrivateKey
		cfg.ControlPublicKey = issued.ControlPublicKey
		cfg.RootPublicKey = issued.RootPublicKey
		cfg.IdentitySignature = issued.IdentitySignature
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
		if p.ControlPublicKey != "" {
			fmt.Printf("  control_public_key: %s\n", p.ControlPublicKey)
		}
		if p.RootPublicKey != "" {
			fmt.Printf("  root_public_key: %s\n", p.RootPublicKey)
		}
		if p.IdentitySignature != "" {
			fmt.Printf("  identity_signature: %s\n", p.IdentitySignature)
		}
		fmt.Printf("  dynamic_endpoint: %t\n", p.DynamicEndpoint)
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

func promptIssuedIdentityBlock(r *bufio.Reader) (*config.IssuedPeerIdentity, error) {
	fmt.Printf("paste issued rendezvous identity block (optional; blank line to keep current identity)\n")
	fmt.Printf("end with an empty line:\n")
	var lines []string
	for {
		line, err := r.ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, err
		}
		line = strings.TrimRight(line, "\r\n")
		if strings.TrimSpace(line) == "" {
			if len(lines) == 0 {
				return nil, nil
			}
			break
		}
		lines = append(lines, line)
		if errors.Is(err, io.EOF) {
			break
		}
	}
	return parseIssuedIdentityBlock(strings.Join(lines, "\n"))
}

func promptYesNo(r *bufio.Reader, label string, def bool) (bool, error) {
	defValue := "n"
	if def {
		defValue = "y"
	}
	for {
		value, err := promptString(r, label+" (y/n)", defValue)
		if err != nil {
			return false, err
		}
		switch strings.ToLower(strings.TrimSpace(value)) {
		case "y", "yes":
			return true, nil
		case "n", "no":
			return false, nil
		}
		fmt.Printf("%s must be y or n\n", label)
	}
}

func parseIssuedIdentityBlock(input string) (*config.IssuedPeerIdentity, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return nil, nil
	}
	if !strings.HasPrefix(input, "{") {
		lines := strings.Split(input, "\n")
		for i := len(lines) - 1; i >= 0; i-- {
			trimmed := strings.TrimSpace(lines[i])
			if trimmed == "" {
				continue
			}
			lines[i] = strings.TrimRight(lines[i], ", \t")
			break
		}
		input = "{\n" + strings.Join(lines, "\n") + "\n}"
	}
	var issued config.IssuedPeerIdentity
	if err := json.Unmarshal([]byte(input), &issued); err != nil {
		return nil, fmt.Errorf("invalid issued identity block: %v", err)
	}
	if strings.TrimSpace(issued.PrivateKey) == "" {
		return nil, errors.New("issued identity missing private_key")
	}
	if strings.TrimSpace(issued.PublicKey) == "" {
		return nil, errors.New("issued identity missing public_key")
	}
	if strings.TrimSpace(issued.ControlPrivateKey) == "" {
		return nil, errors.New("issued identity missing control_private_key")
	}
	if strings.TrimSpace(issued.ControlPublicKey) == "" {
		return nil, errors.New("issued identity missing control_public_key")
	}
	if strings.TrimSpace(issued.RootPublicKey) == "" {
		return nil, errors.New("issued identity missing root_public_key")
	}
	if strings.TrimSpace(issued.IdentitySignature) == "" {
		return nil, errors.New("issued identity missing identity_signature")
	}
	pubFromPriv, err := config.PublicKeyFromPrivate(issued.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("invalid private_key: %v", err)
	}
	if err := config.ValidatePublicKey(issued.PublicKey); err != nil {
		return nil, fmt.Errorf("invalid public_key: %v", err)
	}
	if pubFromPriv != issued.PublicKey {
		return nil, errors.New("private_key does not match public_key")
	}
	controlPriv, err := config.ParseControlPrivateKey(issued.ControlPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("invalid control_private_key: %v", err)
	}
	if err := config.ValidateControlPublicKey(issued.ControlPublicKey); err != nil {
		return nil, fmt.Errorf("invalid control_public_key: %v", err)
	}
	if got := base64.StdEncoding.EncodeToString(controlPriv.Public().(ed25519.PublicKey)); got != issued.ControlPublicKey {
		return nil, errors.New("control_private_key does not match control_public_key")
	}
	if err := config.ValidateControlPublicKey(issued.RootPublicKey); err != nil {
		return nil, fmt.Errorf("invalid root_public_key: %v", err)
	}
	if err := config.VerifyIdentityBinding(issued.RootPublicKey, issued.PublicKey, issued.ControlPublicKey, issued.IdentitySignature); err != nil {
		return nil, fmt.Errorf("invalid identity_signature: %v", err)
	}
	return &issued, nil
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
	controlPub, err := promptString(reader, "peer control public key (optional)", "")
	if err != nil {
		return err
	}
	controlPub = strings.TrimSpace(controlPub)
	if controlPub != "" {
		if err := config.ValidateControlPublicKey(controlPub); err != nil {
			return fmt.Errorf("invalid control public key: %v", err)
		}
	}
	rootPub, err := promptString(reader, "peer root public key (optional)", "")
	if err != nil {
		return err
	}
	rootPub = strings.TrimSpace(rootPub)
	if rootPub != "" {
		if err := config.ValidateControlPublicKey(rootPub); err != nil {
			return fmt.Errorf("invalid root public key: %v", err)
		}
	}
	identitySig, err := promptString(reader, "peer identity signature (optional)", "")
	if err != nil {
		return err
	}
	identitySig = strings.TrimSpace(identitySig)

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

	if (rootPub == "") != (identitySig == "") {
		return fmt.Errorf("root public key and identity signature must be provided together")
	}
	if rootPub != "" {
		if err := config.VerifyIdentityBinding(rootPub, strings.TrimSpace(pubKey), controlPub, identitySig); err != nil {
			return fmt.Errorf("invalid identity signature: %v", err)
		}
	}

	cfg.Peers = append(cfg.Peers, config.Peer{
		Name:             name,
		PublicKey:        strings.TrimSpace(pubKey),
		ControlPublicKey: controlPub,
		RootPublicKey:    rootPub,
		IdentitySignature: identitySig,
		Endpoint:         strings.TrimSpace(endpoint),
		DynamicEndpoint:  controlPub != "",
		AllowedIPs:       []string{allowed},
		Keepalive:        keepalive,
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
	name := strings.TrimSpace(cfg.Name)
	if name == "" {
		var err error
		name, err = os.Hostname()
		if err != nil || strings.TrimSpace(name) == "" {
		// Keep export JSON valid even if hostname lookup fails.
			name = "peer"
		}
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
