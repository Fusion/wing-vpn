package config

import (
	"encoding/json"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	ApplyDefaults(&c)
	if c.PublicKey == "" && c.PrivateKey != "" {
		if pub, err := PublicKeyFromPrivate(c.PrivateKey); err == nil {
			c.PublicKey = pub
		}
	}
	if err := EnsureRuntimeIdentity(&c); err != nil {
		return nil, err
	}
	return &c, nil
}

func SelfPath() (string, error) {
	dir, err := StateDir()
	if err != nil {
		return "", err
	}
	return dir + string(os.PathSeparator) + "self.json", nil
}

func EnsureExists(path string) (bool, error) {
	if _, err := os.Stat(path); err == nil {
		return false, nil
	} else if !os.IsNotExist(err) {
		return false, err
	}
	return InitAt(path)
}

func InitAt(path string) (bool, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return false, err
	}
	_ = ensureOwner(dir)
	if _, err := os.Stat(path); err == nil {
		return false, nil
	} else if !os.IsNotExist(err) {
		return false, err
	}
	priv, pub, err := GenerateKeypair()
	if err != nil {
		return false, err
	}
	controlPriv, controlPub, err := GenerateControlKeypair()
	if err != nil {
		return false, err
	}
	cfg := Config{
		Interface:         DefaultInterfaceName(),
		PrivateKey:        priv,
		PublicKey:         pub,
		ControlPrivateKey: controlPriv,
		ControlPublicKey:  controlPub,
		MyEndpoint:        "",
		Address:           "",
		ListenPort:        51821,
		MTU:               1420,
		DisableRoutes:     false,
		Peers:             []Peer{},
	}
	ApplyDefaults(&cfg)
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return false, err
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return false, err
	}
	_ = ensureOwner(path)
	return true, nil
}

func Write(path string, cfg *Config) error {
	if err := EnsureRuntimeIdentity(cfg); err != nil {
		return err
	}
	if cfg.Peers == nil {
		cfg.Peers = []Peer{}
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return err
	}
	_ = ensureOwner(path)
	return nil
}

func WriteState(cfg *Config, osIface string) error {
	dir, err := StateDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	_ = ensureOwner(dir)
	var allowed []string
	for _, p := range cfg.Peers {
		allowed = append(allowed, p.AllowedIPs...)
	}
	st := State{
		ConfigInterface: cfg.Interface,
		OSInterface:     osIface,
		DisableRoutes:   cfg.DisableRoutes,
		AllowedIPs:      allowed,
		PID:             os.Getpid(),
		CreatedAt:       time.Now().UTC().Format(time.RFC3339),
	}
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	path := statePath(cfg.Interface, dir)
	if err := os.WriteFile(path, b, 0o644); err != nil {
		return err
	}
	_ = ensureOwner(path)
	return nil
}

func ReadStates() ([]State, error) {
	dir, err := StateDir()
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var states []State
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		path := dir + string(os.PathSeparator) + e.Name()
		b, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var st State
		if err := json.Unmarshal(b, &st); err != nil {
			continue
		}
		states = append(states, st)
	}
	return states, nil
}

func ReadState(configIface string) (*State, error) {
	dir, err := StateDir()
	if err != nil {
		return nil, err
	}
	path := statePath(configIface, dir)
	if path == "" {
		return nil, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var st State
	if err := json.Unmarshal(b, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

func RemoveState(configIface string) error {
	dir, err := StateDir()
	if err != nil {
		return err
	}
	path := statePath(configIface, dir)
	if path == "" {
		return nil
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func StateDir() (string, error) {
	if v := os.Getenv("WING_STATE_DIR"); v != "" {
		return v, nil
	}
	if sudoUser := os.Getenv("SUDO_USER"); sudoUser != "" && sudoUser != "root" {
		// If invoked with sudo, put state/config under the original user's home.
		if u, err := user.Lookup(sudoUser); err == nil && u.HomeDir != "" {
			return u.HomeDir + string(os.PathSeparator) + ".wing", nil
		}
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return home + string(os.PathSeparator) + ".wing", nil
}

func DefaultInterfaceName() string {
	if runtime.GOOS == "darwin" {
		return "utun101"
	}
	return "wgwing0"
}

func statePath(configIface, dir string) string {
	if configIface == "" {
		return ""
	}
	safe := strings.ReplaceAll(configIface, string(os.PathSeparator), "_")
	return dir + string(os.PathSeparator) + safe + ".json"
}

func ensureOwner(path string) error {
	// When running under sudo, chown files back to the invoking user.
	uid, gid, ok := desiredOwner()
	if !ok {
		return nil
	}
	return os.Chown(path, uid, gid)
}

func desiredOwner() (int, int, bool) {
	if os.Geteuid() != 0 {
		return 0, 0, false
	}
	if uidStr := os.Getenv("SUDO_UID"); uidStr != "" {
		gidStr := os.Getenv("SUDO_GID")
		uid, err := strconv.Atoi(uidStr)
		if err != nil {
			return 0, 0, false
		}
		gid, err := strconv.Atoi(gidStr)
		if err != nil {
			return 0, 0, false
		}
		return uid, gid, true
	}
	sudoUser := os.Getenv("SUDO_USER")
	if sudoUser == "" || sudoUser == "root" {
		return 0, 0, false
	}
	u, err := user.Lookup(sudoUser)
	if err != nil {
		return 0, 0, false
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return 0, 0, false
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return 0, 0, false
	}
	return uid, gid, true
}
