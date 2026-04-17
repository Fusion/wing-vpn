package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"

	"wing/config"
	"wing/wireguard"
)

func main() {
	var cfgPath string
	var reuse bool
	var genkey bool
	var genpsk bool
	var wgGoPath string
	var down bool
	var status bool
	var osIfaceFlag string
	var detach bool
	var downAll bool
	var initCfg bool
	var setup bool
	var setupAddr string
	var setupPort int
	var setupMTU int
	var listPeers bool
	var addPeer bool
	var removePeer bool
	var exportPeer bool
	var importPeer bool

	flag.StringVar(&cfgPath, "config", "", "path to config json")
	flag.BoolVar(&reuse, "reuse", false, "reuse existing wireguard device if present (linux only)")
	flag.BoolVar(&genkey, "genkey", false, "generate a wireguard keypair and exit")
	flag.BoolVar(&genpsk, "genpsk", false, "generate a preshared key and exit")
	flag.StringVar(&wgGoPath, "wireguard-go", "", "path to wireguard-go binary (optional)")
	flag.BoolVar(&down, "down", false, "remove interface and routes (linux/macOS)")
	flag.BoolVar(&status, "status", false, "show wireguard device and peer status and exit")
	flag.StringVar(&osIfaceFlag, "os-iface", "", "os interface name (macOS only; optional for -down)")
	flag.BoolVar(&detach, "detach", false, "do not wait; leave interface up and return to prompt")
	flag.BoolVar(&downAll, "down-all", false, "remove all interfaces created by wing (from state)")
	flag.BoolVar(&initCfg, "init", false, "initialize ~/.wing/self.json with defaults")
	flag.BoolVar(&setup, "setup", false, "set address/listen_port/mtu in config")
	flag.StringVar(&setupAddr, "address", "", "address for -setup (default 10.7.0.1/32)")
	flag.IntVar(&setupPort, "listen-port", -1, "listen port for -setup (default 51821)")
	flag.IntVar(&setupMTU, "mtu", -1, "mtu for -setup (default 1420)")
	flag.BoolVar(&listPeers, "list-peers", false, "list peers from config")
	flag.BoolVar(&addPeer, "add-peer", false, "add a peer to config")
	flag.BoolVar(&removePeer, "remove-peer", false, "remove a peer from config")
	flag.BoolVar(&exportPeer, "export", false, "export this node as a peer json block")
	flag.BoolVar(&importPeer, "import", false, "import a peer json block into config")
	flag.Parse()

	if genkey || genpsk {
		if err := handleKeygen(genkey, genpsk); err != nil {
			fatalf("keygen: %v", err)
		}
		return
	}

	if initCfg {
		if err := handleInit(); err != nil {
			fatalf("init: %v", err)
		}
		return
	}

	if downAll {
		if err := wireguard.DownAll(); err != nil {
			fatalf("down-all: %v", err)
		}
		return
	}

	if cfgPath == "" {
		path, err := config.SelfPath()
		if err != nil {
			fatalf("config: %v", err)
		}
		cfgPath = path
	}

	if created, err := config.EnsureExists(cfgPath); err != nil {
		fatalf("config: %v", err)
	} else if created {
		fmt.Printf("created %s\n", cfgPath)
		// If we created the config on the fly, most commands should stop so the user
		// can fill peers/address. Only config-editing commands continue immediately.
		if !(setup || listPeers || addPeer || removePeer || exportPeer || importPeer) {
			fmt.Printf("edit address + peers, then rerun wing\n")
			return
		}
		fmt.Printf("continuing with requested command\n")
	}

	if setup {
		if err := handleSetup(cfgPath, setupAddr, setupPort, setupMTU); err != nil {
			fatalf("setup: %v", err)
		}
		return
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		fatalf("config: %v", err)
	}

	if cfg.Interface == "" {
		fatalf("config: interface required")
	}

	if down {
		if err := wireguard.Down(cfg, osIfaceFlag); err != nil {
			fatalf("down: %v", err)
		}
		return
	}
	if status {
		if err := wireguard.Status(cfg); err != nil {
			fatalf("status: %v", err)
		}
		return
	}
	if listPeers {
		if err := handleListPeers(cfg); err != nil {
			fatalf("list-peers: %v", err)
		}
		return
	}
	if addPeer {
		if err := handleAddPeer(cfgPath, cfg); err != nil {
			fatalf("add-peer: %v", err)
		}
		return
	}
	if removePeer {
		if err := handleRemovePeer(cfgPath, cfg); err != nil {
			fatalf("remove-peer: %v", err)
		}
		return
	}
	if exportPeer {
		if err := handleExport(cfg); err != nil {
			fatalf("export: %v", err)
		}
		return
	}
	if importPeer {
		if err := handleImport(cfgPath, cfg); err != nil {
			fatalf("import: %v", err)
		}
		return
	}

	if cfg.PrivateKey == "" {
		fatalf("config: private_key required")
	}
	if cfg.Address == "" {
		fatalf("config: address required")
	}

	if err := wireguard.ValidateConfig(cfg); err != nil {
		fatalf("config: %v", err)
	}

	if reuse && runtime.GOOS == "darwin" {
		fatalf("-reuse is not supported on macOS; stop the existing device first")
	}

	if wireguard.DeviceExists(cfg.Interface) && !reuse {
		fatalf("device %s already exists; use -reuse (linux only) or pick a different interface", cfg.Interface)
	}

	osIface := cfg.Interface
	var wgCmd *exec.Cmd
	deleteOnExit := false
	createdByWing := false
	if !wireguard.DeviceExists(cfg.Interface) {
		var err error
		if runtime.GOOS == "linux" {
			var createdKernel bool
			osIface, wgCmd, createdKernel, err = wireguard.EnsureLinuxDevice(cfg.Interface, wgGoPath, detach)
			if err != nil {
				fatalf("device: %v", err)
			}
			// createdKernel means we created a kernel WG link, so we own cleanup.
			deleteOnExit = createdKernel
			createdByWing = createdKernel || wgCmd != nil
		} else {
			osIface, wgCmd, err = wireguard.EnsureUserspaceWG(cfg.Interface, wgGoPath, detach)
			if err != nil {
				fatalf("wireguard-go: %v", err)
			}
			createdByWing = wgCmd != nil
		}
	}

	if err := wireguard.SetInterfaceAddr(osIface, cfg.Address, cfg.MTU); err != nil {
		fatalf("interface addr: %v", err)
	}

	if err := wireguard.Configure(cfg); err != nil {
		fatalf("configure wg: %v", err)
	}

	routesAdded := false
	if !cfg.DisableRoutes {
		if err := wireguard.AddPeerRoutes(osIface, cfg.Peers); err != nil {
			fatalf("routes: %v", err)
		}
		routesAdded = true
	}

	if createdByWing {
		if err := config.WriteState(cfg, osIface); err != nil {
			fatalf("state: %v", err)
		}
	}

	fmt.Printf("up: %s (os=%s, addr=%s)\n", cfg.Interface, osIface, cfg.Address)
	if detach {
		if wgCmd != nil && wgCmd.Process != nil {
			_ = wgCmd.Process.Release()
		}
		return
	}
	wireguard.WaitForSignal(cfg.Interface, wgCmd, osIface, cfg.Peers, routesAdded, deleteOnExit)
}

func fatalf(msg string, args ...any) {
	fmt.Fprintf(os.Stderr, msg+"\n", args...)
	os.Exit(1)
}

func promptString(r *bufio.Reader, label, def string) (string, error) {
	if def != "" {
		fmt.Printf("%s [%s]: ", label, def)
	} else {
		fmt.Printf("%s: ", label)
	}
	line, err := r.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	s := strings.TrimSpace(line)
	if s == "" {
		return def, nil
	}
	return s, nil
}

func promptInt(r *bufio.Reader, label string, def int) (int, error) {
	val, err := promptString(r, label, strconv.Itoa(def))
	if err != nil {
		return 0, err
	}
	n, err := strconv.Atoi(val)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("invalid %s: %q", label, val)
	}
	return n, nil
}

func promptRequiredString(r *bufio.Reader, label string) (string, error) {
	for {
		s, err := promptString(r, label, "")
		if err != nil {
			return "", err
		}
		if strings.TrimSpace(s) != "" {
			return s, nil
		}
		fmt.Printf("%s is required\n", label)
	}
}
