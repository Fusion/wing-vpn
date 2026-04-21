package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"wing/cli"
	"wing/config"
	"wing/rendezvous"
	"wing/wireguard"
)

func printStartupBanner(mode string) {
	fmt.Printf("wing-vpn v%s (%q mode)\n", version, mode)
}

func main() {
	var cfgPath string
	var reuse bool
	var genkey bool
	var genrootkey bool
	var issuepeerkey bool
	var genpsk bool
	var rootPrivateKey string
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
	var reload bool
	var showVersion bool
	var debug bool
	var jsonOutput bool
	var daemonMode bool
	var serveRendezvous bool
	var rendezvousListen string
	var rendezvousTrustedRoots string
	var rendezvousStatus string

	flag.StringVar(&cfgPath, "config", "", "path to config json")
	flag.BoolVar(&reuse, "reuse", false, "reuse existing wireguard device if present (linux only)")
	flag.BoolVar(&genkey, "genkey", false, "generate a WireGuard keypair and exit")
	flag.BoolVar(&genrootkey, "genrootkey", false, "generate a root signing keypair and exit")
	flag.BoolVar(&issuepeerkey, "issuepeerkey", false, "issue a peer identity bundle signed by -root-private-key and exit")
	flag.BoolVar(&genpsk, "genpsk", false, "generate a preshared key and exit")
	flag.StringVar(&rootPrivateKey, "root-private-key", "", "base64 root private key used with -issuepeerkey")
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
	flag.BoolVar(&reload, "reload", false, "re-read config and apply to existing interface")
	flag.BoolVar(&showVersion, "version", false, "print version and exit")
	flag.BoolVar(&debug, "debug", false, "enable debug logging")
	flag.BoolVar(&jsonOutput, "json", false, "format supported command output as json")
	flag.BoolVar(&daemonMode, "daemon", false, "run wing as a long-lived control-plane daemon")
	flag.BoolVar(&serveRendezvous, "serve-rendezvous", false, "run the rendezvous HTTP service")
	flag.StringVar(&rendezvousListen, "rendezvous-listen", "", "listen address for -serve-rendezvous")
	flag.StringVar(&rendezvousTrustedRoots, "rendezvous-trusted-roots", "", "comma-separated base64 root public keys trusted by -serve-rendezvous")
	flag.StringVar(&rendezvousStatus, "rendezvous-status", "", "query configured rendezvous servers for self or a peer name/public key")
	flag.Parse()

	if showVersion {
		fmt.Printf("wing %s\n", version)
		return
	}

	if genkey || genrootkey || issuepeerkey || genpsk {
		if err := cli.HandleKeygen(genkey, genrootkey, issuepeerkey, genpsk, rootPrivateKey); err != nil {
			fatalf("keygen: %v", err)
		}
		return
	}

	if initCfg {
		if err := cli.HandleInit(); err != nil {
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

	if serveRendezvous {
		if rendezvousListen == "" {
			rendezvousListen = config.DefaultRendezvousListen
		}
		trustedRoots := splitCommaSeparated(rendezvousTrustedRoots)
		if len(trustedRoots) == 0 && strings.TrimSpace(cfgPath) != "" {
			serveCfg, err := config.Load(cfgPath)
			if err != nil {
				fatalf("serve-rendezvous config: %v", err)
			}
			trustedRoots = append(trustedRoots, serveCfg.Rendezvous.TrustedRootPublicKeys...)
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		printStartupBanner("rendezvous")
		if err := rendezvous.Serve(ctx, rendezvousListen, trustedRoots, debug); err != nil {
			fatalf("serve-rendezvous: %v", err)
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
		if err := cli.HandleSetup(cfgPath, setupAddr, setupPort, setupMTU); err != nil {
			fatalf("setup: %v", err)
		}
		return
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		fatalf("config: %v", err)
	}
	if err := config.PersistRuntimeIdentity(cfgPath, cfg); err != nil {
		fatalf("config identity: %v", err)
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
	if rendezvousStatus != "" {
		if err := cli.HandleRendezvousStatus(cfg, rendezvousStatus, jsonOutput); err != nil {
			cli.PrintRendezvousStatusHint()
			fatalf("rendezvous-status: %v", err)
		}
		return
	}
	if reload {
		if err := wireguard.Reload(cfg, osIfaceFlag); err != nil {
			fatalf("reload: %v", err)
		}
		return
	}
	if listPeers {
		if err := cli.HandleListPeers(cfg); err != nil {
			fatalf("list-peers: %v", err)
		}
		return
	}
	if addPeer {
		if err := cli.HandleAddPeer(cfgPath, cfg); err != nil {
			fatalf("add-peer: %v", err)
		}
		return
	}
	if removePeer {
		if err := cli.HandleRemovePeer(cfgPath, cfg); err != nil {
			fatalf("remove-peer: %v", err)
		}
		return
	}
	if exportPeer {
		if err := cli.HandleExport(cfg); err != nil {
			fatalf("export: %v", err)
		}
		return
	}
	if importPeer {
		if err := cli.HandleImport(cfgPath, cfg); err != nil {
			fatalf("import: %v", err)
		}
		return
	}

	if cfg.PrivateKey == "" {
		fatalf("config: private_key required")
	}
	if cfg.PublicKey == "" {
		fatalf("config: public_key required")
	}
	if cfg.Address == "" {
		fatalf("config: address required")
	}

	if err := wireguard.ValidateConfig(cfg); err != nil {
		fatalf("config: %v", err)
	}

	if daemonMode {
		if detach {
			fatalf("-detach cannot be used with -daemon; run it under a service manager")
		}
		printStartupBanner("daemon")
		if err := runDaemon(cfgPath, cfg, wgGoPath, reuse); err != nil {
			fatalf("daemon: %v", err)
		}
		return
	}

	sess, err := startSession(cfg, wgGoPath, reuse, detach)
	if err != nil {
		fatalf("up: %v", err)
	}

	fmt.Printf("up: %s (os=%s, addr=%s)\n", cfg.Interface, sess.osIface, cfg.Address)
	if detach {
		if sess.wgCmd != nil && sess.wgCmd.Process != nil {
			_ = sess.wgCmd.Process.Release()
		}
		return
	}
	wireguard.WaitForSignal(cfg.Interface, sess.wgCmd, sess.osIface, cfg.Peers, sess.routesAdded, sess.deleteOnExit)
}

func fatalf(msg string, args ...any) {
	fmt.Fprintf(os.Stderr, msg+"\n", args...)
	os.Exit(1)
}

func splitCommaSeparated(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		out = append(out, part)
	}
	return out
}
