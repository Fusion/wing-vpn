package wireguard

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"syscall"

	"wing/config"
)

func WaitForSignal(configIface string, cmd *exec.Cmd, osIface string, peers []config.Peer, routesAdded bool, deleteOnExit bool) {
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, os.Interrupt, syscall.SIGTERM)
	<-sigc
	if routesAdded {
		removePeerRoutes(osIface, peers)
	}
	if deleteOnExit && runtime.GOOS == "linux" {
		_ = run("ip", "link", "del", osIface)
	}
	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		_, _ = cmd.Process.Wait()
	}
	_ = config.RemoveState(configIface)
}

func Down(cfg *config.Config, osIfaceFlag string) error {
	switch runtime.GOOS {
	case "linux":
		if !DeviceExists(cfg.Interface) {
			return fmt.Errorf("device %s not found", cfg.Interface)
		}
		if !cfg.DisableRoutes {
			removePeerRoutes(cfg.Interface, cfg.Peers)
		}
		if err := run("ip", "link", "del", cfg.Interface); err != nil {
			return err
		}
		_ = config.RemoveState(cfg.Interface)
		return nil

	case "darwin":
		if !DeviceExists(cfg.Interface) {
			return fmt.Errorf("device %s not found", cfg.Interface)
		}
		osIface := osIfaceFlag
		// macOS utun names are dynamic; try address/route matching if -os-iface not provided.
		if osIface == "" {
			ip, _, err := net.ParseCIDR(cfg.Address)
			if err == nil && ip != nil {
				if iface, ferr := findDarwinIfaceByIP(ip); ferr == nil {
					osIface = iface
				}
			}
		}
		if osIface == "" && len(cfg.Peers) > 0 {
			if iface, ferr := findDarwinIfaceByRoute(cfg.Peers); ferr == nil {
				osIface = iface
			}
		}

		if osIface == "" {
			return errors.New("could not determine utun interface; rerun with -os-iface utunX")
		}

		if !cfg.DisableRoutes {
			removePeerRoutes(osIface, cfg.Peers)
		}
		_ = run("ifconfig", osIface, "down")
		_ = terminateWireguardGo(cfg.Interface)
		_ = config.RemoveState(cfg.Interface)
		return nil

	default:
		return fmt.Errorf("-down is not supported on %s", runtime.GOOS)
	}
}

func DownAll() error {
	states, err := config.ReadStates()
	if err != nil {
		return err
	}
	if len(states) == 0 {
		return errors.New("no wing state files found")
	}
	for _, st := range states {
		// State tracks both logical config interface and OS interface (utunX on macOS).
		if !st.DisableRoutes && len(st.AllowedIPs) > 0 {
			removeAllowedIPRoutes(st.OSInterface, st.AllowedIPs)
		}
		switch runtime.GOOS {
		case "linux":
			if st.OSInterface != "" {
				_ = run("ip", "link", "del", st.OSInterface)
			} else if st.ConfigInterface != "" {
				_ = run("ip", "link", "del", st.ConfigInterface)
			}
		case "darwin":
			if st.OSInterface != "" {
				_ = run("ifconfig", st.OSInterface, "down")
			}
			if st.ConfigInterface != "" {
				_ = terminateWireguardGo(st.ConfigInterface)
			}
		}

		_ = config.RemoveState(st.ConfigInterface)
	}
	return nil
}

func Reload(cfg *config.Config, osIfaceFlag string) error {
	if !DeviceExists(cfg.Interface) {
		return fmt.Errorf("device %s not found; start wing first", cfg.Interface)
	}

	osIface := cfg.Interface
	if runtime.GOOS == "darwin" {
		if osIfaceFlag != "" {
			osIface = osIfaceFlag
		} else {
			if st, err := config.ReadState(cfg.Interface); err == nil && st != nil && st.OSInterface != "" {
				osIface = st.OSInterface
			}
			if osIface == cfg.Interface {
				if ip, _, err := net.ParseCIDR(cfg.Address); err == nil && ip != nil {
					if iface, ferr := findDarwinIfaceByIP(ip); ferr == nil {
						osIface = iface
					}
				}
			}
			if osIface == cfg.Interface && len(cfg.Peers) > 0 {
				if iface, ferr := findDarwinIfaceByRoute(cfg.Peers); ferr == nil {
					osIface = iface
				}
			}
		}
		if osIface == cfg.Interface {
			return errors.New("could not determine utun interface; rerun with -os-iface utunX")
		}
	}

	if st, err := config.ReadState(cfg.Interface); err == nil && st != nil {
		oldIface := st.OSInterface
		if oldIface == "" {
			oldIface = osIface
		}
		removeAllowedIPRoutes(oldIface, st.AllowedIPs)
	}

	if err := Configure(cfg); err != nil {
		return err
	}
	if !cfg.DisableRoutes {
		if err := AddPeerRoutes(osIface, cfg.Peers); err != nil {
			return err
		}
	}
	return config.WriteState(cfg, osIface)
}

func findDarwinIfaceByIP(ip net.IP) (string, error) {
	out, err := exec.Command("ifconfig", "-a").Output()
	if err != nil {
		return "", err
	}
	lines := strings.Split(string(out), "\n")
	current := ""
	for _, line := range lines {
		if strings.HasPrefix(line, "\t") || strings.HasPrefix(line, " ") {
			fields := strings.Fields(line)
			if len(fields) >= 2 && fields[0] == "inet" {
				if net.ParseIP(fields[1]).Equal(ip) && strings.HasPrefix(current, "utun") {
					return current, nil
				}
			}
			continue
		}
		if strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			current = strings.TrimSpace(parts[0])
		}
	}
	return "", errors.New("utun with address not found")
}

func findDarwinIfaceByRoute(peers []config.Peer) (string, error) {
	for _, p := range peers {
		for _, a := range p.AllowedIPs {
			ip, _, err := net.ParseCIDR(a)
			if err != nil || ip == nil {
				continue
			}
			out, err := exec.Command("route", "-n", "get", ip.String()).Output()
			if err != nil {
				continue
			}
			for _, line := range strings.Split(string(out), "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "interface:") {
					fields := strings.Fields(line)
					if len(fields) >= 2 && strings.HasPrefix(fields[1], "utun") {
						return fields[1], nil
					}
				}
			}
		}
	}
	return "", errors.New("utun not found from routes")
}

func terminateWireguardGo(iface string) error {
	if iface == "" {
		return nil
	}
	out, err := exec.Command("pgrep", "-f", "wireguard-go.*"+iface).Output()
	if err != nil {
		return err
	}
	pids := strings.Fields(string(out))
	for _, pid := range pids {
		_ = run("kill", pid)
	}
	return nil
}
