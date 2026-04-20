package wireguard

import (
	"fmt"
	"net"
	"runtime"
	"strings"

	"wing/config"
)

func AddPeerRoutes(osIface string, peers []config.Peer) error {
	// This tool only adds /32 host routes to avoid touching default routes.
	for _, p := range peers {
		for _, a := range p.AllowedIPs {
			ip, ipnet, err := net.ParseCIDR(a)
			if err != nil {
				return err
			}
			if !isHostRouteIPv4(ipnet) {
				return fmt.Errorf("only /32 IPv4 allowed for routes: %s", a)
			}
			switch runtime.GOOS {
			case "linux":
				if err := run("ip", "route", "replace", ip.String()+"/32", "dev", osIface); err != nil {
					return err
				}
			case "darwin":
				if err := routeAddHostDarwin(ip.String(), osIface); err != nil {
					return err
				}
			default:
				return fmt.Errorf("unsupported OS: %s", runtime.GOOS)
			}
		}
	}
	return nil
}

func routeAddHostDarwin(ip, iface string) error {
	err := run("route", "-n", "add", "-host", ip, "-interface", iface)
	if err == nil {
		return nil
	}
	if strings.Contains(err.Error(), "File exists") || strings.Contains(err.Error(), "exists") {
		return run("route", "-n", "change", "-host", ip, "-interface", iface)
	}
	return err
}

func removePeerRoutes(osIface string, peers []config.Peer) {
	for _, p := range peers {
		for _, a := range p.AllowedIPs {
			ip, ipnet, err := net.ParseCIDR(a)
			if err != nil || !isHostRouteIPv4(ipnet) {
				continue
			}
			switch runtime.GOOS {
			case "linux":
				_ = run("ip", "route", "del", ip.String()+"/32", "dev", osIface)
			case "darwin":
				_ = run("route", "-n", "delete", "-host", ip.String(), "-interface", osIface)
			}
		}
	}
}

func RemovePeerRoutes(osIface string, peers []config.Peer) {
	removePeerRoutes(osIface, peers)
}

func removeAllowedIPRoutes(osIface string, allowedIPs []string) {
	if osIface == "" || len(allowedIPs) == 0 {
		return
	}
	peers := peersFromAllowedIPs(allowedIPs)
	removePeerRoutes(osIface, peers)
}

func peersFromAllowedIPs(allowedIPs []string) []config.Peer {
	var peers []config.Peer
	for _, a := range allowedIPs {
		peers = append(peers, config.Peer{AllowedIPs: []string{a}})
	}
	return peers
}

func isHostRouteIPv4(ipnet *net.IPNet) bool {
	if ipnet == nil || ipnet.IP.To4() == nil {
		return false
	}
	ones, bits := ipnet.Mask.Size()
	return bits == 32 && ones == 32
}
