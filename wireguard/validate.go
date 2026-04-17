package wireguard

import (
	"fmt"
	"net"

	"wing/config"
)

func ValidateConfig(cfg *config.Config) error {
	_, _, err := net.ParseCIDR(cfg.Address)
	if err != nil {
		return fmt.Errorf("invalid address %q", cfg.Address)
	}
	for _, p := range cfg.Peers {
		if p.PublicKey == "" {
			return fmt.Errorf("peer %q: public_key required", p.Name)
		}
		if len(p.AllowedIPs) == 0 {
			return fmt.Errorf("peer %q: allowed_ips required", p.Name)
		}
		for _, a := range p.AllowedIPs {
			_, ipnet, err := net.ParseCIDR(a)
			if err != nil {
				return fmt.Errorf("peer %q: invalid allowed_ip %q", p.Name, a)
			}
			if !isHostRouteIPv4(ipnet) {
				return fmt.Errorf("peer %q: allowed_ip must be /32 IPv4 in this minimal version: %q", p.Name, a)
			}
		}
	}
	return nil
}
