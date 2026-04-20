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
	if cfg.ControlPublicKey != "" {
		if err := config.ValidateControlPublicKey(cfg.ControlPublicKey); err != nil {
			return fmt.Errorf("invalid control_public_key: %v", err)
		}
	}
	for _, p := range cfg.Peers {
		if p.PublicKey == "" {
			return fmt.Errorf("peer %q: public_key required", p.Name)
		}
		if p.ControlPublicKey != "" {
			if err := config.ValidateControlPublicKey(p.ControlPublicKey); err != nil {
				return fmt.Errorf("peer %q: invalid control_public_key: %v", p.Name, err)
			}
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
