package wireguard

import (
	"fmt"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl"

	"wing/config"
)

func Status(cfg *config.Config) error {
	client, err := wgctrl.New()
	if err != nil {
		return err
	}
	defer client.Close()

	dev, err := client.Device(cfg.Interface)
	if err != nil {
		if isWgNotRunningErr(err) {
			printStatusFromConfig(cfg)
			return nil
		}
		return err
	}

	fmt.Printf("interface: %s\n", dev.Name)
	fmt.Printf("public_key: %s\n", dev.PublicKey.String())
	if dev.ListenPort > 0 {
		fmt.Printf("listen_port: %d\n", dev.ListenPort)
	} else {
		fmt.Printf("listen_port: (none)\n")
	}
	if dev.FirewallMark != 0 {
		fmt.Printf("fwmark: %d\n", dev.FirewallMark)
	}

	if len(dev.Peers) == 0 {
		fmt.Printf("peers: (none)\n")
		return nil
	}

	fmt.Printf("peers:\n")
	for _, p := range dev.Peers {
		fmt.Printf("- public_key: %s\n", p.PublicKey.String())
		if p.Endpoint != nil {
			fmt.Printf("  endpoint: %s\n", p.Endpoint.String())
		} else {
			fmt.Printf("  endpoint: (none)\n")
		}
		if len(p.AllowedIPs) > 0 {
			var ips []string
			for _, ip := range p.AllowedIPs {
				ips = append(ips, ip.String())
			}
			fmt.Printf("  allowed_ips: %s\n", strings.Join(ips, ", "))
		} else {
			fmt.Printf("  allowed_ips: (none)\n")
		}
		if !p.LastHandshakeTime.IsZero() {
			age := time.Since(p.LastHandshakeTime).Round(time.Second)
			fmt.Printf("  last_handshake: %s ago\n", age)
		} else {
			fmt.Printf("  last_handshake: never\n")
		}
		fmt.Printf("  rx_bytes: %d\n", p.ReceiveBytes)
		fmt.Printf("  tx_bytes: %d\n", p.TransmitBytes)
		if p.PersistentKeepaliveInterval > 0 {
			fmt.Printf("  keepalive: %s\n", p.PersistentKeepaliveInterval)
		}
	}
	return nil
}

func isWgNotRunningErr(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "no such device") ||
		strings.Contains(msg, "no such file") ||
		strings.Contains(msg, "file does not exist") ||
		strings.Contains(msg, "not found")
}

func printStatusFromConfig(cfg *config.Config) {
	fmt.Printf("interface: %s (not running)\n", cfg.Interface)
	if cfg.Address != "" {
		fmt.Printf("address: %s\n", cfg.Address)
	}
	if cfg.ListenPort > 0 {
		fmt.Printf("listen_port: %d\n", cfg.ListenPort)
	}
	if cfg.MyPublicKey != "" {
		fmt.Printf("my_public_key: %s\n", cfg.MyPublicKey)
	}
	if cfg.ControlPublicKey != "" {
		fmt.Printf("control_public_key: %s\n", cfg.ControlPublicKey)
	}
	if cfg.MyEndpoint != "" {
		fmt.Printf("my_endpoint: %s\n", cfg.MyEndpoint)
	}
	urls := config.EffectiveRendezvousURLs(cfg)
	if len(urls) > 0 {
		fmt.Printf("rendezvous_urls: %s\n", strings.Join(urls, ", "))
	}
	fmt.Printf("peers: %d\n", len(cfg.Peers))
	fmt.Printf("hint: start wing to bring the interface up, then re-run -status\n")
}
