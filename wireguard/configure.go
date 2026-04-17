package wireguard

import (
	"errors"
	"fmt"
	"net"
	"runtime"
	"strconv"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"wing/config"
)

func SetInterfaceAddr(osIface, cidr string, mtu int) error {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}
	if ip.To4() == nil {
		return errors.New("only IPv4 supported in this minimal version")
	}

	switch runtime.GOOS {
	case "linux":
		if err := run("ip", "address", "replace", cidr, "dev", osIface); err != nil {
			return err
		}
		if mtu > 0 {
			if err := run("ip", "link", "set", "mtu", strconv.Itoa(mtu), "dev", osIface); err != nil {
				return err
			}
		}
		return run("ip", "link", "set", "up", "dev", osIface)

	case "darwin":
		// utun uses point-to-point syntax; pass the IP as both local and destination.
		netmask := maskToDotted(ipnet.Mask)
		if netmask == "" {
			return errors.New("invalid netmask")
		}
		args := []string{osIface, "inet", ip.String(), ip.String(), "netmask", netmask, "up"}
		if err := run("ifconfig", args...); err != nil {
			return err
		}
		if mtu > 0 {
			return run("ifconfig", osIface, "mtu", strconv.Itoa(mtu))
		}
		return nil

	default:
		return fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
}

func Configure(cfg *config.Config) error {
	// wgctrl can briefly report "no such device" after interface creation.
	var lastErr error
	for i := 0; i < 5; i++ {
		if err := configureOnce(cfg); err == nil {
			return nil
		} else {
			lastErr = err
			if strings.Contains(err.Error(), "no such device") {
				time.Sleep(100 * time.Millisecond)
				continue
			}
			return err
		}
	}
	return lastErr
}

func configureOnce(cfg *config.Config) error {
	client, err := wgctrl.New()
	if err != nil {
		return err
	}
	defer client.Close()

	priv, err := wgtypes.ParseKey(strings.TrimSpace(cfg.PrivateKey))
	if err != nil {
		return err
	}

	wgCfg := wgtypes.Config{
		PrivateKey:   &priv,
		ReplacePeers: true,
	}
	if cfg.ListenPort > 0 {
		lp := cfg.ListenPort
		wgCfg.ListenPort = &lp
	}

	for _, p := range cfg.Peers {
		pub, err := wgtypes.ParseKey(strings.TrimSpace(p.PublicKey))
		if err != nil {
			return fmt.Errorf("peer %q: invalid public key", p.Name)
		}
		peerCfg := wgtypes.PeerConfig{
			PublicKey:         pub,
			ReplaceAllowedIPs: true,
		}
		if p.Endpoint != "" {
			ep, err := net.ResolveUDPAddr("udp", p.Endpoint)
			if err != nil {
				return fmt.Errorf("peer %q: invalid endpoint", p.Name)
			}
			peerCfg.Endpoint = ep
		}
		if p.Keepalive > 0 {
			ka := time.Duration(p.Keepalive) * time.Second
			peerCfg.PersistentKeepaliveInterval = &ka
		}
		for _, a := range p.AllowedIPs {
			_, ipnet, err := net.ParseCIDR(a)
			if err != nil {
				return fmt.Errorf("peer %q: invalid allowed_ip %q", p.Name, a)
			}
			peerCfg.AllowedIPs = append(peerCfg.AllowedIPs, *ipnet)
		}
		wgCfg.Peers = append(wgCfg.Peers, peerCfg)
	}

	return client.ConfigureDevice(cfg.Interface, wgCfg)
}
