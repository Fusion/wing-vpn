package wireguard

import (
	"fmt"
	"net"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"wing/config"
)

type PeerState struct {
	PublicKey     string
	Endpoint      string
	LastHandshake time.Time
	Keepalive     time.Duration
	RXBytes       int64
	TXBytes       int64
}

func PeerStates(iface string) (map[string]PeerState, error) {
	client, err := wgctrl.New()
	if err != nil {
		return nil, err
	}
	defer client.Close()

	device, err := client.Device(iface)
	if err != nil {
		return nil, err
	}
	states := make(map[string]PeerState, len(device.Peers))
	for _, peer := range device.Peers {
		state := PeerState{
			PublicKey:     peer.PublicKey.String(),
			LastHandshake: peer.LastHandshakeTime,
			Keepalive:     peer.PersistentKeepaliveInterval,
			RXBytes:       peer.ReceiveBytes,
			TXBytes:       peer.TransmitBytes,
		}
		if peer.Endpoint != nil {
			state.Endpoint = peer.Endpoint.String()
		}
		states[state.PublicKey] = state
	}
	return states, nil
}

func UpdatePeerEndpoint(iface string, peer config.Peer, endpoint string, keepalive int) error {
	client, err := wgctrl.New()
	if err != nil {
		return err
	}
	defer client.Close()

	pub, err := wgtypes.ParseKey(strings.TrimSpace(peer.PublicKey))
	if err != nil {
		return fmt.Errorf("peer %q: invalid public key", peer.Name)
	}
	ep, err := net.ResolveUDPAddr("udp", endpoint)
	if err != nil {
		return fmt.Errorf("peer %q: invalid endpoint", peer.Name)
	}

	peerCfg := wgtypes.PeerConfig{
		PublicKey: pub,
		Endpoint:  ep,
	}
	if keepalive > 0 {
		interval := time.Duration(keepalive) * time.Second
		peerCfg.PersistentKeepaliveInterval = &interval
	}
	return client.ConfigureDevice(iface, wgtypes.Config{Peers: []wgtypes.PeerConfig{peerCfg}})
}

func TriggerPeerHandshake(peer config.Peer, probePort int) error {
	if len(peer.AllowedIPs) == 0 {
		return nil
	}
	ip, _, err := net.ParseCIDR(peer.AllowedIPs[0])
	if err != nil {
		return err
	}
	port := probePort
	if port <= 0 {
		port = 9
	}
	addr := net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("udp4", addr, time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	_, err = conn.Write([]byte{0})
	return err
}
