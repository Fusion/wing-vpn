package stun

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	bindingRequestType  = 0x0001
	bindingSuccessType  = 0x0101
	xorMappedAddrType   = 0x0020
	mappedAddrType      = 0x0001
	stunMagicCookie     = 0x2112A442
	stunHeaderSize      = 20
	defaultProbeTimeout = 3 * time.Second
)

type Result struct {
	Server      string
	LocalAddr   string
	Reflexive   string
	GuessedPort string
}

func ProbeServers(ctx context.Context, servers []string, listenPort int) ([]Result, error) {
	var results []Result
	var firstErr error
	for _, server := range servers {
		res, err := Probe(ctx, server, listenPort)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		results = append(results, *res)
	}
	if len(results) == 0 && firstErr != nil {
		return nil, firstErr
	}
	return results, nil
}

func Probe(ctx context.Context, server string, listenPort int) (*Result, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > defaultProbeTimeout {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, defaultProbeTimeout)
		defer cancel()
	}

	serverAddr, err := net.ResolveUDPAddr("udp4", server)
	if err != nil {
		return nil, err
	}

	localAddr := ":0"
	if listenPort > 0 {
		localAddr = ":" + strconv.Itoa(listenPort)
	}
	lc := net.ListenConfig{
		Control: func(_, _ string, c syscall.RawConn) error {
			var setErr error
			if err := c.Control(func(fd uintptr) {
				if listenPort <= 0 {
					return
				}
				_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
				if err := unix.SetsockoptInt(int(fd), syscall.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil {
					setErr = err
				}
			}); err != nil {
				return err
			}
			return setErr
		},
	}
	packetConn, err := lc.ListenPacket(ctx, "udp4", localAddr)
	if err != nil {
		return nil, err
	}
	defer packetConn.Close()

	conn, ok := packetConn.(*net.UDPConn)
	if !ok {
		return nil, errors.New("listen packet did not return UDPConn")
	}
	if err := conn.SetDeadline(time.Now().Add(defaultProbeTimeout)); err != nil {
		return nil, err
	}

	txID := make([]byte, 12)
	if _, err := rand.Read(txID); err != nil {
		return nil, err
	}
	req := make([]byte, stunHeaderSize)
	binary.BigEndian.PutUint16(req[0:2], bindingRequestType)
	binary.BigEndian.PutUint16(req[2:4], 0)
	binary.BigEndian.PutUint32(req[4:8], stunMagicCookie)
	copy(req[8:20], txID)

	if _, err := conn.WriteToUDP(req, serverAddr); err != nil {
		return nil, err
	}

	buf := make([]byte, 1500)
	n, _, err := readResponse(conn, buf, txID)
	if err != nil {
		return nil, err
	}
	reflexive, err := parseMappedAddress(buf[:n], txID)
	if err != nil {
		return nil, err
	}
	result := &Result{
		Server:    serverAddr.String(),
		LocalAddr: conn.LocalAddr().String(),
		Reflexive: reflexive,
	}
	if listenPort > 0 {
		host, _, err := net.SplitHostPort(reflexive)
		if err == nil {
			result.GuessedPort = net.JoinHostPort(host, strconv.Itoa(listenPort))
		}
	}
	return result, nil
}

func readResponse(conn *net.UDPConn, buf []byte, txID []byte) (int, *net.UDPAddr, error) {
	for {
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			return 0, nil, err
		}
		if n < stunHeaderSize {
			continue
		}
		if binary.BigEndian.Uint32(buf[4:8]) != stunMagicCookie {
			continue
		}
		if binary.BigEndian.Uint16(buf[0:2]) != bindingSuccessType {
			continue
		}
		if string(buf[8:20]) != string(txID) {
			continue
		}
		return n, addr, nil
	}
}

func parseMappedAddress(msg []byte, txID []byte) (string, error) {
	if len(msg) < stunHeaderSize {
		return "", errors.New("stun response too short")
	}
	msgLen := int(binary.BigEndian.Uint16(msg[2:4]))
	if len(msg) < stunHeaderSize+msgLen {
		return "", errors.New("stun response truncated")
	}
	offset := stunHeaderSize
	for offset+4 <= stunHeaderSize+msgLen {
		attrType := binary.BigEndian.Uint16(msg[offset : offset+2])
		attrLen := int(binary.BigEndian.Uint16(msg[offset+2 : offset+4]))
		start := offset + 4
		end := start + attrLen
		if end > len(msg) {
			return "", errors.New("stun attribute truncated")
		}
		value := msg[start:end]
		switch attrType {
		case xorMappedAddrType:
			return decodeMappedAddress(value, txID, true)
		case mappedAddrType:
			return decodeMappedAddress(value, txID, false)
		}
		padding := (4 - (attrLen % 4)) % 4
		offset = end + padding
	}
	return "", errors.New("stun response missing mapped address")
}

func decodeMappedAddress(value []byte, txID []byte, xor bool) (string, error) {
	if len(value) < 8 {
		return "", errors.New("mapped address too short")
	}
	family := value[1]
	port := binary.BigEndian.Uint16(value[2:4])
	addrBytes := append([]byte(nil), value[4:]...)
	if xor {
		port ^= uint16(stunMagicCookie >> 16)
		cookie := make([]byte, 4)
		binary.BigEndian.PutUint32(cookie, stunMagicCookie)
		switch family {
		case 0x01:
			if len(addrBytes) != 4 {
				return "", errors.New("invalid IPv4 XOR-MAPPED-ADDRESS length")
			}
			for i := range addrBytes {
				addrBytes[i] ^= cookie[i]
			}
		case 0x02:
			if len(addrBytes) != 16 {
				return "", errors.New("invalid IPv6 XOR-MAPPED-ADDRESS length")
			}
			xorKey := append(cookie, txID...)
			for i := range addrBytes {
				addrBytes[i] ^= xorKey[i]
			}
		default:
			return "", fmt.Errorf("unsupported address family %d", family)
		}
	}
	ip := net.IP(addrBytes)
	if ip == nil {
		return "", errors.New("invalid IP in mapped address")
	}
	return net.JoinHostPort(ip.String(), strconv.Itoa(int(port))), nil
}
