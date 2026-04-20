package stun

import (
	"encoding/binary"
	"net"
	"testing"
)

func TestDecodeMappedAddressXORIPv4(t *testing.T) {
	txID := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	ip := net.ParseIP("203.0.113.10").To4()
	if ip == nil {
		t.Fatalf("failed to parse IP")
	}
	value := make([]byte, 8)
	value[1] = 0x01
	binary.BigEndian.PutUint16(value[2:4], uint16(51821)^uint16(stunMagicCookie>>16))
	cookie := make([]byte, 4)
	binary.BigEndian.PutUint32(cookie, stunMagicCookie)
	for i := range ip {
		value[4+i] = ip[i] ^ cookie[i]
	}
	got, err := decodeMappedAddress(value, txID, true)
	if err != nil {
		t.Fatalf("decodeMappedAddress error: %v", err)
	}
	if got != "203.0.113.10:51821" {
		t.Fatalf("decodeMappedAddress = %q, want %q", got, "203.0.113.10:51821")
	}
}

func TestParseMappedAddressFromResponse(t *testing.T) {
	txID := []byte{1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3}
	value := make([]byte, 8)
	value[1] = 0x01
	binary.BigEndian.PutUint16(value[2:4], uint16(12345)^uint16(stunMagicCookie>>16))
	ip := net.ParseIP("198.51.100.7").To4()
	cookie := make([]byte, 4)
	binary.BigEndian.PutUint32(cookie, stunMagicCookie)
	for i := range ip {
		value[4+i] = ip[i] ^ cookie[i]
	}

	msg := make([]byte, stunHeaderSize+4+len(value))
	binary.BigEndian.PutUint16(msg[0:2], bindingSuccessType)
	binary.BigEndian.PutUint16(msg[2:4], uint16(4+len(value)))
	binary.BigEndian.PutUint32(msg[4:8], stunMagicCookie)
	copy(msg[8:20], txID)
	offset := stunHeaderSize
	binary.BigEndian.PutUint16(msg[offset:offset+2], xorMappedAddrType)
	binary.BigEndian.PutUint16(msg[offset+2:offset+4], uint16(len(value)))
	copy(msg[offset+4:], value)

	got, err := parseMappedAddress(msg, txID)
	if err != nil {
		t.Fatalf("parseMappedAddress error: %v", err)
	}
	if got != "198.51.100.7:12345" {
		t.Fatalf("parseMappedAddress = %q, want %q", got, "198.51.100.7:12345")
	}
}
