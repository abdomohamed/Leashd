package daemon

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"

	"github.com/abdotalema/leashd/internal/bpf"
)

func parseEvent(raw []byte, evt *bpf.ConnectEvent) error {
	if len(raw) < 56 {
		return fmt.Errorf("event too short: %d bytes", len(raw))
	}
	r := bytes.NewReader(raw)
	return binary.Read(r, binary.NativeEndian, evt)
}

func commString(comm [16]byte) string {
	n := bytes.IndexByte(comm[:], 0)
	if n < 0 {
		n = 16
	}
	return string(comm[:n])
}

func uint32ToIPStr(n uint32) string {
	// n is a host-endian (little-endian on x86) copy of a network-byte-order
	// (big-endian) uint32 read via bpf_probe_read_user.
	// LittleEndian decomposition restores the original network-order bytes,
	// which are the canonical IPv4 octets [a, b, c, d].
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, n)
	return fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3])
}

func uint32ToNetIP(n uint32) net.IP {
	// Same byte-order reasoning as uint32ToIPStr.
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, n)
	return net.IP(b)
}

func networkToHostPort(port uint16) uint16 {
	// port was read from sin_port (network/big-endian) into a host-endian uint16.
	// Swap bytes to convert back to host byte order (ntohs equivalent).
	return (port >> 8) | (port << 8)
}
