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
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, n)
	return fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3])
}

func uint32ToNetIP(n uint32) net.IP {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, n)
	return net.IP(b)
}

func networkToHostPort(port uint16) uint16 {
	b := [2]byte{byte(port >> 8), byte(port)}
	return binary.BigEndian.Uint16(b[:])
}
