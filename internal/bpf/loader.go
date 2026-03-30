//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Wno-unused-value -Wno-pointer-sign -Wno-compare-distinct-pointer-types -target bpf -D__TARGET_ARCH_x86" Leashd ../../ebpf/leashd.c -- -I../../ebpf/headers

package bpf

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

// ConnectEvent mirrors the connect_event struct in ebpf/leashd.h.
type ConnectEvent struct {
	TimestampNS uint64
	PID         uint32
	TGID        uint32
	DstIP       uint32 // network byte order
	DstPort     uint16 // network byte order
	Protocol    uint8
	Verdict     uint8
	CgroupID    uint64
	Comm        [16]byte
	_           [6]byte // padding
}

// Loader manages the lifecycle of the leashd eBPF programs and maps.
type Loader struct {
	objs   *LeashdObjects
	links  []link.Link
	reader *ringbuf.Reader
	logger *slog.Logger
}

// Load compiles (via embedded object) and loads all eBPF programs and maps into
// the kernel.
func Load(logger *slog.Logger) (*Loader, error) {
	// Bump the kernel's locked memory limit so the BPF verifier can allocate maps.
	if err := setRlimitInfinity(); err != nil {
		logger.Warn("failed to set RLIMIT_MEMLOCK to infinity", "error", err)
	}

	objs := &LeashdObjects{}
	if err := LoadLeashdObjects(objs, nil); err != nil {
		var ve *ebpf.VerifierError
		if ok := isVerifierError(err, &ve); ok {
			return nil, fmt.Errorf("BPF verifier error:\n%s", ve)
		}
		return nil, fmt.Errorf("load eBPF objects: %w", err)
	}

	logger.Info("eBPF objects loaded",
		"maps", []string{"policy_map", "tracked_cgroups", "events"},
		"programs", []string{"kprobe_tcp_connect", "kprobe_udp_connect", "cgroup_skb_egress"},
	)

	l := &Loader{objs: objs, logger: logger}
	return l, nil
}

// AttachKprobes attaches the kprobe programs to tcp_v4_connect and
// ip4_datagram_connect. Returns a cleanup function.
func (l *Loader) AttachKprobes() error {
	tcpLink, err := link.Kprobe("tcp_v4_connect", l.objs.KprobeTcpConnect, nil)
	if err != nil {
		return fmt.Errorf("attach kprobe/tcp_v4_connect: %w", err)
	}
	l.links = append(l.links, tcpLink)
	l.logger.Info("kprobe attached", "function", "tcp_v4_connect")

	udpLink, err := link.Kprobe("ip4_datagram_connect", l.objs.KprobeUdpConnect, nil)
	if err != nil {
		// UDP kprobe is best-effort; log and continue.
		l.logger.Warn("attach kprobe/ip4_datagram_connect failed (UDP events won't be captured)", "error", err)
	} else {
		l.links = append(l.links, udpLink)
		l.logger.Info("kprobe attached", "function", "ip4_datagram_connect")
	}
	return nil
}

// AttachCgroup attaches the cgroup/skb egress filter to the cgroup at cgroupPath.
func (l *Loader) AttachCgroup(cgroupPath string) (link.Link, error) {
	cgroupFD, err := os.Open(cgroupPath)
	if err != nil {
		return nil, fmt.Errorf("open cgroup dir %s: %w", cgroupPath, err)
	}
	defer func() { _ = cgroupFD.Close() }()

	lnk, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupInetEgress,
		Program: l.objs.CgroupSkbEgress,
	})
	if err != nil {
		return nil, fmt.Errorf("attach cgroup/skb to %s: %w", cgroupPath, err)
	}
	l.logger.Info("cgroup/skb egress filter attached", "cgroup", cgroupPath)
	return lnk, nil
}

// NewRingBufReader returns a reader for the events ring buffer.
func (l *Loader) NewRingBufReader() (*ringbuf.Reader, error) {
	r, err := ringbuf.NewReader(l.objs.Events)
	if err != nil {
		return nil, fmt.Errorf("create ring buffer reader: %w", err)
	}
	return r, nil
}

// Maps returns the typed map wrappers.
func (l *Loader) Maps() *Maps {
	return &Maps{objs: l.objs, logger: l.logger}
}

// Close detaches all links and closes eBPF objects.
func (l *Loader) Close() {
	for _, lnk := range l.links {
		_ = lnk.Close()
	}
	if l.reader != nil {
		_ = l.reader.Close()
	}
	if l.objs != nil {
		_ = l.objs.Close()
	}
	l.logger.Info("eBPF programs and maps unloaded")
}
