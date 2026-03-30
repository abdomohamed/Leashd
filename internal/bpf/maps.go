package bpf

import (
	"encoding/binary"
	"fmt"
	"log/slog"
	"unsafe"
)

// Maps provides typed access to the BPF maps managed by the Loader.
type Maps struct {
	objs   *LeashdObjects
	logger *slog.Logger
}

// LPMKey is the key type for the policy_map LPM trie.
// Must match struct { __u32 prefixlen; __u32 ip; } in leashd.h.
type LPMKey struct {
	PrefixLen uint32
	IP        uint32 // network byte order
}

// PolicyVal is the value type for policy_map.
type PolicyVal struct {
	Verdict uint8
	Pad     [3]uint8
}

// SetPolicy inserts or updates a policy entry in the BPF policy map.
// ip is a uint32 in network byte order (as produced by the policy compiler).
func (m *Maps) SetPolicy(prefixLen uint32, ip uint32, verdict uint8) error {
	key := LPMKey{PrefixLen: prefixLen, IP: ip}
	val := PolicyVal{Verdict: verdict}
	if err := m.objs.PolicyMap.Put(unsafe.Pointer(&key), unsafe.Pointer(&val)); err != nil {
		return fmt.Errorf("set policy map entry: %w", err)
	}
	m.logger.Debug("policy map updated",
		"prefix_len", prefixLen,
		"ip", uint32ToIP(ip),
		"verdict", verdict,
	)
	return nil
}

// DeletePolicy removes a policy entry from the BPF policy map.
func (m *Maps) DeletePolicy(prefixLen uint32, ip uint32) error {
	key := LPMKey{PrefixLen: prefixLen, IP: ip}
	if err := m.objs.PolicyMap.Delete(unsafe.Pointer(&key)); err != nil {
		return fmt.Errorf("delete policy map entry: %w", err)
	}
	return nil
}

// AddTrackedCgroup registers a cgroup ID so the eBPF kprobe monitors it.
func (m *Maps) AddTrackedCgroup(cgroupID uint64) error {
	val := uint8(1)
	if err := m.objs.TrackedCgroups.Put(&cgroupID, &val); err != nil {
		return fmt.Errorf("add tracked cgroup %d: %w", cgroupID, err)
	}
	m.logger.Info("cgroup registered in BPF map", "cgroup_id", cgroupID)
	return nil
}

// RemoveTrackedCgroup unregisters a cgroup ID.
func (m *Maps) RemoveTrackedCgroup(cgroupID uint64) error {
	if err := m.objs.TrackedCgroups.Delete(&cgroupID); err != nil {
		return fmt.Errorf("remove tracked cgroup %d: %w", cgroupID, err)
	}
	m.logger.Info("cgroup unregistered from BPF map", "cgroup_id", cgroupID)
	return nil
}

func uint32ToIP(n uint32) string {
	// n is LittleEndian-encoded: LSB of uint32 = first network octet.
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, n)
	return fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3])
}
