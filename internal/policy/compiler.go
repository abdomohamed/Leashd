package policy

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/abdotalema/leashd/internal/config"
)

// Verdict values mirror the BPF VERDICT_* constants in ebpf/leashd.h.
const (
	VerdictAllow uint8 = 0
	VerdictWarn  uint8 = 1
	VerdictBlock uint8 = 2
)

// LPMEntry represents a single entry to be inserted into the BPF LPM trie.
type LPMEntry struct {
	PrefixLen uint32
	IP        uint32 // network byte order
	Verdict   uint8
	RuleID    string
}

// CompiledPolicy is the result of compiling a config.Config into BPF map entries.
type CompiledPolicy struct {
	Entries        []LPMEntry
	DefaultVerdict uint8
	Version        int
}

// Compile translates a config.Config (with pre-resolved IPs for domains) into
// a list of LPMEntry values ready to be loaded into the kernel BPF policy map.
//
// resolvedIPs maps domain name → []net.IP (from the DNS resolver).
func Compile(cfg *config.Config, resolvedIPs map[string][]net.IP, version int) (*CompiledPolicy, error) {
	defaultVerdict, err := actionToVerdict(cfg.Defaults.Action)
	if err != nil {
		return nil, fmt.Errorf("defaults.action: %w", err)
	}

	policy := &CompiledPolicy{
		DefaultVerdict: defaultVerdict,
		Version:        version,
	}

	for _, rule := range cfg.Rules {
		verdict, err := actionToVerdict(rule.Action)
		if err != nil {
			return nil, fmt.Errorf("rule %q: %w", rule.ID, err)
		}

		// Exact IPs
		for _, ipStr := range rule.IPs {
			ip := net.ParseIP(ipStr)
			if ip == nil {
				return nil, fmt.Errorf("rule %q: invalid IP %q", rule.ID, ipStr)
			}
			entry, err := ipToLPMEntry(ip, 32, verdict, rule.ID)
			if err != nil {
				return nil, err
			}
			policy.Entries = append(policy.Entries, entry)
		}

		// CIDRs
		for _, cidrStr := range rule.CIDRs {
			_, ipNet, err := net.ParseCIDR(cidrStr)
			if err != nil {
				return nil, fmt.Errorf("rule %q: invalid CIDR %q: %w", rule.ID, cidrStr, err)
			}
			ones, _ := ipNet.Mask.Size()
			entry, err := ipToLPMEntry(ipNet.IP, ones, verdict, rule.ID)
			if err != nil {
				return nil, err
			}
			policy.Entries = append(policy.Entries, entry)
		}

		// Domains → resolved IPs
		for _, domain := range rule.Domains {
			if ips, ok := resolvedIPs[domain]; ok {
				for _, ip := range ips {
					entry, err := ipToLPMEntry(ip, 32, verdict, rule.ID)
					if err != nil {
						return nil, err
					}
					policy.Entries = append(policy.Entries, entry)
				}
			}
			// Wildcard domains and unresolved domains are handled at runtime
			// by the policy engine via reverse DNS.
		}
	}

	return policy, nil
}

func ipToLPMEntry(ip net.IP, prefixLen int, verdict uint8, ruleID string) (LPMEntry, error) {
	v4 := ip.To4()
	if v4 == nil {
		return LPMEntry{}, fmt.Errorf("only IPv4 is supported (got %s)", ip)
	}
	// Store the IP as a LittleEndian uint32 so its in-memory byte layout on
	// x86-64 matches network byte order (e.g. 127.0.0.1 → value 0x0100007f,
	// memory bytes [7f,00,00,01]).  The BPF LPM trie matches from the
	// lowest-address byte of the key's IP field, which must be the most-
	// significant network octet for prefix matching to be correct.
	return LPMEntry{
		PrefixLen: uint32(prefixLen),
		IP:        binary.LittleEndian.Uint32(v4),
		Verdict:   verdict,
		RuleID:    ruleID,
	}, nil
}

func actionToVerdict(action string) (uint8, error) {
	switch action {
	case config.ActionAllow:
		return VerdictAllow, nil
	case config.ActionWarn:
		return VerdictWarn, nil
	case config.ActionBlock:
		return VerdictBlock, nil
	default:
		return 0, fmt.Errorf("unknown action %q", action)
	}
}
