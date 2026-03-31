package policy

import (
	"net"
	"testing"

	"github.com/abdotalema/leashd/internal/config"
)

func TestCompileExactIP(t *testing.T) {
	cfg := &config.Config{
		Version:  "1",
		Defaults: config.Defaults{Action: config.ActionWarn},
		Rules: []config.Rule{
			{ID: "r1", IPs: []string{"1.2.3.4"}, Action: config.ActionAllow},
		},
	}
	p, err := Compile(cfg, nil, nil, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// +2 for the two catch-all default entries (0.0.0.0/1 + 128.0.0.0/1).
	if len(p.Entries) != 3 {
		t.Fatalf("expected 3 entries (1 rule + 2 catch-all), got %d", len(p.Entries))
	}
	// First two entries are the catch-all defaults.
	if p.Entries[0].PrefixLen != 1 || p.Entries[1].PrefixLen != 1 {
		t.Errorf("expected catch-all prefixlen 1, got %d and %d", p.Entries[0].PrefixLen, p.Entries[1].PrefixLen)
	}
	// Third entry is the explicit IP rule.
	e := p.Entries[2]
	if e.PrefixLen != 32 {
		t.Errorf("expected prefixlen 32 for exact IP, got %d", e.PrefixLen)
	}
	if e.Verdict != VerdictAllow {
		t.Errorf("expected ALLOW verdict, got %d", e.Verdict)
	}
}

func TestCompileCIDR(t *testing.T) {
	cfg := &config.Config{
		Version:  "1",
		Defaults: config.Defaults{Action: config.ActionBlock},
		Rules: []config.Rule{
			{ID: "internal", CIDRs: []string{"10.0.0.0/8"}, Action: config.ActionAllow},
		},
	}
	p, err := Compile(cfg, nil, nil, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(p.Entries) != 3 {
		t.Fatalf("expected 3 entries (1 CIDR + 2 catch-all), got %d", len(p.Entries))
	}
	e := p.Entries[2] // skip catch-all pair at indices 0-1
	if e.PrefixLen != 8 {
		t.Errorf("expected prefixlen 8 for /8 CIDR, got %d", e.PrefixLen)
	}
}

func TestCompileResolvedDomain(t *testing.T) {
	cfg := &config.Config{
		Version:  "1",
		Defaults: config.Defaults{Action: config.ActionWarn},
		Rules: []config.Rule{
			{ID: "pypi", Domains: []string{"pypi.org"}, Action: config.ActionAllow},
		},
	}
	resolved := map[string][]net.IP{
		"pypi.org": {net.ParseIP("151.101.1.63"), net.ParseIP("151.101.65.63")},
	}
	p, err := Compile(cfg, resolved, nil, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(p.Entries) != 4 {
		t.Errorf("expected 4 entries (2 resolved IPs + 2 catch-all), got %d", len(p.Entries))
	}
	// Skip catch-all pair at indices 0-1; verify the domain entries.
	for _, e := range p.Entries[2:] {
		if e.Verdict != VerdictAllow {
			t.Errorf("expected ALLOW verdict for pypi.org IP, got %d", e.Verdict)
		}
	}
}

func TestCompileDefaultVerdict(t *testing.T) {
	cfg := &config.Config{
		Version:  "1",
		Defaults: config.Defaults{Action: config.ActionBlock},
	}
	p, err := Compile(cfg, nil, nil, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.DefaultVerdict != VerdictBlock {
		t.Errorf("expected default BLOCK verdict, got %d", p.DefaultVerdict)
	}
	// The two catch-all entries (0.0.0.0/1 + 128.0.0.0/1) must carry the same verdict.
	if len(p.Entries) < 2 {
		t.Fatal("expected at least the 2 catch-all entries")
	}
	for i, catchAll := range p.Entries[:2] {
		if catchAll.PrefixLen != 1 {
			t.Errorf("catch-all[%d] prefixLen = %d, want 1", i, catchAll.PrefixLen)
		}
		if catchAll.Verdict != VerdictBlock {
			t.Errorf("catch-all[%d] verdict = %d, want BLOCK (%d)", i, catchAll.Verdict, VerdictBlock)
		}
		if catchAll.RuleID != "_default" {
			t.Errorf("catch-all[%d] ruleID = %q, want _default", i, catchAll.RuleID)
		}
	}
}

func TestCompileEmptyRules(t *testing.T) {
	cfg := &config.Config{
		Version:  "1",
		Defaults: config.Defaults{Action: config.ActionWarn},
	}
	p, err := Compile(cfg, nil, nil, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Even with no rules, the two catch-all default entries are always present.
	if len(p.Entries) != 2 {
		t.Errorf("expected 2 entries (catch-all pair only), got %d", len(p.Entries))
	}
	for i, e := range p.Entries {
		if e.PrefixLen != 1 || e.Verdict != VerdictWarn {
			t.Errorf("catch-all[%d] mismatch: prefixLen=%d verdict=%d", i, e.PrefixLen, e.Verdict)
		}
	}
}

func TestCompileDNSServerIPs(t *testing.T) {
	cfg := &config.Config{
		Version:  "1",
		Defaults: config.Defaults{Action: config.ActionBlock},
	}
	dnsIPs := []net.IP{net.ParseIP("192.168.65.7").To4()}
	p, err := Compile(cfg, nil, dnsIPs, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// 2 catch-all + 1 DNS allow = 3 entries.
	if len(p.Entries) != 3 {
		t.Fatalf("expected 3 entries (2 catch-all + 1 DNS), got %d", len(p.Entries))
	}
	dnsEntry := p.Entries[2]
	if dnsEntry.PrefixLen != 32 {
		t.Errorf("DNS entry prefixLen = %d, want 32", dnsEntry.PrefixLen)
	}
	if dnsEntry.Verdict != VerdictAllow {
		t.Errorf("DNS entry verdict = %d, want ALLOW (%d)", dnsEntry.Verdict, VerdictAllow)
	}
	if dnsEntry.RuleID != "_dns-allow" {
		t.Errorf("DNS entry ruleID = %q, want _dns-allow", dnsEntry.RuleID)
	}
}
