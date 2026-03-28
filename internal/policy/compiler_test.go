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
	p, err := Compile(cfg, nil, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(p.Entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(p.Entries))
	}
	e := p.Entries[0]
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
	p, err := Compile(cfg, nil, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(p.Entries) != 1 {
		t.Fatalf("expected 1 entry for CIDR, got %d", len(p.Entries))
	}
	e := p.Entries[0]
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
	p, err := Compile(cfg, resolved, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(p.Entries) != 2 {
		t.Errorf("expected 2 entries for 2 resolved IPs, got %d", len(p.Entries))
	}
	for _, e := range p.Entries {
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
	p, err := Compile(cfg, nil, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.DefaultVerdict != VerdictBlock {
		t.Errorf("expected default BLOCK verdict, got %d", p.DefaultVerdict)
	}
}

func TestCompileEmptyRules(t *testing.T) {
	cfg := &config.Config{
		Version:  "1",
		Defaults: config.Defaults{Action: config.ActionWarn},
	}
	p, err := Compile(cfg, nil, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(p.Entries) != 0 {
		t.Errorf("expected 0 entries for empty rules, got %d", len(p.Entries))
	}
}
