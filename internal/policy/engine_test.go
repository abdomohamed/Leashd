package policy

import (
	"encoding/binary"
	"log/slog"
	"net"
	"testing"

	"github.com/abdotalema/leashd/internal/config"
)

func makePolicy(defaultAction string, entries []LPMEntry) *CompiledPolicy {
	v, _ := actionToVerdict(defaultAction)
	return &CompiledPolicy{
		DefaultVerdict: v,
		Entries:        entries,
		Version:        1,
	}
}

func TestVerdictAllowExactIP(t *testing.T) {
	pol := makePolicy(config.ActionWarn, []LPMEntry{
		{PrefixLen: 32, IP: ipToUint32("1.2.3.4"), Verdict: VerdictAllow, RuleID: "r1"},
	})
	cfg := &config.Config{Version: "1", Defaults: config.Defaults{Action: config.ActionWarn}}
	e := NewEngine(cfg, pol, nil, slog.Default())

	v, ruleID, _ := e.Verdict(net.ParseIP("1.2.3.4"))
	if v != VerdictAllow {
		t.Errorf("expected ALLOW, got %d", v)
	}
	if ruleID != "r1" {
		t.Errorf("expected rule 'r1', got %q", ruleID)
	}
}

func TestVerdictDefaultForUnknown(t *testing.T) {
	pol := makePolicy(config.ActionBlock, nil)
	cfg := &config.Config{Version: "1", Defaults: config.Defaults{Action: config.ActionBlock}}
	e := NewEngine(cfg, pol, nil, slog.Default())

	v, _, _ := e.Verdict(net.ParseIP("9.9.9.9"))
	if v != VerdictBlock {
		t.Errorf("expected BLOCK default, got %d", v)
	}
}

func TestVerdictCIDR(t *testing.T) {
	// 10.0.0.0/8
	pol := makePolicy(config.ActionBlock, []LPMEntry{
		{PrefixLen: 8, IP: ipToUint32("10.0.0.0"), Verdict: VerdictAllow, RuleID: "internal"},
	})
	cfg := &config.Config{Version: "1", Defaults: config.Defaults{Action: config.ActionBlock}}
	e := NewEngine(cfg, pol, nil, slog.Default())

	// IP inside CIDR
	v, _, _ := e.Verdict(net.ParseIP("10.50.1.2"))
	if v != VerdictAllow {
		t.Errorf("expected ALLOW for IP inside CIDR, got %d", v)
	}

	// IP outside CIDR
	v, _, _ = e.Verdict(net.ParseIP("11.0.0.1"))
	if v != VerdictBlock {
		t.Errorf("expected BLOCK for IP outside CIDR, got %d", v)
	}
}

func TestVerdictBlockOverridesDefault(t *testing.T) {
	pol := makePolicy(config.ActionWarn, []LPMEntry{
		{PrefixLen: 32, IP: ipToUint32("5.5.5.5"), Verdict: VerdictBlock, RuleID: "blocklist"},
	})
	cfg := &config.Config{Version: "1", Defaults: config.Defaults{Action: config.ActionWarn}}
	e := NewEngine(cfg, pol, nil, slog.Default())

	v, _, _ := e.Verdict(net.ParseIP("5.5.5.5"))
	if v != VerdictBlock {
		t.Errorf("expected explicit BLOCK to override default WARN, got %d", v)
	}
}

func TestUpdatePolicy(t *testing.T) {
	pol1 := makePolicy(config.ActionWarn, nil)
	cfg := &config.Config{Version: "1", Defaults: config.Defaults{Action: config.ActionWarn}}
	e := NewEngine(cfg, pol1, nil, slog.Default())

	v, _, _ := e.Verdict(net.ParseIP("1.1.1.1"))
	if v != VerdictWarn {
		t.Errorf("expected WARN before update, got %d", v)
	}

	pol2 := makePolicy(config.ActionBlock, nil)
	cfg2 := &config.Config{Version: "1", Defaults: config.Defaults{Action: config.ActionBlock}}
	e.UpdatePolicy(cfg2, pol2)

	v, _, _ = e.Verdict(net.ParseIP("1.1.1.1"))
	if v != VerdictBlock {
		t.Errorf("expected BLOCK after policy update, got %d", v)
	}
}

func ipToUint32(s string) uint32 {
	// Must match ipToLPMEntry encoding: LittleEndian uint32 so memory = network bytes.
	return binary.LittleEndian.Uint32(net.ParseIP(s).To4())
}
