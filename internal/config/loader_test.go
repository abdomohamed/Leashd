package config

import (
	"testing"
)

func TestParseValid(t *testing.T) {
	yaml := `
version: "1"
project:
  name: test-project
defaults:
  action: warn
  log: true
rules:
  - id: pypi
    domains: ["pypi.org"]
    ports: [443]
    action: allow
`
	cfg, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Project.Name != "test-project" {
		t.Errorf("expected project name 'test-project', got %q", cfg.Project.Name)
	}
	if len(cfg.Rules) != 1 {
		t.Errorf("expected 1 rule, got %d", len(cfg.Rules))
	}
}

func TestParseMissingVersion(t *testing.T) {
	yaml := `
project:
  name: test
defaults:
  action: warn
`
	_, err := Parse([]byte(yaml))
	if err == nil {
		t.Fatal("expected error for missing version, got nil")
	}
}

func TestParseInvalidAction(t *testing.T) {
	yaml := `
version: "1"
project:
  name: test
defaults:
  action: dance
`
	_, err := Parse([]byte(yaml))
	if err == nil {
		t.Fatal("expected error for invalid action, got nil")
	}
}

func TestParseInvalidCIDR(t *testing.T) {
	yaml := `
version: "1"
project:
  name: test
defaults:
  action: warn
rules:
  - id: bad
    cidrs: ["not-a-cidr"]
    action: allow
`
	_, err := Parse([]byte(yaml))
	if err == nil {
		t.Fatal("expected error for invalid CIDR, got nil")
	}
}

func TestParseBroadCIDRBlocked(t *testing.T) {
	yaml := `
version: "1"
project:
  name: test
defaults:
  action: warn
rules:
  - id: too-broad
    cidrs: ["0.0.0.0/4"]
    action: allow
`
	_, err := Parse([]byte(yaml))
	if err == nil {
		t.Fatal("expected error for CIDR prefix < 8, got nil")
	}
}

func TestParseValidCIDR(t *testing.T) {
	yaml := `
version: "1"
project:
  name: test
defaults:
  action: warn
rules:
  - id: internal
    cidrs: ["10.0.0.0/8"]
    action: allow
`
	_, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("unexpected error for valid CIDR: %v", err)
	}
}

func TestParseInvalidIP(t *testing.T) {
	yaml := `
version: "1"
project:
  name: test
defaults:
  action: warn
rules:
  - id: bad-ip
    ips: ["not.an.ip.addr"]
    action: allow
`
	_, err := Parse([]byte(yaml))
	if err == nil {
		t.Fatal("expected error for invalid IP, got nil")
	}
}

func TestParseTooManyRules(t *testing.T) {
	// Build a yaml with MaxRules+1 rules
	header := "version: \"1\"\nproject:\n  name: test\ndefaults:\n  action: warn\nrules:\n"
	ruleBlock := ""
	for i := 0; i <= MaxRules; i++ {
		ruleBlock += "  - id: rule" + string(rune('a'+i%26)) + "\n    domains: [\"example.com\"]\n    action: allow\n"
	}
	_, err := Parse([]byte(header + ruleBlock))
	if err == nil {
		t.Fatal("expected error for too many rules, got nil")
	}
}
