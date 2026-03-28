package config

import (
	"fmt"
	"net"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	ActionAllow = "allow"
	ActionWarn  = "warn"
	ActionBlock = "block"

	MaxRules          = 1000
	MaxDomainsPerRule = 50
	MinCIDRPrefix     = 8
)

var validActions = map[string]bool{
	ActionAllow: true,
	ActionWarn:  true,
	ActionBlock: true,
}

// Load reads and validates a rules.yaml file at the given path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read rules file: %w", err)
	}
	return Parse(data)
}

// Parse parses and validates rules.yaml content from raw bytes.
func Parse(data []byte) (*Config, error) {
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse yaml: %w", err)
	}
	if err := validate(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func validate(cfg *Config) error {
	if cfg.Version == "" {
		return fmt.Errorf("rules.yaml: missing required field 'version'")
	}
	if cfg.Version != "1" {
		return fmt.Errorf("rules.yaml: unsupported version %q (expected \"1\")", cfg.Version)
	}
	if !validActions[cfg.Defaults.Action] {
		return fmt.Errorf("rules.yaml: defaults.action %q is invalid (must be allow, warn, or block)", cfg.Defaults.Action)
	}
	if len(cfg.Rules) > MaxRules {
		return fmt.Errorf("rules.yaml: too many rules (%d > %d)", len(cfg.Rules), MaxRules)
	}
	for i, r := range cfg.Rules {
		if err := validateRule(i, r); err != nil {
			return err
		}
	}
	return nil
}

func validateRule(idx int, r Rule) error {
	label := fmt.Sprintf("rules[%d]", idx)
	if r.ID == "" {
		return fmt.Errorf("rules.yaml: %s missing required field 'id'", label)
	}
	if !validActions[r.Action] {
		return fmt.Errorf("rules.yaml: %s (id=%q) action %q is invalid", label, r.ID, r.Action)
	}
	if len(r.Domains) > MaxDomainsPerRule {
		return fmt.Errorf("rules.yaml: %s (id=%q) too many domains (%d > %d)", label, r.ID, len(r.Domains), MaxDomainsPerRule)
	}
	for _, cidr := range r.CIDRs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return fmt.Errorf("rules.yaml: %s (id=%q) invalid CIDR %q: %w", label, r.ID, cidr, err)
		}
		ones, _ := ipNet.Mask.Size()
		if ones < MinCIDRPrefix {
			return fmt.Errorf("rules.yaml: %s (id=%q) CIDR %q prefix too broad (/%d < /%d)", label, r.ID, cidr, ones, MinCIDRPrefix)
		}
		// Block /0 or /1 allow rules to prevent bypassing all enforcement.
		if r.Action == ActionAllow && ones < MinCIDRPrefix {
			return fmt.Errorf("rules.yaml: %s (id=%q) allow rule with broad CIDR /%d is not permitted", label, r.ID, ones)
		}
	}
	for _, ip := range r.IPs {
		if net.ParseIP(ip) == nil {
			return fmt.Errorf("rules.yaml: %s (id=%q) invalid IP %q", label, r.ID, ip)
		}
	}
	return nil
}

// DefaultLogPath returns the default path for the event log relative to projectDir.
func DefaultLogPath(projectDir string) string {
	return projectDir + "/.leashd/events.jsonl"
}

// DefaultDebugLogPath returns the default path for the debug log relative to projectDir.
func DefaultDebugLogPath(projectDir string) string {
	return projectDir + "/.leashd/debug.log"
}

// Scaffold returns a minimal valid rules.yaml as a byte slice, with optional
// pre-populated rules for detected dependencies.
func Scaffold(projectName string, extraRules []Rule) []byte {
	lines := []string{
		"version: \"1\"",
		"",
		"project:",
		"  name: " + yamlQuote(projectName),
		"",
		"defaults:",
		"  action: warn   # warn | block | allow — verdict for unlisted destinations",
		"  log: true",
		"",
		"rules:",
	}
	if len(extraRules) == 0 {
		lines = append(lines, "  # Add rules here. Example:")
		lines = append(lines, "  # - id: pypi")
		lines = append(lines, "  #   domains: [\"pypi.org\", \"files.pythonhosted.org\"]")
		lines = append(lines, "  #   ports: [443, 80]")
		lines = append(lines, "  #   action: allow")
	} else {
		for _, r := range extraRules {
			lines = append(lines, "  - id: "+r.ID)
			if r.Comment != "" {
				lines = append(lines, "    comment: "+yamlQuote(r.Comment))
			}
			if len(r.Domains) > 0 {
				lines = append(lines, "    domains: "+yamlStringSlice(r.Domains))
			}
			if len(r.Ports) > 0 {
				lines = append(lines, "    ports: "+yamlUint16Slice(r.Ports))
			}
			lines = append(lines, "    action: "+r.Action)
		}
	}
	lines = append(lines, "",
		"notifications:",
		"  terminal: true",
		"  json_log: .leashd/events.jsonl",
	)
	return []byte(strings.Join(lines, "\n") + "\n")
}

func yamlQuote(s string) string {
	if strings.ContainsAny(s, ": #{}[]|>&*!,'\"") {
		return fmt.Sprintf("%q", s)
	}
	return s
}

func yamlStringSlice(ss []string) string {
	quoted := make([]string, len(ss))
	for i, s := range ss {
		quoted[i] = fmt.Sprintf("%q", s)
	}
	return "[" + strings.Join(quoted, ", ") + "]"
}

func yamlUint16Slice(ports []uint16) string {
	parts := make([]string, len(ports))
	for i, p := range ports {
		parts[i] = fmt.Sprintf("%d", p)
	}
	return "[" + strings.Join(parts, ", ") + "]"
}
