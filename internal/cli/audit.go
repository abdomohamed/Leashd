package cli

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/abdotalema/leashd/internal/config"
	"github.com/spf13/cobra"
)

var (
	flagAuditLog            string
	flagAuditNonInteractive bool
	flagAuditApproveAll     bool
	flagAuditSince          time.Duration
)

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Review and action WARN/BLOCK events from the event log",
	Long: `leashd audit reads the event log produced by leashd run and lets you
review WARN and BLOCK events. You can promote connections to permanent rules
in rules.yaml without restarting leashd run (hot-reload picks up changes).`,
	RunE: runAudit,
}

func init() {
	auditCmd.Flags().StringVar(&flagAuditLog, "log", "", "Path to events.jsonl (default: .leashd/events.jsonl)")
	auditCmd.Flags().BoolVar(&flagAuditNonInteractive, "non-interactive", false, "Non-interactive mode (for scripts/tests)")
	auditCmd.Flags().BoolVar(&flagAuditApproveAll, "approve-all", false, "Approve all WARN events (requires --non-interactive)")
	auditCmd.Flags().DurationVar(&flagAuditSince, "since", 0, "Only show events within this duration (e.g. 1h, 30m)")
}

// auditEvent mirrors the JSON written by JSONLogSink.
type auditEvent struct {
	Timestamp   time.Time `json:"timestamp"`
	PID         uint32    `json:"pid"`
	Comm        string    `json:"comm"`
	DstIP       string    `json:"dst_ip"`
	DstPort     uint16    `json:"dst_port"`
	ReverseDNS  string    `json:"reverse_dns"`
	MatchedRule string    `json:"matched_rule"`
	Verdict     string    `json:"verdict"`
}

func runAudit(cmd *cobra.Command, args []string) error {
	dir, err := projectDir()
	if err != nil {
		return err
	}

	logPath := flagAuditLog
	if logPath == "" {
		logPath = filepath.Join(dir, ".leashd", "events.jsonl")
	}

	events, err := loadEvents(logPath, flagAuditSince)
	if err != nil {
		return fmt.Errorf("read event log %s: %w", logPath, err)
	}

	// Filter to only WARN and BLOCK events.
	var violations []auditEvent
	for _, e := range events {
		if e.Verdict == "warn" || e.Verdict == "block" {
			violations = append(violations, e)
		}
	}

	if len(violations) == 0 {
		fmt.Println("No violations found in event log.")
		return nil
	}

	fmt.Printf("Found %d violation(s):\n\n", len(violations))

	rulesPath := filepath.Join(dir, "rules.yaml")
	cfg, err := config.Load(rulesPath)
	if err != nil {
		return fmt.Errorf("load rules.yaml: %w", err)
	}

	if flagAuditNonInteractive && flagAuditApproveAll {
		return approveAll(violations, cfg, rulesPath)
	}

	// Interactive mode — TODO: implement bubbletea TUI in Phase 5.
	for i, v := range violations {
		host := v.ReverseDNS
		if host == "" {
			host = v.DstIP
		}
		fmt.Printf("[%d] %s (pid %d) → %s:%d [%s]\n",
			i+1, v.Comm, v.PID, host, v.DstPort, v.Verdict)
	}
	fmt.Println("\nInteractive TUI coming in Phase 5. Use --non-interactive --approve-all for now.")
	return nil
}

func approveAll(violations []auditEvent, cfg *config.Config, rulesPath string) error {
	added := 0
	for _, v := range violations {
		if v.Verdict != "warn" {
			continue
		}
		// Use reverse DNS hostname if available, otherwise fall back to exact IP.
		target := v.DstIP
		if v.ReverseDNS != "" {
			target = v.ReverseDNS
		}

		// Skip if already in rules.
		if ruleExists(cfg, target) {
			continue
		}

		ruleID := fmt.Sprintf("approved-%s", sanitizeID(target))
		cfg.Rules = append(cfg.Rules, config.Rule{
			ID:      ruleID,
			Comment: fmt.Sprintf("Auto-approved by leashd audit (comm=%s)", v.Comm),
			IPs:     []string{v.DstIP},
			Action:  config.ActionAllow,
		})
		added++
	}

	if added == 0 {
		fmt.Println("No new rules to add.")
		return nil
	}

	if err := writeRulesAtomic(cfg, rulesPath); err != nil {
		return fmt.Errorf("write rules.yaml: %w", err)
	}
	fmt.Printf("Added %d rule(s) to %s\n", added, rulesPath)
	return nil
}

func ruleExists(cfg *config.Config, target string) bool {
	for _, r := range cfg.Rules {
		for _, ip := range r.IPs {
			if ip == target {
				return true
			}
		}
		for _, d := range r.Domains {
			if d == target {
				return true
			}
		}
	}
	return false
}

func writeRulesAtomic(cfg *config.Config, path string) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	data := config.Scaffold(cfg.Project.Name, cfg.Rules)
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	_ = f.Close()
	return os.Rename(tmp, path)
}

func sanitizeID(s string) string {
	out := make([]byte, 0, len(s))
	for _, c := range []byte(s) {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' {
			out = append(out, c)
		} else {
			out = append(out, '-')
		}
	}
	return string(out)
}

func loadEvents(path string, since time.Duration) ([]auditEvent, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer func() { _ = f.Close() }()

	cutoff := time.Time{}
	if since > 0 {
		cutoff = time.Now().Add(-since)
	}

	var events []auditEvent
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var e auditEvent
		if err := json.Unmarshal(scanner.Bytes(), &e); err != nil {
			continue // skip malformed lines
		}
		if !cutoff.IsZero() && e.Timestamp.Before(cutoff) {
			continue
		}
		events = append(events, e)
	}
	return events, scanner.Err()
}
