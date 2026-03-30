//go:build e2e

package e2e_test

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/abdotalema/leashd/tests/e2e/helpers"
)

// TestAuditApproveAll runs a full audit workflow:
// 1. Generate WARN events for a target IP
// 2. Run leashd audit --non-interactive --approve-all
// 3. Verify rules.yaml contains an allow rule for that IP
func TestAuditApproveAll(t *testing.T) {
	ln, addr := helpers.ListenTCP(t)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
	host, _, _ := splitHostPort(addr)

	rulesYAML := `version: "1"
project:
  name: audit-test
defaults:
  action: warn
  log: true
`
	sess := helpers.StartLeashd(t, rulesYAML, "sleep", "30")

	// Generate a WARN event.
	_ = helpers.SpawnConnector(t, sess, addr)
	helpers.WaitForEvent(t, sess.LogPath, helpers.MatchWarn(host), 5*time.Second)

	// Run audit in non-interactive approve-all mode.
	_, stderr, err := helpers.RunLeashd(sess.Dir, "audit", "--non-interactive", "--approve-all")
	if err != nil {
		t.Fatalf("leashd audit failed: %v\n%s", err, stderr)
	}

	// Verify rules.yaml now contains an allow entry for the target IP.
	rulesData, err := os.ReadFile(sess.RulesPath)
	if err != nil {
		t.Fatalf("read rules.yaml: %v", err)
	}
	if !strings.Contains(string(rulesData), host) {
		t.Errorf("rules.yaml does not contain allow rule for %s after audit\n%s", host, rulesData)
	}
}
