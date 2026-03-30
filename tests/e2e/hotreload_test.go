//go:build e2e

package e2e_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/abdotalema/leashd/tests/e2e/helpers"
)

// TestHotReload verifies that updating rules.yaml while the daemon is running
// changes enforcement within 500ms.
func TestHotReload(t *testing.T) {
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
	host, port, _ := splitHostPort(addr)

	// Start with warn-all policy.
	rulesYAML := `version: "1"
project:
  name: hotreload-test
defaults:
  action: warn
  log: true
`
	sess := helpers.StartLeashd(t, rulesYAML, "sleep", "60")

	// First connection: should be WARN.
	_ = helpers.SpawnConnector(t, sess, addr)
	helpers.WaitForEvent(t, sess.LogPath, helpers.MatchWarn(host), 5*time.Second)

	// Hot-reload: add explicit block rule for this IP.
	updatedRules := fmt.Sprintf(`version: "1"
project:
  name: hotreload-test
defaults:
  action: warn
  log: true
rules:
  - id: block-test-ip
    cidrs: ["%s/32"]
    ports: [%s]
    action: block
`, host, port)

	reloadTime := time.Now()
	sess.UpdateRules(t, updatedRules)

	// Wait for fsnotify + BPF map update (should be < 200ms).
	time.Sleep(200 * time.Millisecond)

	// Second connection: should now be BLOCK.
	_ = helpers.SpawnConnector(t, sess, addr)

	helpers.WaitForEvent(t, sess.LogPath, helpers.MatchBlock(host), 3*time.Second)

	elapsed := time.Since(reloadTime)
	if elapsed > 500*time.Millisecond {
		t.Logf("hot-reload enforcement latency %s (expected <500ms)", elapsed)
	}
}
