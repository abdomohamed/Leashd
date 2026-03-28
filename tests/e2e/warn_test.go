//go:build e2e

package e2e_test

import (
	"testing"
	"time"

	"github.com/abdotalema/leashd/tests/e2e/helpers"
)

// TestWarnVerdict checks that a connection to an unknown IP is allowed through
// but a WARN event is recorded.
func TestWarnVerdict(t *testing.T) {
	ln, addr := helpers.ListenTCP(t)
	helpers.AcceptAndClose(ln)
	host, _, _ := splitHostPort(addr)

	rulesYAML := `version: "1"
project:
  name: warn-test
defaults:
  action: warn
  log: true
`

	sess := helpers.StartLeashd(t, rulesYAML, "sleep", "30")

	if err := helpers.SpawnConnector(t, sess, addr); err != nil {
		t.Logf("connector failed (non-fatal for warn test): %v", err)
	}

	ev := helpers.WaitForEvent(t, sess.LogPath, helpers.MatchWarn(host), 5*time.Second)
	if ev.Verdict != "warn" {
		t.Errorf("expected warn verdict, got %s", ev.Verdict)
	}
}
