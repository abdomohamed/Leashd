//go:build e2e

package e2e_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/abdotalema/leashd/tests/e2e/helpers"
)

// TestAllowVerdict checks that a connection to an explicitly-allowed IP
// succeeds and no BLOCK/WARN event is written.
func TestAllowVerdict(t *testing.T) {
	ln, addr := helpers.ListenTCP(t)
	accepted := helpers.AcceptAndClose(ln)

	// Parse the listen IP:port for the allow rule.
	host, port, _ := splitHostPort(addr)

	rulesYAML := fmt.Sprintf(`version: "1"
project:
  name: allow-test
defaults:
  action: block
  log: true
rules:
  - id: allow-local
    cidrs: ["%s/32"]
    ports: [%s]
    action: allow
`, host, port)

	sess := helpers.StartLeashd(t, rulesYAML, "sleep", "30")

	if err := helpers.SpawnConnector(t, sess, addr); err != nil {
		t.Fatalf("connector failed (expected success): %v", err)
	}

	// The listener should have accepted the connection.
	select {
	case err := <-accepted:
		if err != nil {
			t.Fatalf("listener accept error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("listener did not accept connection within 2s")
	}

	// No BLOCK or WARN events should appear.
	helpers.AssertNoEvent(t, sess.LogPath, func(e helpers.Event) bool {
		return (e.IsBlock() || e.IsWarn()) && e.DstIP == host
	}, 2*time.Second)
}
