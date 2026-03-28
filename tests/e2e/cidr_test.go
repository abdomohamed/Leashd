//go:build e2e

package e2e_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/abdotalema/leashd/tests/e2e/helpers"
)

// TestCIDRAllowInside checks that an IP inside an allowed CIDR is not blocked.
func TestCIDRAllowInside(t *testing.T) {
	ln, addr := helpers.ListenTCP(t)
	helpers.AcceptAndClose(ln)
	host, port, _ := splitHostPort(addr)

	rulesYAML := fmt.Sprintf(`version: "1"
project:
  name: cidr-allow-inside
defaults:
  action: block
  log: true
rules:
  - id: allow-loopback
    cidrs: ["127.0.0.0/8"]
    ports: [%s]
    action: allow
`, port)

	sess := helpers.StartLeashd(t, rulesYAML, "sleep", "30")

	if err := helpers.SpawnConnector(t, sess, addr); err != nil {
		t.Fatalf("connector failed for IP inside allowed CIDR: %v", err)
	}

	helpers.AssertNoEvent(t, sess.LogPath, helpers.MatchBlock(host), 2*time.Second)
}

// TestCIDRBlockOutside checks that an IP outside the allowed CIDR is blocked.
func TestCIDRBlockOutside(t *testing.T) {
	// Use a routable IP that won't actually connect (we only care about the verdict).
	target := "203.0.113.1" // TEST-NET-3, should not route

	rulesYAML := `version: "1"
project:
  name: cidr-block-outside
defaults:
  action: block
  log: true
rules:
  - id: allow-loopback
    cidrs: ["127.0.0.0/8"]
    action: allow
`

	sess := helpers.StartLeashd(t, rulesYAML, "sleep", "30")

	// Attempt connection to a non-loopback IP — expect block.
	_ = helpers.SpawnConnector(t, sess, fmt.Sprintf("%s:443", target))

	helpers.WaitForEvent(t, sess.LogPath, helpers.MatchBlock(target), 5*time.Second)
}
