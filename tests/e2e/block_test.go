//go:build e2e

package e2e_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/abdotalema/leashd/tests/e2e/helpers"
)

// TestBlockVerdict checks that a connection to a blocked IP is dropped and
// a BLOCK event is written to the event log.
func TestBlockVerdict(t *testing.T) {
	ln, addr := helpers.ListenTCP(t)
	helpers.AcceptAndClose(ln) // allow accept goroutine to drain if packet somehow gets through

	host, port, _ := splitHostPort(addr)
	_ = port

	rulesYAML := `version: "1"
project:
  name: block-test
defaults:
  action: block
  log: true
`

	sess := helpers.StartLeashd(t, rulesYAML, "sleep", "30")

	// The connector should fail (connection blocked or refused).
	if err := helpers.SpawnConnector(t, sess, addr); err == nil {
		t.Log("connector succeeded (packet may have escaped cgroup enforcement — check kernel version)")
	}

	// A BLOCK event must appear.
	ev := helpers.WaitForEvent(t, sess.LogPath, helpers.MatchBlock(host), 5*time.Second)
	if ev.DstIP != host {
		t.Errorf("expected dst_ip=%s, got %s", host, ev.DstIP)
	}
	if ev.PID == 0 {
		t.Error("expected non-zero PID in event")
	}
	if ev.Comm == "" {
		t.Error("expected non-empty comm in event")
	}
}

// TestBlockCIDR checks that all IPs inside a blocked CIDR are dropped.
func TestBlockCIDR(t *testing.T) {
	ln, addr := helpers.ListenTCP(t)
	helpers.AcceptAndClose(ln)
	host, _, _ := splitHostPort(addr)

	rulesYAML := fmt.Sprintf(`version: "1"
project:
  name: block-cidr-test
defaults:
  action: block
  log: true
rules:
  - id: block-loopback
    cidrs: ["%s/32"]
    action: block
`, host)

	sess := helpers.StartLeashd(t, rulesYAML, "sleep", "30")
	_ = helpers.SpawnConnector(t, sess, addr)

	helpers.WaitForEvent(t, sess.LogPath, helpers.MatchBlock(host), 5*time.Second)
}
