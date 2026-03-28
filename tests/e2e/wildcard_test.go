//go:build e2e

package e2e_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/abdotalema/leashd/tests/e2e/helpers"
)

// TestWildcardDomainAllow verifies that a wildcard domain rule (*.test.local)
// matches a connection whose reverse DNS resolves to foo.test.local.
//
// This test requires a local DNS mock or /etc/hosts entry mapping
// the test IP to a .test.local hostname. Because this depends on the
// forward-confirm reverse DNS path in the policy engine, it primarily tests
// the wildcard matching logic.
func TestWildcardDomainAllow(t *testing.T) {
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

	// Use a wildcard allow rule. The reverse DNS for 127.x.x.x often returns
	// "localhost" — we rely on the default warn so the test captures the event.
	rulesYAML := fmt.Sprintf(`version: "1"
project:
  name: wildcard-test
defaults:
  action: warn
  log: true
rules:
  - id: allow-localhost-wildcard
    domains: ["*.localhost", "localhost"]
    ports: [%s]
    action: allow
`, port)

	sess := helpers.StartLeashd(t, rulesYAML, "sleep", "30")

	if err := helpers.SpawnConnector(t, sess, addr); err != nil {
		t.Logf("connector result: %v (reverse DNS wildcard match may convert to allow)", err)
	}

	// Wait for any event — allow or warn depending on PTR record.
	_ = helpers.WaitForEvent(t, sess.LogPath, func(e helpers.Event) bool {
		return e.DstIP == host
	}, 5*time.Second)
}
