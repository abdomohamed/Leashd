//go:build e2e

package e2e_test

import (
	"os"
	"testing"
	"time"

	"github.com/abdotalema/leashd/tests/e2e/helpers"
)

// TestSocketCleanup verifies the UNIX socket is removed when leashd exits.
func TestSocketCleanup(t *testing.T) {
	rulesYAML := `version: "1"
project:
  name: lifecycle-test
defaults:
  action: warn
  log: true
`
	sess := helpers.StartLeashd(t, rulesYAML, "sleep", "1")

	sockPath := sess.SockPath

	// Wait for leashd to exit on its own (sleep 1 child exits).
	time.Sleep(3 * time.Second)

	if _, err := os.Stat(sockPath); err == nil {
		t.Errorf("socket %s still exists after leashd exit", sockPath)
	}
}

// TestStaleSocketRecovery verifies that leashd removes a stale socket and
// creates a new one.
func TestStaleSocketRecovery(t *testing.T) {
	dir := t.TempDir()

	sockPath, err := helpers.WaitForSocketPath(dir)
	if err != nil {
		t.Fatalf("derive socket path: %v", err)
	}

	// Create a stale socket file.
	f, err := os.Create(sockPath)
	if err != nil {
		t.Fatalf("create stale socket: %v", err)
	}
	f.Close()

	rulesYAML := `version: "1"
project:
  name: stale-socket-test
defaults:
  action: warn
  log: true
`
	// StartLeashd should succeed despite the stale socket.
	sess := helpers.StartLeashdInDir(t, dir, rulesYAML, "sleep", "30")
	if sess.SockPath != sockPath {
		t.Errorf("expected socket path %s, got %s", sockPath, sess.SockPath)
	}
}

// TestCgroupCleanup verifies that the cgroup is removed when leashd exits.
func TestCgroupCleanup(t *testing.T) {
	rulesYAML := `version: "1"
project:
  name: cgroup-cleanup-test
defaults:
  action: warn
  log: true
`
	sess := helpers.StartLeashd(t, rulesYAML, "sleep", "1")

	// Give leashd time to record its cgroup path.
	time.Sleep(500 * time.Millisecond)
	events := helpers.ReadEvents(t, sess.LogPath)
	var cgroupPath string
	for _, ev := range events {
		if ev.Meta.CgroupPath != "" {
			cgroupPath = ev.Meta.CgroupPath
			break
		}
	}

	// Wait for leashd to exit.
	time.Sleep(3 * time.Second)

	if cgroupPath != "" {
		if _, err := os.Stat(cgroupPath); err == nil {
			t.Errorf("cgroup %s still exists after leashd exit", cgroupPath)
		}
	}
}
