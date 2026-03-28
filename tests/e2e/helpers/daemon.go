//go:build e2e

// Package helpers provides test utilities for leashd E2E tests.
package helpers

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/abdotalema/leashd/internal/ipc"
)

// LeashSession represents a running leashd session under test.
type LeashSession struct {
	// Dir is the temp project directory for this session.
	Dir string
	// LogPath is the path to .leashd/events.jsonl.
	LogPath string
	// SockPath is the UNIX socket path for IPC.
	SockPath string
	// RulesPath is the path to rules.yaml.
	RulesPath string
	// CgroupPath is the cgroupv2 directory leashd created for this session.
	// Populated via IPC status query after the daemon starts.
	CgroupPath string

	cmd *exec.Cmd
}

// StartLeashd writes rulesYAML to a temp directory, then starts
// `leashd run <wrappedCmd>` as a subprocess. It waits up to 3s for the
// IPC socket to appear before returning.
func StartLeashd(t *testing.T, rulesYAML string, wrappedCmd ...string) *LeashSession {
	t.Helper()

	dir := t.TempDir()

	rulesPath := filepath.Join(dir, "rules.yaml")
	if err := os.WriteFile(rulesPath, []byte(rulesYAML), 0644); err != nil {
		t.Fatalf("write rules.yaml: %v", err)
	}

	leashd := LeashdBinary()

	sockPath, err := ipc.ProjectSocketPath(dir)
	if err != nil {
		t.Fatalf("derive socket path: %v", err)
	}

	logDir := filepath.Join(dir, ".leashd")
	if err := os.MkdirAll(logDir, 0700); err != nil {
		t.Fatalf("create .leashd dir: %v", err)
	}
	logPath := filepath.Join(logDir, "events.jsonl")

	args := []string{"run", "--dir", dir}
	args = append(args, wrappedCmd...)

	cmd := exec.Command(leashd, args...)
	cmd.Dir = dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		t.Fatalf("start leashd: %v", err)
	}

	sess := &LeashSession{
		Dir:       dir,
		LogPath:   logPath,
		SockPath:  sockPath,
		RulesPath: rulesPath,
		cmd:       cmd,
	}

	// Wait for the socket to appear.
	if err := WaitForSocket(sockPath, 5*time.Second); err != nil {
		_ = cmd.Process.Kill()
		t.Fatalf("leashd did not create socket: %v", err)
	}

	// Query the daemon for its cgroup path so SpawnConnector can place
	// the connector process inside the managed cgroup.
	if status, err := querySessionStatus(sockPath); err == nil {
		sess.CgroupPath = status.CgroupPath
	}

	t.Cleanup(func() { sess.Stop(t) })

	return sess
}

// Stop sends SIGTERM to leashd and waits for it to exit.
func (s *LeashSession) Stop(t *testing.T) {
	t.Helper()
	if s.cmd == nil || s.cmd.Process == nil {
		return
	}
	_ = s.cmd.Process.Signal(os.Interrupt)
	done := make(chan error, 1)
	go func() { done <- s.cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		_ = s.cmd.Process.Kill()
	}
	// Assert socket was cleaned up.
	if _, err := os.Stat(s.SockPath); err == nil {
		t.Logf("warning: socket %s still exists after leashd exit", s.SockPath)
	}
}

// UpdateRules atomically overwrites the session's rules.yaml.
func (s *LeashSession) UpdateRules(t *testing.T, rulesYAML string) {
	t.Helper()
	tmp := s.RulesPath + ".tmp"
	if err := os.WriteFile(tmp, []byte(rulesYAML), 0644); err != nil {
		t.Fatalf("write temp rules: %v", err)
	}
	if err := os.Rename(tmp, s.RulesPath); err != nil {
		t.Fatalf("rename rules: %v", err)
	}
}

// WaitForSocket waits until the given UNIX socket path is connectable.
func WaitForSocket(path string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("unix", path, 200*time.Millisecond)
		if err == nil {
			conn.Close()
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("socket %s did not appear within %s", path, timeout)
}

// WaitForSocketPath returns the expected socket path for the given directory
// without waiting for it to exist.
func WaitForSocketPath(dir string) (string, error) {
	return ipc.ProjectSocketPath(dir)
}

// LeashdBinary returns the path to the leashd binary to use in tests.
// Resolution order: $LEASHD_BIN env var → PATH → repo root bin/leashd.
func LeashdBinary() string {
	if v := os.Getenv("LEASHD_BIN"); v != "" {
		return v
	}
	if p, err := exec.LookPath("leashd"); err == nil {
		return p
	}
	// go test sets cwd to the package dir; walk up to repo root.
	dir, _ := os.Getwd()
	for {
		candidate := filepath.Join(dir, "bin", "leashd")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "leashd" // last resort — will fail with a clear error
}

// querySessionStatus dials the IPC socket and returns the daemon status.
func querySessionStatus(sockPath string) (*ipc.StatusResponse, error) {
	conn, err := net.DialTimeout("unix", sockPath, 2*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if err := json.NewEncoder(conn).Encode(ipc.Request{Cmd: ipc.CmdStatus}); err != nil {
		return nil, err
	}
	var resp ipc.StatusResponse
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// RunLeashd runs a one-shot leashd command (not run, e.g. "status") in the
// given project directory and returns stdout, stderr, and the exit error.
func RunLeashd(dir string, args ...string) (string, string, error) {
	binary := LeashdBinary()
	fullArgs := append([]string{"--dir", dir}, args...)
	cmd := exec.Command(binary, fullArgs...)
	cmd.Dir = dir
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}
