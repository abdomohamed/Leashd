//go:build e2e

package helpers

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"
)

// ConnectTCP attempts a TCP connection to addr and returns nil on success.
func ConnectTCP(addr string) error {
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return err
	}
	conn.Close()
	return nil
}

// SpawnConnector runs the connector binary inside the leashd-managed cgroup
// so that BPF kprobe and cgroup/skb enforcement applies to the connection.
//
// Uses SysProcAttr.CgroupFD for atomic placement at fork time (Linux 5.7+).
// Also writes the PID to cgroup.procs immediately after start as belt-and-suspenders.
// If CgroupFD placement fails, falls back to cgroup.procs only.
func SpawnConnector(t *testing.T, sess *LeashSession, addr string) error {
	t.Helper()
	connBin := ConnectorBinary(t)

	run := func(withCgroupFD bool) error {
		cmd := exec.Command(connBin, "--addr", addr, "--timeout", "3s")
		cmd.Dir = sess.Dir
		var outBuf bytes.Buffer
		cmd.Stdout = &outBuf
		cmd.Stderr = &outBuf

		if withCgroupFD && sess.CgroupPath != "" {
			cgroupFD, err := os.Open(sess.CgroupPath)
			if err != nil {
				t.Logf("open cgroup dir %s: %v", sess.CgroupPath, err)
			} else {
				cmd.SysProcAttr = &syscall.SysProcAttr{
					CgroupFD:    int(cgroupFD.Fd()),
					UseCgroupFD: true,
				}
				if err := cmd.Start(); err != nil {
					_ = cgroupFD.Close()
					t.Logf("connector start with CgroupFD failed: %v — will retry without", err)
					return err
				}
				_ = cgroupFD.Close()
				// Belt-and-suspenders: also write PID to cgroup.procs.
				writeCgroupProcs(t, sess.CgroupPath, cmd.Process.Pid)
				err := cmd.Wait()
				t.Logf("connector (CgroupFD) pid=%d output: %s", cmd.Process.Pid, outBuf.String())
				return err
			}
		}

		// cgroup.procs approach: start first, then move into cgroup.
		if err := cmd.Start(); err != nil {
			t.Logf("connector start failed: %v", err)
			return err
		}
		writeCgroupProcs(t, sess.CgroupPath, cmd.Process.Pid)
		err := cmd.Wait()
		t.Logf("connector (cgroup.procs) pid=%d output: %s", cmd.Process.Pid, outBuf.String())
		return err
	}

	if err := run(true); err != nil {
		// Only retry if cmd.Start() itself failed (e.g. kernel doesn't support
		// UseCgroupFD). If the connector process ran but exited non-zero (connection
		// refused/blocked by policy), that is the real verdict — don't re-run outside
		// the cgroup, which would bypass BPF enforcement.
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return err
		}
		t.Logf("CgroupFD start failed (%v) — retrying with cgroup.procs only", err)
		return run(false)
	}
	return nil
}

func writeCgroupProcs(t *testing.T, cgroupPath string, pid int) {
	t.Helper()
	if cgroupPath == "" {
		t.Logf("warning: CgroupPath empty — connector pid=%d outside cgroup, BPF events won't fire", pid)
		return
	}
	procsPath := filepath.Join(cgroupPath, "cgroup.procs")
	if err := os.WriteFile(procsPath, []byte(strconv.Itoa(pid)+"\n"), 0); err != nil {
		t.Logf("warning: write cgroup.procs %s: %v — BPF events may not fire", procsPath, err)
	} else {
		t.Logf("connector pid=%d placed in cgroup %s", pid, cgroupPath)
	}
}

// ListenTCP starts a TCP listener on a free port on localhost and returns
// the listener and the address string. The listener is closed when t ends.
func ListenTCP(t *testing.T) (net.Listener, string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen TCP: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	return ln, ln.Addr().String()
}

// AcceptAndClose accepts a single connection from ln and closes it immediately.
// Runs in a goroutine — the returned channel receives nil when accepted or
// an error if ln is closed before a connection arrives.
func AcceptAndClose(ln net.Listener) <-chan error {
	ch := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			ch <- err
			return
		}
		conn.Close()
		ch <- nil
	}()
	return ch
}

// ListenAddr returns a random localhost:port that is not yet in use.
func ListenAddr() string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(fmt.Sprintf("find free port: %v", err))
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

// ConnectorBinary returns the path to the connector test binary.
// Resolution order: $CONNECTOR_BIN env var → repo root relative path.
func ConnectorBinary(t *testing.T) string {
	t.Helper()
	if v := os.Getenv("CONNECTOR_BIN"); v != "" {
		return v
	}
	// go test sets cwd to the package dir; walk up to find the built connector.
	dir, _ := os.Getwd()
	for {
		candidate := filepath.Join(dir, "tests", "e2e", "helpers", "connector", "connector")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatalf("connector binary not found (run 'make testbin' first, or set CONNECTOR_BIN)")
	return ""
}
