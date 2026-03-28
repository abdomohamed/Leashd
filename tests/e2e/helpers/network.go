//go:build e2e

package helpers

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
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
// It uses SysProcAttr.CgroupFD to place the process at fork time, mirroring
// how leashd itself places the wrapped child into the cgroup.
func SpawnConnector(t *testing.T, sess *LeashSession, addr string) error {
	t.Helper()
	connBin := ConnectorBinary(t)
	cmd := exec.Command(connBin, "--addr", addr, "--timeout", "3s")
	cmd.Dir = sess.Dir

	if sess.CgroupPath != "" {
		cgroupFD, err := os.Open(sess.CgroupPath)
		if err == nil {
			defer cgroupFD.Close()
			cmd.SysProcAttr = &syscall.SysProcAttr{
				CgroupFD:    int(cgroupFD.Fd()),
				UseCgroupFD: true,
			}
		}
	}

	out, err := cmd.CombinedOutput()
	t.Logf("connector output: %s", out)
	return err
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
