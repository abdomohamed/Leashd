//go:build e2e

package helpers

import (
	"fmt"
	"net"
	"os/exec"
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

// SpawnConnector runs the connector binary inside the session's cgroup
// (by virtue of it being a child of the leashd-managed process) and
// returns the connection error (nil = success).
func SpawnConnector(t *testing.T, sess *LeashSession, addr string) error {
	t.Helper()
	connBin := ConnectorBinary(t)
	cmd := exec.Command(connBin, "--addr", addr, "--timeout", "3s")
	cmd.Dir = sess.Dir
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
func ConnectorBinary(t *testing.T) string {
	t.Helper()
	p := "tests/e2e/helpers/connector/connector"
	if _, err := exec.LookPath(p); err == nil {
		return p
	}
	// Try abs path via go build output.
	out, err := exec.Command("go", "build", "-o", "/tmp/leashd-connector",
		"./tests/e2e/helpers/connector/").CombinedOutput()
	if err != nil {
		t.Fatalf("build connector: %v\n%s", err, out)
	}
	return "/tmp/leashd-connector"
}
