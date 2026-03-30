//go:build e2e

package e2e_test

import (
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/abdotalema/leashd/internal/ipc"
	"github.com/abdotalema/leashd/tests/e2e/helpers"
)

// TestIPCStatusQuery checks the basic status query via the UNIX socket.
func TestIPCStatusQuery(t *testing.T) {
	rulesYAML := `version: "1"
project:
  name: ipc-test
defaults:
  action: warn
  log: true
`
	sess := helpers.StartLeashd(t, rulesYAML, "sleep", "30")

	conn, err := net.DialTimeout("unix", sess.SockPath, 2*time.Second)
	if err != nil {
		t.Fatalf("connect to socket: %v", err)
	}
	defer conn.Close()

	req := ipc.Request{Cmd: ipc.CmdStatus}
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		t.Fatalf("send request: %v", err)
	}

	var resp ipc.StatusResponse
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if !resp.Active {
		t.Error("expected active=true in status response")
	}
	if resp.PolicyVersion < 0 {
		t.Errorf("unexpected policy version: %d", resp.PolicyVersion)
	}
}

// TestIPCEventStream checks that WARN events are delivered on the stream command.
func TestIPCEventStream(t *testing.T) {
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
	host, _, _ := splitHostPort(addr)

	rulesYAML := `version: "1"
project:
  name: ipc-stream-test
defaults:
  action: warn
  log: true
`
	sess := helpers.StartLeashd(t, rulesYAML, "sleep", "30")

	// Open a stream connection.
	streamConn, err := net.DialTimeout("unix", sess.SockPath, 2*time.Second)
	if err != nil {
		t.Fatalf("connect stream: %v", err)
	}
	defer streamConn.Close()

	req := ipc.Request{Cmd: ipc.CmdStream}
	if err := json.NewEncoder(streamConn).Encode(req); err != nil {
		t.Fatalf("send stream request: %v", err)
	}

	// Generate a connection event.
	_ = helpers.SpawnConnector(t, sess, addr)

	// Read events from stream until we see the expected one.
	done := make(chan bool, 1)
	go func() {
		dec := json.NewDecoder(streamConn)
		for {
			var ev helpers.Event
			if err := dec.Decode(&ev); err != nil {
				return
			}
			if ev.DstIP == host {
				done <- true
				return
			}
		}
	}()

	select {
	case <-done:
		// success
	case <-time.After(5 * time.Second):
		t.Fatal("did not receive event on stream within 5s")
	}
}

// TestIPCNoSession checks that leashd status exits non-zero when no daemon
// is running.
func TestIPCNoSession(t *testing.T) {
	dir := t.TempDir()
	_, _, err := helpers.RunLeashd(dir, "status")
	if err == nil {
		t.Fatal("expected non-zero exit when no session running")
	}
}
