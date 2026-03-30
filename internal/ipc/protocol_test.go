package ipc

import (
	"encoding/json"
	"testing"
)

func TestRequestRoundTrip(t *testing.T) {
	for _, cmd := range []string{CmdStatus, CmdStream, "unknown"} {
		req := Request{Cmd: cmd}
		data, err := json.Marshal(req)
		if err != nil {
			t.Fatalf("marshal Request{Cmd:%q}: %v", cmd, err)
		}
		var got Request
		if err := json.Unmarshal(data, &got); err != nil {
			t.Fatalf("unmarshal Request: %v", err)
		}
		if got.Cmd != cmd {
			t.Errorf("round-trip: expected cmd %q, got %q", cmd, got.Cmd)
		}
	}
}

func TestStatusResponseRoundTrip(t *testing.T) {
	resp := StatusResponse{
		Active:        true,
		PolicyVersion: 3,
		EventsPerSec:  42.5,
		TotalEvents:   100,
		Violations:    5,
		CgroupID:      12345,
		CgroupPath:    "/sys/fs/cgroup/leashd/myproject",
	}
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got StatusResponse
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got != resp {
		t.Errorf("round-trip mismatch:\n  got  %+v\n  want %+v", got, resp)
	}
}

func TestErrorResponseRoundTrip(t *testing.T) {
	resp := ErrorResponse{Error: "something went wrong"}
	data, _ := json.Marshal(resp)
	var got ErrorResponse
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Error != resp.Error {
		t.Errorf("expected %q, got %q", resp.Error, got.Error)
	}
}

func TestSocketPathDeterministic(t *testing.T) {
	p1, err := ProjectSocketPath("/home/user/myproject")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	p2, err := ProjectSocketPath("/home/user/myproject")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p1 != p2 {
		t.Errorf("socket path not deterministic: %q vs %q", p1, p2)
	}
}

func TestSocketPathDiffers(t *testing.T) {
	p1, _ := ProjectSocketPath("/home/user/project-a")
	p2, _ := ProjectSocketPath("/home/user/project-b")
	if p1 == p2 {
		t.Error("different directories should produce different socket paths")
	}
}
