//go:build e2e

package helpers

import (
	"bufio"
	"encoding/json"
	"os"
	"testing"
	"time"
)

// Event mirrors the JSON structure written to .leashd/events.jsonl.
type Event struct {
	Timestamp  string `json:"timestamp"`
	PID        uint32 `json:"pid"`
	Comm       string `json:"comm"`
	DstIP      string `json:"dst_ip"`
	DstPort    uint16 `json:"dst_port"`
	ReverseDNS string `json:"reverse_dns"`
	MatchedRule string `json:"matched_rule"`
	Verdict    string `json:"verdict"`

	Meta struct {
		CgroupID      uint64 `json:"cgroup_id"`
		CgroupPath    string `json:"cgroup_path"`
		KernelVerdict string `json:"kernel_verdict"`
		EngineOverride bool  `json:"engine_override"`
		PolicyVersion  int   `json:"policy_version"`
	} `json:"_meta"`
}

// IsAllow returns true if the event has an ALLOW verdict.
func (e Event) IsAllow() bool { return e.Verdict == "allow" }

// IsWarn returns true if the event has a WARN verdict.
func (e Event) IsWarn() bool { return e.Verdict == "warn" }

// IsBlock returns true if the event has a BLOCK verdict.
func (e Event) IsBlock() bool { return e.Verdict == "block" }

// WaitForEvent polls logPath until an event matching match appears or timeout.
// It fails the test if no matching event appears within the timeout.
func WaitForEvent(t *testing.T, logPath string, match func(Event) bool, timeout time.Duration) Event {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		events := ReadEvents(t, logPath)
		for _, ev := range events {
			if match(ev) {
				return ev
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	// Dump whatever IS in the log to help diagnose.
	if events := ReadEvents(t, logPath); len(events) > 0 {
		t.Logf("events.jsonl has %d event(s) but none matched; last events:", len(events))
		for i, ev := range events {
			t.Logf("  [%d] verdict=%s dst_ip=%s pid=%d comm=%s", i, ev.Verdict, ev.DstIP, ev.PID, ev.Comm)
		}
	} else {
		t.Logf("events.jsonl is empty (no events received from BPF ring buffer)")
	}
	t.Fatalf("no matching event appeared in %s within %s", logPath, timeout)
	return Event{}
}

// AssertNoEvent asserts that no matching event appears in logPath within window.
func AssertNoEvent(t *testing.T, logPath string, match func(Event) bool, window time.Duration) {
	t.Helper()
	deadline := time.Now().Add(window)
	for time.Now().Before(deadline) {
		events := ReadEvents(t, logPath)
		for _, ev := range events {
			if match(ev) {
				t.Errorf("unexpected matching event found: %+v", ev)
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// ReadEvents reads all events from logPath. Returns empty slice if file
// doesn't exist yet.
func ReadEvents(t *testing.T, logPath string) []Event {
	t.Helper()
	f, err := os.Open(logPath)
	if err != nil {
		return nil
	}
	defer f.Close()

	var events []Event
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var ev Event
		if err := json.Unmarshal(line, &ev); err == nil {
			events = append(events, ev)
		}
	}
	return events
}

// MatchDstIP returns a matcher that matches events for the given destination IP.
func MatchDstIP(ip string) func(Event) bool {
	return func(e Event) bool { return e.DstIP == ip }
}

// MatchBlock returns a matcher for BLOCK events to the given IP.
func MatchBlock(ip string) func(Event) bool {
	return func(e Event) bool { return e.IsBlock() && e.DstIP == ip }
}

// MatchWarn returns a matcher for WARN events to the given IP.
func MatchWarn(ip string) func(Event) bool {
	return func(e Event) bool { return e.IsWarn() && e.DstIP == ip }
}

// MatchAllow returns a matcher for ALLOW events to the given IP.
func MatchAllow(ip string) func(Event) bool {
	return func(e Event) bool { return e.IsAllow() && e.DstIP == ip }
}
