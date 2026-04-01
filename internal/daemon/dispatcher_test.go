package daemon

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/abdotalema/leashd/internal/config"
	"github.com/abdotalema/leashd/internal/policy"
)

func testEvent(verdict uint8) EnrichedEvent {
	var evt EnrichedEvent
	copy(evt.Comm[:], "curl")
	evt.DstIPStr = "93.184.216.34"
	evt.ReverseDNS = "example.com"
	evt.MatchedRule = "test-rule"
	evt.FinalVerdict = verdict
	evt.Timestamp = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	evt.PolicyVer = 1
	evt.CgroupPath = "/sys/fs/cgroup/leashd-test"
	return evt
}

func TestJSONLogSink_WritesEventToDisk(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, ".leashd", "events.jsonl")

	notif := config.Notifications{
		Terminal: false,
		JSONLog:  logPath,
	}
	disp, err := NewDispatcher(notif, dir, -1, -1, testLogger(t))
	if err != nil {
		t.Fatalf("NewDispatcher: %v", err)
	}

	evt := testEvent(policy.VerdictWarn)
	disp.Dispatch(context.Background(), evt)
	disp.Close()

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read event log: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("event log is empty — event was not written to disk")
	}

	var entry logEvent
	if err := json.Unmarshal(data, &entry); err != nil {
		t.Fatalf("unmarshal event: %v", err)
	}

	if entry.Verdict != "warn" {
		t.Errorf("verdict = %q, want %q", entry.Verdict, "warn")
	}
	if entry.DstIP != "93.184.216.34" {
		t.Errorf("dst_ip = %q, want %q", entry.DstIP, "93.184.216.34")
	}
	if entry.Comm != "curl" {
		t.Errorf("comm = %q, want %q", entry.Comm, "curl")
	}
	if entry.ReverseDNS != "example.com" {
		t.Errorf("reverse_dns = %q, want %q", entry.ReverseDNS, "example.com")
	}
	if entry.MatchedRule != "test-rule" {
		t.Errorf("matched_rule = %q, want %q", entry.MatchedRule, "test-rule")
	}
	if entry.Meta.CgroupPath != "/sys/fs/cgroup/leashd-test" {
		t.Errorf("cgroup_path = %q, want %q", entry.Meta.CgroupPath, "/sys/fs/cgroup/leashd-test")
	}
	if entry.Meta.PolicyVersion != 1 {
		t.Errorf("policy_version = %d, want 1", entry.Meta.PolicyVersion)
	}
}

func TestJSONLogSink_DefaultLogPath(t *testing.T) {
	dir := t.TempDir()

	notif := config.Notifications{
		Terminal: false,
		JSONLog:  "", // empty → should use default
	}
	disp, err := NewDispatcher(notif, dir, -1, -1, testLogger(t))
	if err != nil {
		t.Fatalf("NewDispatcher: %v", err)
	}

	evt := testEvent(policy.VerdictBlock)
	disp.Dispatch(context.Background(), evt)
	disp.Close()

	defaultPath := filepath.Join(dir, ".leashd", "events.jsonl")
	data, err := os.ReadFile(defaultPath)
	if err != nil {
		t.Fatalf("read default event log: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("default event log is empty — event was not written to disk")
	}

	var entry logEvent
	if err := json.Unmarshal(data, &entry); err != nil {
		t.Fatalf("unmarshal event: %v", err)
	}
	if entry.Verdict != "block" {
		t.Errorf("verdict = %q, want %q", entry.Verdict, "block")
	}
}

func TestJSONLogSink_MultipleEvents(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, ".leashd", "events.jsonl")

	notif := config.Notifications{JSONLog: logPath}
	disp, err := NewDispatcher(notif, dir, -1, -1, testLogger(t))
	if err != nil {
		t.Fatalf("NewDispatcher: %v", err)
	}

	ctx := context.Background()
	disp.Dispatch(ctx, testEvent(policy.VerdictAllow))
	disp.Dispatch(ctx, testEvent(policy.VerdictWarn))
	disp.Dispatch(ctx, testEvent(policy.VerdictBlock))
	disp.Close()

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read event log: %v", err)
	}

	lines := splitJSONL(data)
	if len(lines) != 3 {
		t.Fatalf("expected 3 JSONL lines, got %d\nraw:\n%s", len(lines), string(data))
	}

	verdicts := []string{"allow", "warn", "block"}
	for i, line := range lines {
		var entry logEvent
		if err := json.Unmarshal(line, &entry); err != nil {
			t.Fatalf("line %d: unmarshal: %v", i, err)
		}
		if entry.Verdict != verdicts[i] {
			t.Errorf("line %d: verdict = %q, want %q", i, entry.Verdict, verdicts[i])
		}
	}
}

func TestJSONLogSink_CreatesDirectoryIfMissing(t *testing.T) {
	dir := t.TempDir()
	nested := filepath.Join(dir, "deep", "nested", ".leashd", "events.jsonl")

	notif := config.Notifications{JSONLog: nested}
	disp, err := NewDispatcher(notif, dir, -1, -1, testLogger(t))
	if err != nil {
		t.Fatalf("NewDispatcher: %v", err)
	}

	disp.Dispatch(context.Background(), testEvent(policy.VerdictAllow))
	disp.Close()

	if _, err := os.Stat(nested); err != nil {
		t.Fatalf("expected file at %s: %v", nested, err)
	}
}

func TestJSONLogSink_EngineOverrideField(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "events.jsonl")

	notif := config.Notifications{JSONLog: logPath}
	disp, err := NewDispatcher(notif, dir, -1, -1, testLogger(t))
	if err != nil {
		t.Fatalf("NewDispatcher: %v", err)
	}

	evt := testEvent(policy.VerdictBlock)
	evt.Verdict = policy.VerdictAllow
	evt.FinalVerdict = policy.VerdictBlock
	disp.Dispatch(context.Background(), evt)
	disp.Close()

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var entry logEvent
	if err := json.Unmarshal(data, &entry); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !entry.Meta.EngineOverride {
		t.Error("expected engine_override=true when kernel and engine verdicts differ")
	}
	if entry.Meta.KernelVerdict != "allow" {
		t.Errorf("kernel_verdict = %q, want %q", entry.Meta.KernelVerdict, "allow")
	}
}

func TestJSONLogSink_FileOwnedByInvokingUser(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, ".leashd", "events.jsonl")

	currentUID := os.Getuid()
	currentGID := os.Getgid()

	notif := config.Notifications{JSONLog: logPath}
	disp, err := NewDispatcher(notif, dir, currentUID, currentGID, testLogger(t))
	if err != nil {
		t.Fatalf("NewDispatcher: %v", err)
	}

	disp.Dispatch(context.Background(), testEvent(policy.VerdictWarn))
	disp.Close()

	// Verify the log file is owned by the specified UID/GID.
	info, err := os.Stat(logPath)
	if err != nil {
		t.Fatalf("stat log file: %v", err)
	}
	stat := info.Sys().(*syscall.Stat_t)
	if int(stat.Uid) != currentUID {
		t.Errorf("log file UID = %d, want %d", stat.Uid, currentUID)
	}
	if int(stat.Gid) != currentGID {
		t.Errorf("log file GID = %d, want %d", stat.Gid, currentGID)
	}

	// Verify the log directory is also owned by the specified UID/GID.
	dirInfo, err := os.Stat(filepath.Dir(logPath))
	if err != nil {
		t.Fatalf("stat log dir: %v", err)
	}
	dirStat := dirInfo.Sys().(*syscall.Stat_t)
	if int(dirStat.Uid) != currentUID {
		t.Errorf("log dir UID = %d, want %d", dirStat.Uid, currentUID)
	}
	if int(dirStat.Gid) != currentGID {
		t.Errorf("log dir GID = %d, want %d", dirStat.Gid, currentGID)
	}
}

func TestJSONLogSink_NoChownWhenNegativeUID(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, ".leashd", "events.jsonl")

	// -1, -1 means no chown — file should still be created and writable.
	notif := config.Notifications{JSONLog: logPath}
	disp, err := NewDispatcher(notif, dir, -1, -1, testLogger(t))
	if err != nil {
		t.Fatalf("NewDispatcher: %v", err)
	}

	disp.Dispatch(context.Background(), testEvent(policy.VerdictAllow))
	disp.Close()

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("event log is empty")
	}
}

// splitJSONL splits JSONL content into individual JSON objects, ignoring empty lines.
func splitJSONL(data []byte) [][]byte {
	var lines [][]byte
	for _, line := range splitBytes(data, '\n') {
		if len(line) > 0 {
			lines = append(lines, line)
		}
	}
	return lines
}

func splitBytes(data []byte, sep byte) [][]byte {
	var result [][]byte
	start := 0
	for i, b := range data {
		if b == sep {
			result = append(result, data[start:i])
			start = i + 1
		}
	}
	if start < len(data) {
		result = append(result, data[start:])
	}
	return result
}

func testLogger(t *testing.T) *slog.Logger {
	t.Helper()
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
}
