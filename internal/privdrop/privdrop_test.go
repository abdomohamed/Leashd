package privdrop

import (
	"os"
	"os/user"
	"runtime"
	"strconv"
	"syscall"
	"testing"
)

func TestResolve_ExplicitUser(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux only")
	}

	// Look up the current user so we have a known-valid username.
	u, err := user.Current()
	if err != nil {
		t.Fatalf("user.Current: %v", err)
	}

	result, err := Resolve(u.Username)
	if err != nil {
		t.Fatalf("Resolve(%q): %v", u.Username, err)
	}
	if result == nil {
		t.Fatal("expected non-nil result for explicit user")
	}

	wantUID, _ := strconv.ParseUint(u.Uid, 10, 32)
	wantGID, _ := strconv.ParseUint(u.Gid, 10, 32)

	if result.UID != uint32(wantUID) {
		t.Errorf("UID = %d, want %d", result.UID, wantUID)
	}
	if result.GID != uint32(wantGID) {
		t.Errorf("GID = %d, want %d", result.GID, wantGID)
	}
	if result.Username != u.Username {
		t.Errorf("Username = %q, want %q", result.Username, u.Username)
	}
	if result.Credential == nil {
		t.Fatal("Credential is nil")
	}
	if result.Credential.Uid != uint32(wantUID) {
		t.Errorf("Credential.Uid = %d, want %d", result.Credential.Uid, wantUID)
	}
	if len(result.Credential.Groups) == 0 {
		t.Error("expected at least one supplementary group")
	}
}

func TestResolve_InvalidUser(t *testing.T) {
	_, err := Resolve("nonexistent_user_12345")
	if err == nil {
		t.Fatal("expected error for invalid user")
	}
}

func TestResolve_SudoUID(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux only")
	}

	u, err := user.Current()
	if err != nil {
		t.Fatalf("user.Current: %v", err)
	}

	// Simulate sudo environment.
	t.Setenv("SUDO_UID", u.Uid)
	t.Setenv("SUDO_GID", u.Gid)
	t.Setenv("SUDO_USER", u.Username)

	// Skip if current user is root (UID 0 is intentionally skipped).
	if u.Uid == "0" {
		result, err := Resolve("")
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if result != nil {
			t.Fatal("expected nil result when SUDO_UID is 0")
		}
		return
	}

	result, err := Resolve("")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}

	wantUID, _ := strconv.ParseUint(u.Uid, 10, 32)
	if result.UID != uint32(wantUID) {
		t.Errorf("UID = %d, want %d", result.UID, wantUID)
	}
	if result.Username != u.Username {
		t.Errorf("Username = %q, want %q", result.Username, u.Username)
	}
}

func TestResolve_NoSudo(t *testing.T) {
	// Ensure SUDO_UID is not set.
	t.Setenv("SUDO_UID", "")
	os.Unsetenv("SUDO_UID")

	result, err := Resolve("")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if result != nil {
		t.Fatal("expected nil result when no sudo context")
	}
}

func TestResolve_SudoUIDZero(t *testing.T) {
	t.Setenv("SUDO_UID", "0")
	t.Setenv("SUDO_GID", "0")

	result, err := Resolve("")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if result != nil {
		t.Fatal("expected nil result when SUDO_UID is 0 (root→root)")
	}
}

func TestResolve_SudoUIDInvalid(t *testing.T) {
	t.Setenv("SUDO_UID", "notanumber")

	_, err := Resolve("")
	if err == nil {
		t.Fatal("expected error for invalid SUDO_UID")
	}
}

func TestResult_Env(t *testing.T) {
	r := &Result{
		Credential: &syscall.Credential{Uid: 1000, Gid: 1000},
		UID:        1000,
		GID:        1000,
		Username:   "testuser",
		HomeDir:    "/home/testuser",
	}

	base := []string{
		"PATH=/usr/bin:/bin",
		"HOME=/root",
		"USER=root",
		"LOGNAME=root",
		"TERM=xterm",
	}

	got := r.Env(base)

	env := make(map[string]string)
	for _, e := range got {
		k := envKey(e)
		env[k] = e[len(k)+1:]
	}

	if env["HOME"] != "/home/testuser" {
		t.Errorf("HOME = %q, want /home/testuser", env["HOME"])
	}
	if env["USER"] != "testuser" {
		t.Errorf("USER = %q, want testuser", env["USER"])
	}
	if env["LOGNAME"] != "testuser" {
		t.Errorf("LOGNAME = %q, want testuser", env["LOGNAME"])
	}
	if env["PATH"] != "/usr/bin:/bin" {
		t.Errorf("PATH = %q, want /usr/bin:/bin", env["PATH"])
	}
	if env["TERM"] != "xterm" {
		t.Errorf("TERM = %q, want xterm", env["TERM"])
	}
}

func TestResult_Env_PreservesUnrelated(t *testing.T) {
	r := &Result{
		Username: "u",
		HomeDir:  "/home/u",
	}

	base := []string{"FOO=bar", "BAZ=qux"}
	got := r.Env(base)

	// Should contain FOO, BAZ, HOME, USER, LOGNAME
	if len(got) != 5 {
		t.Errorf("len(env) = %d, want 5; got %v", len(got), got)
	}
}
