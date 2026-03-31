// Package privdrop resolves credentials for dropping privileges before
// exec'ing a child process. It supports explicit --user lookup and
// auto-detection from SUDO_UID/SUDO_GID environment variables.
package privdrop

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
	"syscall"
)

// Result holds the resolved credentials and environment overrides
// needed to drop the child process to a non-root user.
type Result struct {
	Credential *syscall.Credential
	UID        uint32
	GID        uint32
	Username   string
	HomeDir    string
}

// Env returns environment variable overrides so the child sees
// HOME, USER, and LOGNAME matching its actual UID.
func (r *Result) Env(base []string) []string {
	overrides := map[string]string{
		"HOME":    r.HomeDir,
		"USER":    r.Username,
		"LOGNAME": r.Username,
	}
	out := make([]string, 0, len(base)+len(overrides))
	for _, e := range base {
		key := envKey(e)
		if _, ok := overrides[key]; ok {
			continue // will be replaced
		}
		out = append(out, e)
	}
	for k, v := range overrides {
		out = append(out, k+"="+v)
	}
	return out
}

func envKey(entry string) string {
	for i := 0; i < len(entry); i++ {
		if entry[i] == '=' {
			return entry[:i]
		}
	}
	return entry
}

// Resolve determines which credentials to use for the child process.
//
// Priority:
//  1. Explicit username (--user flag) → look up in /etc/passwd
//  2. SUDO_UID / SUDO_GID from environment → auto-detect invoking user
//  3. Neither available → return nil (no privilege drop)
//
// Returns nil with no error when privilege dropping should be skipped.
func Resolve(username string) (*Result, error) {
	if username != "" {
		return resolveByName(username)
	}
	return resolveFromSudo()
}

func resolveByName(username string) (*Result, error) {
	u, err := user.Lookup(username)
	if err != nil {
		return nil, fmt.Errorf("look up user %q: %w", username, err)
	}
	return resultFromUser(u)
}

func resolveFromSudo() (*Result, error) {
	uidStr := os.Getenv("SUDO_UID")
	if uidStr == "" {
		return nil, nil // no sudo context, skip dropping
	}
	uid, err := strconv.ParseUint(uidStr, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("parse SUDO_UID=%q: %w", uidStr, err)
	}
	if uid == 0 {
		return nil, nil // root invoked sudo from root, nothing to drop
	}

	u, err := user.LookupId(uidStr)
	if err != nil {
		// Fallback: use SUDO_UID/SUDO_GID directly without group lookup.
		return resolveFromSudoRaw(uint32(uid))
	}
	return resultFromUser(u)
}

// resolveFromSudoRaw builds a result when /etc/passwd lookup fails
// (e.g., LDAP/NIS user, minimal container). Uses SUDO_GID if available,
// otherwise falls back to the same value as UID for the primary GID.
func resolveFromSudoRaw(uid uint32) (*Result, error) {
	gid := uid // default: same as UID
	if gidStr := os.Getenv("SUDO_GID"); gidStr != "" {
		parsed, err := strconv.ParseUint(gidStr, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("parse SUDO_GID=%q: %w", gidStr, err)
		}
		gid = uint32(parsed)
	}

	username := os.Getenv("SUDO_USER")
	if username == "" {
		username = strconv.FormatUint(uint64(uid), 10)
	}
	homeDir := "/home/" + username

	return &Result{
		Credential: &syscall.Credential{
			Uid:    uid,
			Gid:    gid,
			Groups: []uint32{gid},
		},
		UID:      uid,
		GID:      gid,
		Username: username,
		HomeDir:  homeDir,
	}, nil
}

func resultFromUser(u *user.User) (*Result, error) {
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("parse uid %q: %w", u.Uid, err)
	}
	gid, err := strconv.ParseUint(u.Gid, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("parse gid %q: %w", u.Gid, err)
	}

	groups, err := supplementaryGroups(u)
	if err != nil {
		// Non-fatal: fall back to primary group only.
		groups = []uint32{uint32(gid)}
	}

	homeDir := u.HomeDir
	if homeDir == "" {
		homeDir = "/home/" + u.Username
	}

	return &Result{
		Credential: &syscall.Credential{
			Uid:    uint32(uid),
			Gid:    uint32(gid),
			Groups: groups,
		},
		UID:      uint32(uid),
		GID:      uint32(gid),
		Username: u.Username,
		HomeDir:  homeDir,
	}, nil
}

func supplementaryGroups(u *user.User) ([]uint32, error) {
	gids, err := u.GroupIds()
	if err != nil {
		return nil, err
	}
	groups := make([]uint32, 0, len(gids))
	for _, g := range gids {
		id, err := strconv.ParseUint(g, 10, 32)
		if err != nil {
			continue
		}
		groups = append(groups, uint32(id))
	}
	if len(groups) == 0 {
		return nil, fmt.Errorf("no groups resolved")
	}
	return groups, nil
}
