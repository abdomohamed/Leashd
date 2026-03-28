package ipc

import (
	"crypto/sha256"
	"fmt"
	"path/filepath"
)

// ProjectSocketPath returns the UNIX domain socket path for the leashd session
// rooted at dir. Both the server (leashd run) and client (leashd status) must
// call this with the same directory to find each other.
//
// The path is derived by:
//  1. Converting dir to an absolute path (handles relative paths like ".")
//  2. Resolving all symlinks to a canonical path (prevents hash mismatch when
//     the same directory is reached via different symlink paths)
//  3. Taking the first 8 bytes of SHA-256(canonical) as a hex string
func ProjectSocketPath(dir string) (string, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", fmt.Errorf("resolve absolute path for %q: %w", dir, err)
	}
	canonical, err := filepath.EvalSymlinks(abs)
	if err != nil {
		// Directory may not exist yet (e.g. during tests); use abs as fallback.
		canonical = abs
	}
	h := sha256.Sum256([]byte(canonical))
	return fmt.Sprintf("/tmp/leashd-%x.sock", h[:8]), nil
}
