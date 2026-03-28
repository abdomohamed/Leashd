package cgroup

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	// CgroupRoot is the cgroupv2 unified hierarchy root for leashd-managed cgroups.
	CgroupRoot = "/sys/fs/cgroup/leashd"
)

// Manager manages a single cgroupv2 for a leashd session.
type Manager struct {
	name string
	path string
}

// NewManager creates a Manager for a cgroup with the given name under CgroupRoot.
// The cgroup is not created until Create() is called.
func NewManager(name string) *Manager {
	return &Manager{
		name: name,
		path: filepath.Join(CgroupRoot, name),
	}
}

// Path returns the absolute filesystem path of this cgroup.
func (m *Manager) Path() string {
	return m.path
}

// Create creates the cgroup directory and enables required controllers.
func (m *Manager) Create() error {
	// Ensure the leashd root cgroup exists.
	if err := os.MkdirAll(CgroupRoot, 0755); err != nil {
		return fmt.Errorf("create cgroup root %s: %w", CgroupRoot, err)
	}
	// Create the session cgroup.
	if err := os.Mkdir(m.path, 0755); err != nil && !os.IsExist(err) {
		return fmt.Errorf("create cgroup %s: %w", m.path, err)
	}
	return nil
}

// AddPID writes a PID to cgroup.procs, placing it in this cgroup.
func (m *Manager) AddPID(pid int) error {
	procsPath := filepath.Join(m.path, "cgroup.procs")
	if err := os.WriteFile(procsPath, []byte(strconv.Itoa(pid)+"\n"), 0); err != nil {
		return fmt.Errorf("add pid %d to cgroup %s: %w", pid, m.path, err)
	}
	return nil
}

// CgroupID returns the cgroup ID as seen by the kernel (inode number on cgroupv2).
// This matches what bpf_get_current_cgroup_id() returns.
func (m *Manager) CgroupID() (uint64, error) {
	var stat unix.Stat_t
	if err := unix.Stat(m.path, &stat); err != nil {
		return 0, fmt.Errorf("stat cgroup %s: %w", m.path, err)
	}
	return stat.Ino, nil
}

// FD opens the cgroup directory and returns a file descriptor.
// Used with SysProcAttr.CgroupFD for atomic process placement (Linux 5.7+).
// Caller is responsible for closing the returned *os.File.
func (m *Manager) FD() (*os.File, error) {
	f, err := os.Open(m.path)
	if err != nil {
		return nil, fmt.Errorf("open cgroup fd %s: %w", m.path, err)
	}
	return f, nil
}

// Delete removes the cgroup directory. The cgroup must be empty (no processes).
func (m *Manager) Delete() error {
	if err := os.Remove(m.path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("delete cgroup %s: %w", m.path, err)
	}
	return nil
}

// CheckCgroupV2 returns an error if the cgroupv2 unified hierarchy is not
// available or the leashd root is not writable.
func CheckCgroupV2() error {
	candidates := []string{
		"/sys/fs/cgroup",
		"/sys/fs/cgroup/unified",
	}
	for _, root := range candidates {
		var st unix.Statfs_t
		if err := unix.Statfs(root, &st); err != nil {
			continue
		}
		// CGROUP2_SUPER_MAGIC = 0x63677270
		if st.Type == 0x63677270 {
			// cgroupv2 found — check if we can create the leashd subdirectory
			testPath := filepath.Join(root, "leashd")
			if err := os.MkdirAll(testPath, 0755); err != nil {
				return fmt.Errorf("cgroupv2 found at %s but not writable: %w", root, err)
			}
			return nil
		}
	}
	return fmt.Errorf("cgroupv2 unified hierarchy not found; ensure it is mounted at /sys/fs/cgroup")
}

// SelfCgroupID returns the cgroup ID of the current process. Useful for tests.
func SelfCgroupID() (uint64, error) {
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return 0, err
	}
	// cgroupv2 format: "0::/path/relative/to/root"
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "0::") {
			relPath := strings.TrimPrefix(line, "0::")
			absPath := filepath.Join("/sys/fs/cgroup", strings.TrimSpace(relPath))
			var stat unix.Stat_t
			if err := unix.Stat(absPath, &stat); err != nil {
				return 0, fmt.Errorf("stat self cgroup %s: %w", absPath, err)
			}
			return stat.Ino, nil
		}
	}
	return 0, fmt.Errorf("could not determine cgroupv2 ID from /proc/self/cgroup")
}
