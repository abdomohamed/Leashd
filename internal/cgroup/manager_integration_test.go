//go:build integration

package cgroup

import (
	"fmt"
	"os"
	"testing"
)

func TestCgroupLifecycle(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("cgroup integration tests require root")
	}

	name := fmt.Sprintf("leashd-test-%d", os.Getpid())
	m := NewManager(name)

	// Create
	if err := m.Create(); err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() { _ = m.Delete() })

	// Verify path exists
	if _, err := os.Stat(m.Path()); err != nil {
		t.Fatalf("cgroup path %s does not exist after Create: %v", m.Path(), err)
	}

	// AddPID (self)
	if err := m.AddPID(os.Getpid()); err != nil {
		t.Fatalf("AddPID: %v", err)
	}

	// CgroupID must be non-zero
	id, err := m.CgroupID()
	if err != nil {
		t.Fatalf("CgroupID: %v", err)
	}
	if id == 0 {
		t.Error("expected non-zero cgroup ID")
	}

	// CgroupID must match kernel view via /proc/self/cgroup
	selfID, err := SelfCgroupID()
	if err != nil {
		t.Logf("SelfCgroupID: %v (may be in hybrid hierarchy)", err)
	} else if selfID != id {
		t.Errorf("CgroupID mismatch: manager says %d, /proc/self/cgroup says %d", id, selfID)
	}

	// FD
	fd, err := m.FD()
	if err != nil {
		t.Fatalf("FD: %v", err)
	}
	fd.Close()

	// Delete (move self back first — can't delete cgroup with processes)
	// Move self back to the root cgroup
	rootManager := NewManager("")
	_ = rootManager.AddPID(os.Getpid())

	if err := m.Delete(); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := os.Stat(m.Path()); !os.IsNotExist(err) {
		t.Errorf("cgroup path still exists after Delete")
	}
}
