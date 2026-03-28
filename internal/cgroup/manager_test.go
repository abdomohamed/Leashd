//go:build !integration

package cgroup

import (
	"testing"
)

// Unit-level test: just ensure the struct and methods exist and compile.
// Real cgroup operations require root and are tested under the integration tag.

func TestNewManager(t *testing.T) {
	m := NewManager("test-session")
	if m == nil {
		t.Fatal("NewManager returned nil")
	}
	if m.Path() == "" {
		t.Error("expected non-empty path")
	}
}

func TestCgroupRootPath(t *testing.T) {
	m := NewManager("my-project-abc123")
	expected := CgroupRoot + "/my-project-abc123"
	if m.Path() != expected {
		t.Errorf("expected path %q, got %q", expected, m.Path())
	}
}
