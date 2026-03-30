//go:build e2e

package e2e_test

import (
	"fmt"
	"net"
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	if os.Getuid() != 0 {
		fmt.Println("SKIP: e2e tests require root (run with sudo)")
		os.Exit(0)
	}
	// E2E tests place connector processes into cgroups via cgroup.procs.
	// This fails inside a container cgroup namespace (e.g. Docker devcontainer)
	// because the kernel rejects cross-namespace cgroup writes. Detect this by
	// comparing our cgroup namespace to the initial namespace (held by PID 1).
	selfNS, err1 := os.Readlink("/proc/self/ns/cgroup")
	initNS, err2 := os.Readlink("/proc/1/ns/cgroup")
	if err1 == nil && err2 == nil && selfNS != initNS {
		fmt.Println("SKIP: e2e tests require host cgroup namespace (skipping inside container)")
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// splitHostPort is a helper to split a host:port string.
func splitHostPort(addr string) (host, port string, err error) {
	host, port, err = net.SplitHostPort(addr)
	return
}
