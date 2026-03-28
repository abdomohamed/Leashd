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
	os.Exit(m.Run())
}

// splitHostPort is a helper to split a host:port string.
func splitHostPort(addr string) (host, port string, err error) {
	host, port, err = net.SplitHostPort(addr)
	return
}
