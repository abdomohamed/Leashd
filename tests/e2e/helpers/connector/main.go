// connector is a tiny TCP dialer binary used by E2E tests.
// It dials the given address, optionally writes a message, and exits.
// Exit code 0 = success, non-zero = connection error.
package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"time"
)

func main() {
	addr := flag.String("addr", "", "TCP address to dial (host:port)")
	timeout := flag.Duration("timeout", 5*time.Second, "Dial timeout")
	flag.Parse()

	if *addr == "" {
		fmt.Fprintln(os.Stderr, "connector: --addr is required")
		os.Exit(2)
	}

	conn, err := net.DialTimeout("tcp", *addr, *timeout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "connector: dial %s failed: %v\n", *addr, err)
		os.Exit(1)
	}
	_ = conn.Close()
	fmt.Printf("connector: connected to %s\n", *addr)
	os.Exit(0)
}
