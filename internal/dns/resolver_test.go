package dns

import (
	"log/slog"
	"net"
	"testing"
)

func testLogger() *slog.Logger {
	return slog.Default()
}

func TestNewResolver(t *testing.T) {
	r := NewResolver(testLogger(), nil)
	if r == nil {
		t.Fatal("NewResolver returned nil")
	}
}

func TestLookupMissReturnsNil(t *testing.T) {
	r := NewResolver(testLogger(), nil)
	ips := r.Lookup("notcached.example.com")
	if ips != nil {
		t.Errorf("expected nil for uncached domain, got %v", ips)
	}
}

func TestIPsEqual(t *testing.T) {
	a := []net.IP{net.ParseIP("1.2.3.4"), net.ParseIP("5.6.7.8")}
	b := []net.IP{net.ParseIP("5.6.7.8"), net.ParseIP("1.2.3.4")}
	if !ipsEqual(a, b) {
		t.Error("ipsEqual: same IPs in different order should be equal")
	}

	c := []net.IP{net.ParseIP("1.2.3.4")}
	if ipsEqual(a, c) {
		t.Error("ipsEqual: different length slices should not be equal")
	}
}

func TestWildcardSkippedInResolveAll(t *testing.T) {
	r := NewResolver(testLogger(), nil)
	// *.example.com is a wildcard — should be skipped without error
	err := r.ResolveAll([]string{"*.example.com"})
	if err != nil {
		t.Fatalf("unexpected error for wildcard domain: %v", err)
	}
}

func TestUpdatesChannel(t *testing.T) {
	r := NewResolver(testLogger(), nil)
	ch := r.Updates()
	if ch == nil {
		t.Error("Updates() should return a non-nil channel")
	}
}
