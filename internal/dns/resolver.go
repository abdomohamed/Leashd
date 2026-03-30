package dns

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	mdns "github.com/miekg/dns"
)

// Upstream DNS servers used for resolution (bypasses the system resolver to
// avoid local spoofing and to get accurate TTL values).
var DefaultUpstreams = []string{"1.1.1.1:53", "8.8.8.8:53"}

// ResolverUpdate is sent on the Updates channel when a domain's IPs change.
type ResolverUpdate struct {
	Domain string
	OldIPs []net.IP
	NewIPs []net.IP
}

type resolvedEntry struct {
	IPs        []net.IP
	MinTTL     time.Duration
	ResolvedAt time.Time
}

// Resolver pre-resolves domain names and keeps them fresh via TTL-based refresh.
type Resolver struct {
	upstreams []string
	client    *mdns.Client

	mu      sync.RWMutex
	cache   map[string]resolvedEntry // domain → resolved entry
	updates chan ResolverUpdate
	logger  *slog.Logger
}

// NewResolver creates a Resolver for the given set of domains.
func NewResolver(logger *slog.Logger, upstreams []string) *Resolver {
	if len(upstreams) == 0 {
		upstreams = DefaultUpstreams
	}
	return &Resolver{
		upstreams: upstreams,
		client:    &mdns.Client{Timeout: 5 * time.Second},
		cache:     make(map[string]resolvedEntry),
		updates:   make(chan ResolverUpdate, 64),
		logger:    logger,
	}
}

// Updates returns a channel that receives updates when a domain's IPs change.
func (r *Resolver) Updates() <-chan ResolverUpdate {
	return r.updates
}

// ResolveAll resolves all given non-wildcard domains synchronously.
// Must be called before Start(). Returns the first error encountered.
func (r *Resolver) ResolveAll(domains []string) error {
	for _, d := range domains {
		if isWildcard(d) {
			r.logger.Debug("skipping wildcard domain in pre-resolve", "domain", d)
			continue
		}
		if _, err := r.resolve(d); err != nil {
			r.logger.Warn("initial DNS resolution failed", "domain", d, "error", err)
			// Non-fatal: log and continue so one bad domain doesn't block startup.
		}
	}
	r.logger.Info("initial DNS resolution complete",
		"domains", len(domains),
		"cached", len(r.cache),
	)
	return nil
}

// Start launches the background TTL-refresh goroutine.
func (r *Resolver) Start(ctx context.Context, domains []string) {
	go r.refreshLoop(ctx, domains)
}

func (r *Resolver) refreshLoop(ctx context.Context, domains []string) {
	// Refresh interval: minimum TTL * 0.8, capped at 30s.
	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			for _, d := range domains {
				if isWildcard(d) {
					continue
				}
				r.mu.RLock()
				prev, hasPrev := r.cache[d]
				r.mu.RUnlock()
				if hasPrev {
					elapsed := time.Since(prev.ResolvedAt)
					ttl := prev.MinTTL
					if ttl < 5*time.Second {
						ttl = 5 * time.Second
					}
					if elapsed < time.Duration(float64(ttl)*0.8) {
						continue
					}
				}
				newIPs, err := r.resolve(d)
				if err != nil {
					r.logger.Warn("DNS refresh failed", "domain", d, "error", err)
					continue
				}
				if hasPrev && !ipsEqual(prev.IPs, newIPs) {
					r.logger.Info("IP change detected on DNS refresh",
						"domain", d,
						"old_ips", formatIPs(prev.IPs),
						"new_ips", formatIPs(newIPs),
					)
					select {
					case r.updates <- ResolverUpdate{Domain: d, OldIPs: prev.IPs, NewIPs: newIPs}:
					default:
					}
				}
			}
		}
	}
}

// Lookup returns the cached IPs for a domain, or nil if not cached.
func (r *Resolver) Lookup(domain string) []net.IP {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if e, ok := r.cache[domain]; ok {
		return e.IPs
	}
	return nil
}

// ReverseLookup performs a PTR record lookup for an IP address.
// Returns empty string on failure or timeout.
func (r *Resolver) ReverseLookup(ip net.IP) string {
	arpa, err := mdns.ReverseAddr(ip.String())
	if err != nil {
		return ""
	}
	for _, upstream := range r.upstreams {
		m := new(mdns.Msg)
		m.SetQuestion(arpa, mdns.TypePTR)
		resp, _, err := r.client.Exchange(m, upstream)
		if err != nil || resp == nil {
			continue
		}
		for _, rr := range resp.Answer {
			if ptr, ok := rr.(*mdns.PTR); ok {
				return strings.TrimSuffix(ptr.Ptr, ".")
			}
		}
	}
	return ""
}

// ConfirmReverseDNS performs forward-confirmation of a reverse DNS lookup to
// prevent PTR spoofing. Returns the hostname only if a forward A lookup of
// hostname includes ip.
func (r *Resolver) ConfirmReverseDNS(ip net.IP) string {
	hostname := r.ReverseLookup(ip)
	if hostname == "" {
		return ""
	}
	forwardIPs, err := r.resolve(hostname)
	if err != nil {
		r.logger.Warn("forward-confirm DNS lookup failed", "hostname", hostname, "error", err)
		return ""
	}
	for _, fwdIP := range forwardIPs {
		if fwdIP.Equal(ip) {
			return hostname
		}
	}
	r.logger.Warn("reverse DNS forward-confirm failed (possible PTR spoofing)",
		"ip", ip.String(), "ptr_hostname", hostname)
	return ""
}

func (r *Resolver) resolve(domain string) ([]net.IP, error) {
	var allIPs []net.IP
	minTTL := time.Duration(300) * time.Second

	for _, upstream := range r.upstreams {
		m := new(mdns.Msg)
		m.SetQuestion(mdns.Fqdn(domain), mdns.TypeA)
		resp, _, err := r.client.Exchange(m, upstream)
		if err != nil || resp == nil {
			continue
		}
		for _, rr := range resp.Answer {
			if a, ok := rr.(*mdns.A); ok {
				allIPs = append(allIPs, a.A)
				ttl := time.Duration(a.Hdr.Ttl) * time.Second
				if ttl < minTTL {
					minTTL = ttl
				}
			}
		}
		if len(allIPs) > 0 {
			break
		}
	}

	if len(allIPs) == 0 {
		// Fall back to system resolver (no TTL info).
		addrs, err := net.LookupHost(domain)
		if err != nil {
			return nil, fmt.Errorf("resolve %s: %w", domain, err)
		}
		for _, a := range addrs {
			if ip := net.ParseIP(a); ip != nil {
				if v4 := ip.To4(); v4 != nil {
					allIPs = append(allIPs, v4)
				}
			}
		}
		minTTL = 60 * time.Second
	}

	r.logger.Debug("resolved domain", "domain", domain, "ips", formatIPs(allIPs), "ttl", minTTL)

	r.mu.Lock()
	r.cache[domain] = resolvedEntry{IPs: allIPs, MinTTL: minTTL, ResolvedAt: time.Now()}
	r.mu.Unlock()

	return allIPs, nil
}

func isWildcard(domain string) bool {
	return strings.Contains(domain, "*")
}

func ipsEqual(a, b []net.IP) bool {
	if len(a) != len(b) {
		return false
	}
	set := make(map[string]bool, len(a))
	for _, ip := range a {
		set[ip.String()] = true
	}
	for _, ip := range b {
		if !set[ip.String()] {
			return false
		}
	}
	return true
}

func formatIPs(ips []net.IP) []string {
	ss := make([]string, len(ips))
	for i, ip := range ips {
		ss[i] = ip.String()
	}
	return ss
}
