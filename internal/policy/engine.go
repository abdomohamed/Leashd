package policy

import (
	"encoding/binary"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/abdotalema/leashd/internal/config"
	ldns "github.com/abdotalema/leashd/internal/dns"
)

// Engine matches raw connect events against the compiled policy and produces verdicts.
type Engine struct {
	mu      sync.RWMutex
	policy  *CompiledPolicy
	cfg     *config.Config
	resolver *ldns.Resolver
	logger  *slog.Logger

	// Forward-learning cache: IP string → verdict, populated on first wildcard hit.
	learnedCache   map[string]learnedEntry
	learnedCacheMu sync.RWMutex
}

type learnedEntry struct {
	Verdict   uint8
	RuleID    string
	ExpiresAt time.Time
}

// NewEngine creates an Engine with an initial policy.
func NewEngine(cfg *config.Config, policy *CompiledPolicy, resolver *ldns.Resolver, logger *slog.Logger) *Engine {
	return &Engine{
		policy:       policy,
		cfg:          cfg,
		resolver:     resolver,
		logger:       logger,
		learnedCache: make(map[string]learnedEntry),
	}
}

// UpdatePolicy atomically replaces the current policy.
func (e *Engine) UpdatePolicy(cfg *config.Config, policy *CompiledPolicy) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.cfg = cfg
	e.policy = policy
	// Clear the learned cache on policy update so stale entries don't persist.
	e.learnedCacheMu.Lock()
	e.learnedCache = make(map[string]learnedEntry)
	e.learnedCacheMu.Unlock()
}

// Verdict returns the verdict for a destination IP, performing reverse DNS
// lookup and wildcard matching when the IP is not in the policy map.
func (e *Engine) Verdict(dstIP net.IP) (verdict uint8, matchedRuleID string, reverseDNS string) {
	e.mu.RLock()
	pol := e.policy
	cfg := e.cfg
	e.mu.RUnlock()

	ipStr := dstIP.String()

	// Check forward-learning cache first.
	e.learnedCacheMu.RLock()
	if entry, ok := e.learnedCache[ipStr]; ok && time.Now().Before(entry.ExpiresAt) {
		e.learnedCacheMu.RUnlock()
		return entry.Verdict, entry.RuleID, ""
	}
	e.learnedCacheMu.RUnlock()

	// Check compiled LPM entries (exact IPs and CIDRs).
	if pol != nil {
		for _, entry := range pol.Entries {
			if matchesLPM(dstIP, entry) {
				e.logger.Debug("verdict_decision",
					"ip", ipStr,
					"matched_rule", entry.RuleID,
					"verdict", entry.Verdict,
				)
				return entry.Verdict, entry.RuleID, ""
			}
		}
	}

	// Not in policy map — perform reverse DNS and check wildcard rules.
	var rdns string
	if e.resolver != nil {
		rdns = e.resolver.ConfirmReverseDNS(dstIP)
	}
	if rdns != "" && cfg != nil {
		for _, rule := range cfg.Rules {
			for _, domain := range rule.Domains {
				if ldns.MatchesDomain(domain, rdns) {
					v, err := actionToVerdict(rule.Action)
					if err != nil {
						continue
					}
					e.logger.Debug("verdict_decision",
						"ip", ipStr,
						"rdns", rdns,
						"matched_rule", rule.ID,
						"via", "wildcard",
						"verdict", v,
					)
					// Cache this IP → verdict for future connections.
					e.learnedCacheMu.Lock()
					e.learnedCache[ipStr] = learnedEntry{
						Verdict:   v,
						RuleID:    rule.ID,
						ExpiresAt: time.Now().Add(5 * time.Minute),
					}
					e.learnedCacheMu.Unlock()
					return v, rule.ID, rdns
				}
			}
		}
	}

	// No match — use default verdict.
	defaultVerdict := VerdictWarn
	if pol != nil {
		defaultVerdict = pol.DefaultVerdict
	}
	e.logger.Debug("verdict_decision",
		"ip", ipStr,
		"rdns", rdns,
		"verdict", defaultVerdict,
		"via", "default",
	)
	return defaultVerdict, "", rdns
}

// matchesLPM checks if ip falls within the LPM entry's prefix.
func matchesLPM(ip net.IP, entry LPMEntry) bool {
	v4 := ip.To4()
	if v4 == nil {
		return false
	}
	if entry.PrefixLen == 0 {
		return true
	}
	if entry.PrefixLen > 32 {
		return false
	}
	// entry.IP is LittleEndian-encoded (memory bytes = network byte order).
	// Restore network-byte-order bytes so standard IP masking works correctly.
	var entryBytes [4]byte
	binary.LittleEndian.PutUint32(entryBytes[:], entry.IP)
	ipInt := binary.BigEndian.Uint32(v4)
	entryInt := binary.BigEndian.Uint32(entryBytes[:])
	mask := ^uint32(0) << (32 - entry.PrefixLen)
	return (ipInt & mask) == (entryInt & mask)
}
