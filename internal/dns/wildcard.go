package dns

import (
	"strings"
)

// MatchesDomain reports whether domain matches pattern.
// Patterns support:
//   - Exact match:    "example.com"       matches "example.com" only
//   - Single-level:   "*.example.com"     matches "foo.example.com" but not "a.b.example.com"
//   - Multi-level:    "**.example.com"    matches "a.b.example.com"
func MatchesDomain(pattern, domain string) bool {
	pattern = strings.ToLower(strings.TrimSuffix(pattern, "."))
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))

	if strings.HasPrefix(pattern, "**.") {
		// Multi-level wildcard: matches any number of subdomain levels.
		suffix := pattern[3:] // strip "**."
		return domain == suffix || strings.HasSuffix(domain, "."+suffix)
	}
	if strings.HasPrefix(pattern, "*.") {
		// Single-level wildcard: matches exactly one subdomain level.
		suffix := pattern[2:] // strip "*."
		if !strings.HasSuffix(domain, "."+suffix) {
			return false
		}
		// Ensure there's exactly one level between the wildcard and the suffix.
		sub := strings.TrimSuffix(domain, "."+suffix)
		return !strings.Contains(sub, ".")
	}
	return pattern == domain
}
