package dns

import "testing"

func TestMatchesDomain(t *testing.T) {
	cases := []struct {
		pattern string
		domain  string
		want    bool
	}{
		// Exact match
		{"example.com", "example.com", true},
		{"example.com", "sub.example.com", false},
		{"example.com", "other.com", false},

		// Single-level wildcard
		{"*.example.com", "foo.example.com", true},
		{"*.example.com", "example.com", false},          // base domain — no match
		{"*.example.com", "a.b.example.com", false},      // two levels — no match
		{"*.amazonaws.com", "s3.amazonaws.com", true},
		{"*.amazonaws.com", "deep.s3.amazonaws.com", false},

		// Multi-level wildcard
		{"**.example.com", "foo.example.com", true},
		{"**.example.com", "a.b.example.com", true},
		{"**.example.com", "example.com", true},   // base domain also matches
		{"**.amazonaws.com", "deep.s3.amazonaws.com", true},

		// Trailing dot normalisation
		{"example.com.", "example.com", true},
		{"example.com", "example.com.", true},

		// Case insensitivity
		{"Example.COM", "example.com", true},
		{"*.Example.COM", "FOO.example.com", true},
	}

	for _, tc := range cases {
		got := MatchesDomain(tc.pattern, tc.domain)
		if got != tc.want {
			t.Errorf("MatchesDomain(%q, %q) = %v, want %v", tc.pattern, tc.domain, got, tc.want)
		}
	}
}
