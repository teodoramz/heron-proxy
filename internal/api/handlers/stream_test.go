package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestOriginAllowed covers the only cross-site control on the live-tail
// websocket: the CSRF middleware cannot apply to a handshake, so a permissive
// Origin check would let any page a signed-in analyst visits stream recorded
// traffic, request bodies included.
func TestOriginAllowed(t *testing.T) {
	cases := []struct {
		name    string
		origin  string
		host    string
		allowed []string
		want    bool
	}{
		{"same origin", "https://waf.example.com", "waf.example.com", nil, true},
		{"same origin, different case", "https://WAF.example.com", "waf.example.com", nil, true},
		{"same host with port", "http://localhost:8081", "localhost:8081", nil, true},
		{"configured cross origin", "https://ops.example.com", "waf.example.com", []string{"https://ops.example.com"}, true},
		{"unconfigured cross origin", "https://evil.example", "waf.example.com", []string{"https://ops.example.com"}, false},
		{"no origin at all", "", "waf.example.com", nil, false},
		{"attacker host prefix", "https://waf.example.com.evil.test", "waf.example.com", nil, false},
		{"scheme mismatch on configured origin", "http://ops.example.com", "waf.example.com", []string{"https://ops.example.com"}, false},
		{"malformed origin", "://nonsense", "waf.example.com", nil, false},
		{"null origin", "null", "waf.example.com", nil, false},
		{"different port is a different origin", "http://localhost:9999", "localhost:8081", nil, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/api/stream", nil)
			r.Host = c.host
			if c.origin != "" {
				r.Header.Set("Origin", c.origin)
			}
			if got := originAllowed(r, c.allowed); got != c.want {
				t.Errorf("originAllowed(origin=%q, host=%q) = %v, want %v", c.origin, c.host, got, c.want)
			}
		})
	}
}

func TestUpgraderUsesTheSameCheck(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/api/stream", nil)
	r.Host = "waf.example.com"
	r.Header.Set("Origin", "https://evil.example")

	if upgrader.CheckOrigin(r) {
		t.Error("the upgrader accepted a hostile origin")
	}

	r.Header.Set("Origin", "https://waf.example.com")
	if !upgrader.CheckOrigin(r) {
		t.Error("the upgrader rejected a same-origin handshake")
	}
}
