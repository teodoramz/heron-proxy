package router

import (
	"net/netip"
	"testing"

	"github.com/amzteodor/heron/internal/config"
)

func testApps() []config.App {
	return []config.App{
		{ID: "1", Name: "api", Hostnames: []string{"api.example"}, Enabled: true},
		{ID: "2", Name: "wild", Hostnames: []string{"*.wild.example"}, Enabled: true},
		{ID: "3", Name: "off", Hostnames: []string{"off.example"}, Enabled: false},
	}
}

func TestMatchExact(t *testing.T) {
	r := New()
	r.Replace(testApps())
	app, ok := r.Match("api.example")
	if !ok || app.ID != "1" {
		t.Fatalf("Match = %v, %v", app, ok)
	}
}

func TestMatchStripsPortAndCase(t *testing.T) {
	r := New()
	r.Replace(testApps())
	for _, host := range []string{"API.Example:8443", "api.example.", "api.example:443"} {
		if _, ok := r.Match(host); !ok {
			t.Errorf("Match(%q) failed", host)
		}
	}
}

func TestMatchWildcard(t *testing.T) {
	r := New()
	r.Replace(testApps())
	app, ok := r.Match("anything.wild.example")
	if !ok || app.ID != "2" {
		t.Fatalf("wildcard match failed: %v %v", app, ok)
	}
	if _, ok := r.Match("wild.example"); ok {
		t.Error("bare parent must not match *.wild.example")
	}
}

func TestMatchExactBeatsWildcard(t *testing.T) {
	r := New()
	r.Replace([]config.App{
		{ID: "w", Hostnames: []string{"*.example"}, Enabled: true},
		{ID: "e", Hostnames: []string{"a.example"}, Enabled: true},
	})
	app, _ := r.Match("a.example")
	if app.ID != "e" {
		t.Errorf("matched %s, want the exact entry", app.ID)
	}
}

func TestDisabledAppNotRouted(t *testing.T) {
	r := New()
	r.Replace(testApps())
	if _, ok := r.Match("off.example"); ok {
		t.Error("a disabled app must not be routable")
	}
	if _, ok := r.ByID("3"); !ok {
		t.Error("a disabled app must still be addressable by ID")
	}
}

func TestUnknownHost(t *testing.T) {
	r := New()
	r.Replace(testApps())
	if _, ok := r.Match("nope.example"); ok {
		t.Error("unknown host matched")
	}
}

func TestReplaceIsLive(t *testing.T) {
	r := New()
	r.Replace(testApps())
	r.Replace([]config.App{{ID: "9", Hostnames: []string{"new.example"}, Enabled: true}})
	if _, ok := r.Match("api.example"); ok {
		t.Error("old route survived Replace")
	}
	if _, ok := r.Match("new.example"); !ok {
		t.Error("new route not installed")
	}
}

func TestReplaceAppliesDefaults(t *testing.T) {
	r := New()
	r.Replace([]config.App{{ID: "1", Hostnames: []string{"a.example"}, Enabled: true}})
	app, _ := r.Match("a.example")
	if app.ClientIPHeader != "X-Real-IP" || app.RetentionDays != 90 {
		t.Errorf("defaults not applied: %+v", app)
	}
}

func addr(s string) netip.Addr { a, _ := netip.ParseAddr(s); return a }

func TestUntrustedPeerXFFIgnored(t *testing.T) {
	trusted := ParseCIDRs([]string{"10.0.0.0/8"})
	real, claimed := ResolveClientIP("203.0.113.9:5555", "1.2.3.4", trusted)
	if real != addr("203.0.113.9") {
		t.Errorf("real = %v, want the TCP peer", real)
	}
	if claimed != addr("1.2.3.4") {
		t.Errorf("claimed = %v, want the spoofed value preserved", claimed)
	}
}

func TestTrustedPeerXFFHonored(t *testing.T) {
	trusted := ParseCIDRs([]string{"10.0.0.0/8"})
	real, claimed := ResolveClientIP("10.1.2.3:443", "198.51.100.7", trusted)
	if real != addr("198.51.100.7") {
		t.Errorf("real = %v, want the forwarded client", real)
	}
	if claimed != addr("198.51.100.7") {
		t.Errorf("claimed = %v", claimed)
	}
}

func TestTrustedChainSkipsTrustedHops(t *testing.T) {
	trusted := ParseCIDRs([]string{"10.0.0.0/8", "172.16.0.0/12"})
	real, claimed := ResolveClientIP("10.0.0.1:443", "198.51.100.7, 172.16.5.5, 10.0.0.9", trusted)
	if real != addr("198.51.100.7") {
		t.Errorf("real = %v, want the rightmost untrusted hop", real)
	}
	if claimed != addr("198.51.100.7") {
		t.Errorf("claimed = %v", claimed)
	}
}

func TestTrustedPeerAllHopsTrusted(t *testing.T) {
	trusted := ParseCIDRs([]string{"10.0.0.0/8"})
	real, _ := ResolveClientIP("10.0.0.1:443", "10.0.0.5, 10.0.0.6", trusted)
	if real != addr("10.0.0.5") {
		t.Errorf("real = %v, want the leftmost hop when all are trusted", real)
	}
}

func TestMalformedXFFIgnored(t *testing.T) {
	trusted := ParseCIDRs([]string{"10.0.0.0/8"})
	real, claimed := ResolveClientIP("10.0.0.1:443", "not-an-ip, , bogus", trusted)
	if real != addr("10.0.0.1") {
		t.Errorf("real = %v, want the peer when XFF is unusable", real)
	}
	if claimed.IsValid() {
		t.Errorf("claimed = %v, want invalid", claimed)
	}
}

func TestXFFEntryWithPort(t *testing.T) {
	trusted := ParseCIDRs([]string{"10.0.0.0/8"})
	real, _ := ResolveClientIP("10.0.0.1:443", "198.51.100.7:1234", trusted)
	if real != addr("198.51.100.7") {
		t.Errorf("real = %v", real)
	}
}

func TestIPv6PeerAndXFF(t *testing.T) {
	trusted := ParseCIDRs([]string{"2001:db8::/32"})
	real, _ := ResolveClientIP("[2001:db8::1]:443", "[2001:4860::8888]:99", trusted)
	if real != addr("2001:4860::8888") {
		t.Errorf("real = %v", real)
	}
}

func TestNoTrustedProxiesConfigured(t *testing.T) {
	real, claimed := ResolveClientIP("10.0.0.1:443", "1.2.3.4", nil)
	if real != addr("10.0.0.1") {
		t.Errorf("real = %v, want the peer when nothing is trusted", real)
	}
	if claimed != addr("1.2.3.4") {
		t.Errorf("claimed = %v", claimed)
	}
}

func TestParseCIDRsAcceptsBareAddress(t *testing.T) {
	p := ParseCIDRs([]string{"10.0.0.1", "192.168.0.0/16", "garbage"})
	if len(p) != 2 {
		t.Fatalf("got %d prefixes, want 2", len(p))
	}
	if !Trusted(addr("10.0.0.1"), p) {
		t.Error("bare address not trusted")
	}
	if Trusted(addr("10.0.0.2"), p) {
		t.Error("bare address widened into a range")
	}
}

func TestPeerAddrWithoutPort(t *testing.T) {
	if got := PeerAddr("203.0.113.5"); got != addr("203.0.113.5") {
		t.Errorf("PeerAddr = %v", got)
	}
}
