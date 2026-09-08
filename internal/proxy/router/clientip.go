package router

import (
	"net"
	"net/netip"
	"strings"
)

// ParseCIDRs parses trusted-proxy prefixes, ignoring entries that do not parse.
// A bare address is accepted as a single-host prefix.
func ParseCIDRs(in []string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if p, err := netip.ParsePrefix(s); err == nil {
			out = append(out, p)
			continue
		}
		if a, err := netip.ParseAddr(s); err == nil {
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
		}
	}
	return out
}

// Trusted reports whether addr falls inside any prefix.
func Trusted(addr netip.Addr, prefixes []netip.Prefix) bool {
	if !addr.IsValid() {
		return false
	}
	addr = addr.Unmap()
	for _, p := range prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// PeerAddr extracts the IP from a host:port remote address.
func PeerAddr(remoteAddr string) netip.Addr {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	addr, err := netip.ParseAddr(strings.Trim(host, "[]"))
	if err != nil {
		return netip.Addr{}
	}
	return addr.Unmap()
}

// ResolveClientIP determines the source address to attribute a request to.
//
// real is the address used for attribution: the TCP peer, unless that peer is a
// trusted proxy, in which case it is the rightmost X-Forwarded-For entry that is
// not itself trusted. claimed is always the leftmost X-Forwarded-For entry, kept
// so a spoofed value stays visible without being believed.
func ResolveClientIP(remoteAddr, xff string, trusted []netip.Prefix) (real, claimed netip.Addr) {
	peer := PeerAddr(remoteAddr)
	real = peer

	hops := parseForwarded(xff)
	if len(hops) > 0 {
		claimed = hops[0]
	}
	if !Trusted(peer, trusted) {
		return real, claimed
	}
	for i := len(hops) - 1; i >= 0; i-- {
		if !Trusted(hops[i], trusted) {
			return hops[i], claimed
		}
	}
	if len(hops) > 0 {
		return hops[0], claimed
	}
	return real, claimed
}

func parseForwarded(xff string) []netip.Addr {
	if xff == "" {
		return nil
	}
	parts := strings.Split(xff, ",")
	out := make([]netip.Addr, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		// Split before trimming so a bracketed IPv6 address with a port parses.
		if host, _, err := net.SplitHostPort(p); err == nil {
			p = host
		}
		p = strings.Trim(p, "[]")
		if a, err := netip.ParseAddr(p); err == nil {
			out = append(out, a.Unmap())
		}
	}
	return out
}
