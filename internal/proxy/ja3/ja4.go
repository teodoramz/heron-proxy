package ja3

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

const ja4Empty = "000000000000"

// JA4 returns the TCP-transport JA4 fingerprint: a_b_c, where a describes the
// hello, b hashes the sorted cipher list, and c hashes the sorted extension
// list with the signature algorithms in their original order.
func (h *ClientHello) JA4() string {
	return fmt.Sprintf("%s_%s_%s", h.ja4A(), h.ja4B(), h.ja4C())
}

func (h *ClientHello) ja4A() string {
	sni := byte('i')
	if h.SNI != "" {
		sni = 'd'
	}
	return fmt.Sprintf("t%s%c%02d%02d%s",
		ja4Version(h.negotiatedVersion()),
		sni,
		capCount(len(filterGREASE(h.CipherSuites))),
		capCount(len(filterGREASE(h.Extensions))),
		h.ja4ALPN(),
	)
}

func (h *ClientHello) ja4B() string {
	ciphers := hexList(filterGREASE(h.CipherSuites))
	if len(ciphers) == 0 {
		return ja4Empty
	}
	sort.Strings(ciphers)
	return truncatedSHA256(strings.Join(ciphers, ","))
}

func (h *ClientHello) ja4C() string {
	exts := make([]string, 0, len(h.Extensions))
	for _, e := range h.Extensions {
		// SNI and ALPN are excluded: their presence is already encoded in part a.
		if IsGREASE(e) || e == extServerName || e == extALPN {
			continue
		}
		exts = append(exts, fmt.Sprintf("%04x", e))
	}
	if len(exts) == 0 {
		return ja4Empty
	}
	sort.Strings(exts)
	out := strings.Join(exts, ",")

	if sigs := hexList(filterGREASE(h.SignatureAlgorithms)); len(sigs) > 0 {
		out += "_" + strings.Join(sigs, ",")
	}
	return truncatedSHA256(out)
}

// negotiatedVersion returns the highest non-GREASE version the client offered.
func (h *ClientHello) negotiatedVersion() uint16 {
	best := uint16(0)
	for _, v := range h.SupportedVersions {
		if !IsGREASE(v) && v > best {
			best = v
		}
	}
	if best != 0 {
		return best
	}
	return h.LegacyVersion
}

func (h *ClientHello) ja4ALPN() string {
	if len(h.ALPN) == 0 || h.ALPN[0] == "" {
		return "00"
	}
	first := h.ALPN[0]
	return string([]byte{first[0], first[len(first)-1]})
}

func ja4Version(v uint16) string {
	switch v {
	case 0x0304:
		return "13"
	case 0x0303:
		return "12"
	case 0x0302:
		return "11"
	case 0x0301:
		return "10"
	case 0x0300:
		return "s3"
	case 0x0002:
		return "s2"
	default:
		return "00"
	}
}

func hexList(vals []uint16) []string {
	out := make([]string, 0, len(vals))
	for _, v := range vals {
		out = append(out, fmt.Sprintf("%04x", v))
	}
	return out
}

func capCount(n int) int {
	if n > 99 {
		return 99
	}
	return n
}

func truncatedSHA256(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}
