package ja3

import (
	"crypto/md5"
	"encoding/hex"
	"strconv"
	"strings"
)

// JA3String returns the unhashed JA3 field string:
// version,ciphers,extensions,groups,ec_point_formats. GREASE values are omitted.
func (h *ClientHello) JA3String() string {
	var b strings.Builder
	b.WriteString(strconv.FormatUint(uint64(h.LegacyVersion), 10))
	b.WriteByte(',')
	writeDecimals(&b, filterGREASE(h.CipherSuites))
	b.WriteByte(',')
	writeDecimals(&b, filterGREASE(h.Extensions))
	b.WriteByte(',')
	writeDecimals(&b, filterGREASE(h.SupportedGroups))
	b.WriteByte(',')
	for i, f := range h.ECPointFormats {
		if i > 0 {
			b.WriteByte('-')
		}
		b.WriteString(strconv.FormatUint(uint64(f), 10))
	}
	return b.String()
}

// JA3 returns the MD5 of the JA3 string, as the fingerprint is conventionally published.
func (h *ClientHello) JA3() string {
	sum := md5.Sum([]byte(h.JA3String()))
	return hex.EncodeToString(sum[:])
}

func writeDecimals(b *strings.Builder, vals []uint16) {
	for i, v := range vals {
		if i > 0 {
			b.WriteByte('-')
		}
		b.WriteString(strconv.FormatUint(uint64(v), 10))
	}
}

func filterGREASE(in []uint16) []uint16 {
	out := make([]uint16, 0, len(in))
	for _, v := range in {
		if !IsGREASE(v) {
			out = append(out, v)
		}
	}
	return out
}
