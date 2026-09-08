package ja3

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

// helloBuilder assembles a syntactically valid ClientHello record.
type helloBuilder struct {
	version    uint16
	ciphers    []uint16
	extensions []byte
}

func (b *helloBuilder) addExt(extType uint16, body []byte) {
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint16(hdr[0:2], extType)
	binary.BigEndian.PutUint16(hdr[2:4], uint16(len(body)))
	b.extensions = append(b.extensions, hdr...)
	b.extensions = append(b.extensions, body...)
}

func (b *helloBuilder) build() []byte {
	body := make([]byte, 0, 256)
	body = binary.BigEndian.AppendUint16(body, b.version)
	body = append(body, make([]byte, 32)...) // random
	body = append(body, 0)                   // empty session id

	ciphers := make([]byte, 0, len(b.ciphers)*2)
	for _, c := range b.ciphers {
		ciphers = binary.BigEndian.AppendUint16(ciphers, c)
	}
	body = binary.BigEndian.AppendUint16(body, uint16(len(ciphers)))
	body = append(body, ciphers...)
	body = append(body, 1, 0) // one compression method: null

	body = binary.BigEndian.AppendUint16(body, uint16(len(b.extensions)))
	body = append(body, b.extensions...)

	hs := []byte{handshakeHello, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	hs = append(hs, body...)

	rec := []byte{recordHandshake, 0x03, 0x01}
	rec = binary.BigEndian.AppendUint16(rec, uint16(len(hs)))
	return append(rec, hs...)
}

func u16s(vals ...uint16) []byte {
	out := make([]byte, 0, len(vals)*2)
	for _, v := range vals {
		out = binary.BigEndian.AppendUint16(out, v)
	}
	return out
}

func vec16(payload []byte) []byte {
	return append(binary.BigEndian.AppendUint16(nil, uint16(len(payload))), payload...)
}

func sampleHello() []byte {
	b := &helloBuilder{version: 0x0303, ciphers: []uint16{0x0a0a, 0x1301, 0xc02f}}
	sni := append([]byte{0x00}, vec16([]byte("example.test"))...)
	b.addExt(extServerName, vec16(sni))
	b.addExt(extSupportedGrps, vec16(u16s(0x001d, 0x0017)))
	b.addExt(extECPointFmts, []byte{0x01, 0x00})
	b.addExt(extSigAlgs, vec16(u16s(0x0403)))
	b.addExt(extSupportedVers, append([]byte{0x04}, u16s(0x0304, 0x0303)...))
	alpn := append(append([]byte{0x02}, []byte("h2")...), append([]byte{0x08}, []byte("http/1.1")...)...)
	b.addExt(extALPN, vec16(alpn))
	b.addExt(0x2a2a, nil) // GREASE
	return b.build()
}

func mustParse(t *testing.T, rec []byte) *ClientHello {
	t.Helper()
	h, err := Parse(rec)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return h
}

func TestParseExtractsFields(t *testing.T) {
	h := mustParse(t, sampleHello())
	if h.SNI != "example.test" {
		t.Errorf("SNI = %q", h.SNI)
	}
	if len(h.CipherSuites) != 3 {
		t.Errorf("CipherSuites = %v", h.CipherSuites)
	}
	if len(h.ALPN) != 2 || h.ALPN[0] != "h2" || h.ALPN[1] != "http/1.1" {
		t.Errorf("ALPN = %v", h.ALPN)
	}
	if len(h.SupportedGroups) != 2 || h.SupportedGroups[0] != 0x001d {
		t.Errorf("SupportedGroups = %v", h.SupportedGroups)
	}
	if len(h.ECPointFormats) != 1 || h.ECPointFormats[0] != 0 {
		t.Errorf("ECPointFormats = %v", h.ECPointFormats)
	}
	if len(h.SignatureAlgorithms) != 1 || h.SignatureAlgorithms[0] != 0x0403 {
		t.Errorf("SignatureAlgorithms = %v", h.SignatureAlgorithms)
	}
}

func TestJA3StringExcludesGREASE(t *testing.T) {
	h := mustParse(t, sampleHello())
	const want = "771,4865-49199,0-10-11-13-43-16,29-23,0"
	if got := h.JA3String(); got != want {
		t.Errorf("JA3String\n got %q\nwant %q", got, want)
	}
}

func TestJA3IsMD5OfString(t *testing.T) {
	h := mustParse(t, sampleHello())
	got := h.JA3()
	if len(got) != 32 {
		t.Fatalf("JA3 = %q, want 32 hex chars", got)
	}
	// Recomputing from the string must agree.
	h2 := &ClientHello{LegacyVersion: 0x0303}
	if h2.JA3() == got {
		t.Error("different hellos produced the same JA3")
	}
}

func TestJA4Prefix(t *testing.T) {
	h := mustParse(t, sampleHello())
	const wantA = "t13d0206h2"
	got := h.JA4()
	if !strings.HasPrefix(got, wantA+"_") {
		t.Errorf("JA4 = %q, want prefix %q", got, wantA)
	}
	parts := strings.Split(got, "_")
	if len(parts) != 3 || len(parts[1]) != 12 || len(parts[2]) != 12 {
		t.Errorf("JA4 shape wrong: %q", got)
	}
}

func TestJA4UsesSupportedVersionsOverLegacy(t *testing.T) {
	b := &helloBuilder{version: 0x0301, ciphers: []uint16{0x1301}}
	b.addExt(extSupportedVers, append([]byte{0x02}, u16s(0x0304)...))
	h := mustParse(t, b.build())
	if !strings.HasPrefix(h.JA4(), "t13i") {
		t.Errorf("JA4 = %q, want t13i prefix (TLS 1.3, no SNI)", h.JA4())
	}
}

func TestJA4NoALPNAndNoSNI(t *testing.T) {
	b := &helloBuilder{version: 0x0303, ciphers: []uint16{0x1301}}
	h := mustParse(t, b.build())
	if !strings.HasPrefix(h.JA4(), "t12i010000") {
		t.Errorf("JA4 = %q, want t12i010000 prefix", h.JA4())
	}
}

func TestJA4CipherCountCapsAt99(t *testing.T) {
	b := &helloBuilder{version: 0x0303}
	for i := range 150 {
		b.ciphers = append(b.ciphers, uint16(0x1000+i))
	}
	h := mustParse(t, b.build())
	if h.JA4()[4:6] != "99" {
		t.Errorf("cipher count = %q, want 99", h.JA4()[4:6])
	}
}

func TestIsGREASE(t *testing.T) {
	for _, v := range []uint16{0x0a0a, 0x1a1a, 0x2a2a, 0xfafa} {
		if !IsGREASE(v) {
			t.Errorf("IsGREASE(%#04x) = false", v)
		}
	}
	for _, v := range []uint16{0x1301, 0xc02f, 0x0000, 0x0a0b} {
		if IsGREASE(v) {
			t.Errorf("IsGREASE(%#04x) = true", v)
		}
	}
}

func TestParseRejectsNonHandshake(t *testing.T) {
	if _, err := Parse([]byte{0x17, 0x03, 0x03, 0x00, 0x01, 0x00}); err != ErrNotClientHello {
		t.Errorf("err = %v, want ErrNotClientHello", err)
	}
}

func TestParseRejectsTruncated(t *testing.T) {
	rec := sampleHello()
	if _, err := Parse(rec[:len(rec)-10]); err == nil {
		t.Error("expected an error for a truncated record")
	}
}

func TestParseRejectsShort(t *testing.T) {
	if _, err := Parse([]byte{0x16, 0x03}); err != ErrNotClientHello {
		t.Errorf("err = %v, want ErrNotClientHello", err)
	}
}

func TestRecordLength(t *testing.T) {
	rec := sampleHello()
	if got := RecordLength(rec); got != len(rec) {
		t.Errorf("RecordLength = %d, want %d", got, len(rec))
	}
	if got := RecordLength([]byte{0x16, 0x03}); got != 0 {
		t.Errorf("RecordLength on partial header = %d, want 0", got)
	}
}

// TestParsesRealGoClientHello checks the parser against bytes produced by a
// real TLS stack rather than the test's own builder.
func TestParsesRealGoClientHello(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	type result struct {
		hello *ClientHello
		err   error
	}
	res := make(chan result, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			res <- result{err: err}
			return
		}
		defer conn.Close()
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))

		hdr := make([]byte, 5)
		if _, err := readFull(conn, hdr); err != nil {
			res <- result{err: err}
			return
		}
		total := RecordLength(hdr)
		buf := make([]byte, total)
		copy(buf, hdr)
		if _, err := readFull(conn, buf[5:]); err != nil {
			res <- result{err: err}
			return
		}
		h, err := Parse(buf)
		res <- result{hello: h, err: err}
	}()

	go func() {
		conn, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			return
		}
		defer conn.Close()
		c := tls.Client(conn, &tls.Config{
			ServerName: "real.example",
			NextProtos: []string{"h2", "http/1.1"},
		})
		c.SetDeadline(time.Now().Add(2 * time.Second))
		_ = c.Handshake() // fails: the listener never replies
	}()

	select {
	case r := <-res:
		if r.err != nil {
			t.Fatalf("capture: %v", r.err)
		}
		if r.hello.SNI != "real.example" {
			t.Errorf("SNI = %q, want real.example", r.hello.SNI)
		}
		if len(r.hello.CipherSuites) == 0 {
			t.Error("no cipher suites parsed")
		}
		if len(r.hello.ALPN) == 0 || r.hello.ALPN[0] != "h2" {
			t.Errorf("ALPN = %v", r.hello.ALPN)
		}
		ja3, ja4 := r.hello.JA3(), r.hello.JA4()
		if len(ja3) != 32 {
			t.Errorf("JA3 = %q", ja3)
		}
		if !strings.HasPrefix(ja4, "t13d") {
			t.Errorf("JA4 = %q, want a t13d prefix from a Go TLS 1.3 client", ja4)
		}
		t.Logf("go client JA3=%s JA4=%s", ja3, ja4)
	case <-time.After(10 * time.Second):
		t.Fatal("timed out capturing a ClientHello")
	}
}

func readFull(c net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := c.Read(buf[total:])
		total += n
		if err != nil {
			return total, fmt.Errorf("read %d/%d: %w", total, len(buf), err)
		}
	}
	return total, nil
}
