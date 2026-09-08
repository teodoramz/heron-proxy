// Package ja3 parses a TLS ClientHello and derives JA3 and JA4 fingerprints.
//
// Go's crypto/tls does not expose extension ordering, which both fingerprints
// depend on, so the proxy peeks the raw handshake bytes and parses them here.
package ja3

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	recordHandshake  = 0x16
	handshakeHello   = 0x01
	extServerName    = 0x0000
	extSupportedGrps = 0x000a
	extECPointFmts   = 0x000b
	extSigAlgs       = 0x000d
	extALPN          = 0x0010
	extSupportedVers = 0x002b
)

// ErrNotClientHello reports bytes that are not a TLS ClientHello record.
var ErrNotClientHello = errors.New("ja3: not a TLS ClientHello")

// ClientHello holds the fields both fingerprints are computed from.
type ClientHello struct {
	LegacyVersion       uint16
	SNI                 string
	CipherSuites        []uint16
	Extensions          []uint16
	SupportedGroups     []uint16
	ECPointFormats      []uint8
	SupportedVersions   []uint16
	SignatureAlgorithms []uint16
	ALPN                []string
}

// IsGREASE reports whether a value is a GREASE placeholder (RFC 8701).
func IsGREASE(v uint16) bool {
	return v&0x0f0f == 0x0a0a && byte(v>>8) == byte(v)
}

// RecordLength returns the total byte length of the TLS record starting at b,
// or 0 if b does not yet hold a complete record header.
func RecordLength(b []byte) int {
	if len(b) < 5 {
		return 0
	}
	return 5 + int(binary.BigEndian.Uint16(b[3:5]))
}

// Parse reads a ClientHello from a complete TLS record.
func Parse(record []byte) (*ClientHello, error) {
	if len(record) < 5 || record[0] != recordHandshake {
		return nil, ErrNotClientHello
	}
	length := int(binary.BigEndian.Uint16(record[3:5]))
	if len(record) < 5+length {
		return nil, fmt.Errorf("ja3: truncated record: have %d, need %d", len(record), 5+length)
	}
	return parseHandshake(record[5 : 5+length])
}

func parseHandshake(b []byte) (*ClientHello, error) {
	c := &cursor{b: b}
	msgType, err := c.u8()
	if err != nil || msgType != handshakeHello {
		return nil, ErrNotClientHello
	}
	bodyLen, err := c.u24()
	if err != nil {
		return nil, ErrNotClientHello
	}
	body, err := c.take(int(bodyLen))
	if err != nil {
		return nil, fmt.Errorf("ja3: truncated handshake body: %w", err)
	}
	return parseHelloBody(body)
}

func parseHelloBody(b []byte) (*ClientHello, error) {
	c := &cursor{b: b}
	h := &ClientHello{}

	var err error
	if h.LegacyVersion, err = c.u16(); err != nil {
		return nil, fmt.Errorf("ja3: version: %w", err)
	}
	if _, err = c.take(32); err != nil {
		return nil, fmt.Errorf("ja3: random: %w", err)
	}
	if err = c.skipVector(1); err != nil {
		return nil, fmt.Errorf("ja3: session id: %w", err)
	}

	ciphers, err := c.vector(2)
	if err != nil {
		return nil, fmt.Errorf("ja3: cipher suites: %w", err)
	}
	h.CipherSuites = toUint16s(ciphers)

	if err = c.skipVector(1); err != nil {
		return nil, fmt.Errorf("ja3: compression methods: %w", err)
	}
	if c.remaining() == 0 {
		return h, nil
	}
	exts, err := c.vector(2)
	if err != nil {
		return nil, fmt.Errorf("ja3: extensions: %w", err)
	}
	if err := h.parseExtensions(exts); err != nil {
		return nil, err
	}
	return h, nil
}

func (h *ClientHello) parseExtensions(b []byte) error {
	c := &cursor{b: b}
	for c.remaining() > 0 {
		extType, err := c.u16()
		if err != nil {
			return fmt.Errorf("ja3: extension type: %w", err)
		}
		data, err := c.vector(2)
		if err != nil {
			return fmt.Errorf("ja3: extension %d body: %w", extType, err)
		}
		h.Extensions = append(h.Extensions, extType)

		switch extType {
		case extServerName:
			h.SNI = parseSNI(data)
		case extSupportedGrps:
			if v, err := (&cursor{b: data}).vector(2); err == nil {
				h.SupportedGroups = toUint16s(v)
			}
		case extECPointFmts:
			if v, err := (&cursor{b: data}).vector(1); err == nil {
				h.ECPointFormats = append(h.ECPointFormats, v...)
			}
		case extSigAlgs:
			if v, err := (&cursor{b: data}).vector(2); err == nil {
				h.SignatureAlgorithms = toUint16s(v)
			}
		case extSupportedVers:
			if v, err := (&cursor{b: data}).vector(1); err == nil {
				h.SupportedVersions = toUint16s(v)
			}
		case extALPN:
			h.ALPN = parseALPN(data)
		}
	}
	return nil
}

func parseSNI(b []byte) string {
	list, err := (&cursor{b: b}).vector(2)
	if err != nil {
		return ""
	}
	c := &cursor{b: list}
	for c.remaining() > 0 {
		nameType, err := c.u8()
		if err != nil {
			return ""
		}
		name, err := c.vector(2)
		if err != nil {
			return ""
		}
		if nameType == 0 {
			return string(name)
		}
	}
	return ""
}

func parseALPN(b []byte) []string {
	list, err := (&cursor{b: b}).vector(2)
	if err != nil {
		return nil
	}
	c := &cursor{b: list}
	var out []string
	for c.remaining() > 0 {
		proto, err := c.vector(1)
		if err != nil {
			return out
		}
		out = append(out, string(proto))
	}
	return out
}

func toUint16s(b []byte) []uint16 {
	out := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		out = append(out, binary.BigEndian.Uint16(b[i:i+2]))
	}
	return out
}

// cursor reads big-endian TLS structures with bounds checking.
type cursor struct {
	b []byte
	i int
}

func (c *cursor) remaining() int { return len(c.b) - c.i }

func (c *cursor) take(n int) ([]byte, error) {
	if n < 0 || c.remaining() < n {
		return nil, fmt.Errorf("ja3: want %d bytes, have %d", n, c.remaining())
	}
	out := c.b[c.i : c.i+n]
	c.i += n
	return out, nil
}

func (c *cursor) u8() (uint8, error) {
	b, err := c.take(1)
	if err != nil {
		return 0, err
	}
	return b[0], nil
}

func (c *cursor) u16() (uint16, error) {
	b, err := c.take(2)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(b), nil
}

func (c *cursor) u24() (uint32, error) {
	b, err := c.take(3)
	if err != nil {
		return 0, err
	}
	return uint32(b[0])<<16 | uint32(b[1])<<8 | uint32(b[2]), nil
}

// vector reads a length-prefixed block whose length field is lenBytes wide.
func (c *cursor) vector(lenBytes int) ([]byte, error) {
	var n int
	switch lenBytes {
	case 1:
		v, err := c.u8()
		if err != nil {
			return nil, err
		}
		n = int(v)
	case 2:
		v, err := c.u16()
		if err != nil {
			return nil, err
		}
		n = int(v)
	default:
		return nil, fmt.Errorf("ja3: unsupported length prefix %d", lenBytes)
	}
	return c.take(n)
}

func (c *cursor) skipVector(lenBytes int) error {
	_, err := c.vector(lenBytes)
	return err
}
