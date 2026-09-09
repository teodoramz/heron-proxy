// Package tlsx provides a listener that fingerprints the TLS ClientHello before
// the handshake, and a certificate store that can be swapped without a restart.
package tlsx

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"sync"

	"github.com/amzteodor/heron/internal/proxy/ja3"
)

const maxHelloRecord = 5 + 65536

// Fingerprint identifies a client's TLS stack.
type Fingerprint struct {
	JA3       string `json:"ja3"`
	JA3String string `json:"ja3_string"`
	JA4       string `json:"ja4"`
	SNI       string `json:"sni"`
}

// Conn buffers the first TLS record so it can be fingerprinted and then replayed
// to the handshake unchanged.
type Conn struct {
	net.Conn

	mu     sync.Mutex
	fp     Fingerprint
	peeked bool
	buf    []byte
	off    int
}

// NewListener wraps a listener so every accepted connection is fingerprinted.
func NewListener(inner net.Listener) net.Listener { return &listener{Listener: inner} }

type listener struct{ net.Listener }

func (l *listener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &Conn{Conn: c}, nil
}

// Read replays the peeked bytes before returning live data.
func (c *Conn) Read(p []byte) (int, error) {
	c.mu.Lock()
	if !c.peeked {
		c.peekLocked()
	}
	if c.off < len(c.buf) {
		n := copy(p, c.buf[c.off:])
		c.off += n
		c.mu.Unlock()
		return n, nil
	}
	c.mu.Unlock()
	return c.Conn.Read(p)
}

// Fingerprint returns the client fingerprint, zero-valued if the first record
// was not a parseable ClientHello.
func (c *Conn) Fingerprint() Fingerprint {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.fp
}

// peekLocked reads the first TLS record into the replay buffer. Any failure
// leaves the bytes read so far in the buffer so the handshake still sees them.
func (c *Conn) peekLocked() {
	c.peeked = true

	hdr := make([]byte, 5)
	n, err := io.ReadFull(c.Conn, hdr)
	c.buf = hdr[:n]
	if err != nil {
		return
	}
	total := ja3.RecordLength(hdr)
	if total <= 5 || total > maxHelloRecord {
		return
	}
	full := make([]byte, total)
	copy(full, hdr)
	n, err = io.ReadFull(c.Conn, full[5:])
	c.buf = full[:5+n]
	if err != nil {
		return
	}
	hello, err := ja3.Parse(full)
	if err != nil {
		return
	}
	c.fp = Fingerprint{
		JA3:       hello.JA3(),
		JA3String: hello.JA3String(),
		JA4:       hello.JA4(),
		SNI:       hello.SNI,
	}
}

type ctxKey struct{}

// ConnContext is an http.Server ConnContext hook that carries the fingerprinted
// connection into each request context.
func ConnContext(ctx context.Context, c net.Conn) context.Context {
	switch v := c.(type) {
	case *Conn:
		return context.WithValue(ctx, ctxKey{}, v)
	case *tls.Conn:
		if inner, ok := v.NetConn().(*Conn); ok {
			return context.WithValue(ctx, ctxKey{}, inner)
		}
	}
	return ctx
}

// FingerprintFromContext returns the fingerprint recorded for the request's connection.
func FingerprintFromContext(ctx context.Context) (Fingerprint, bool) {
	c, ok := ctx.Value(ctxKey{}).(*Conn)
	if !ok {
		return Fingerprint{}, false
	}
	return c.Fingerprint(), true
}
