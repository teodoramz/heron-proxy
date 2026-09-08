package proxy

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
)

// hopByHop headers are consumed by this proxy and never forwarded.
var hopByHop = []string{
	"Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization",
	"Te", "Trailer", "Transfer-Encoding", "Upgrade",
}

// stripHopByHop removes hop-by-hop headers, including any listed in Connection.
func stripHopByHop(h http.Header) {
	for _, v := range h.Values("Connection") {
		for _, name := range strings.Split(v, ",") {
			if name = strings.TrimSpace(name); name != "" {
				h.Del(name)
			}
		}
	}
	for _, name := range hopByHop {
		h.Del(name)
	}
}

// headerMap flattens headers for storage, joining repeats with a comma.
func headerMap(h http.Header) map[string]string {
	out := make(map[string]string, len(h))
	for name, values := range h {
		out[strings.ToLower(name)] = strings.Join(values, ", ")
	}
	return out
}

// bodyCapture holds the leading bytes of a request body and counts the total,
// so oversized bodies still stream to the upstream while only the cap is kept.
type bodyCapture struct {
	head      []byte
	truncated bool
	total     atomic.Uint64
}

// captureBody reads up to limit bytes and returns a reader that replays them
// followed by the remainder of the original body.
func captureBody(body io.ReadCloser, limit int64) (*bodyCapture, io.ReadCloser) {
	c := &bodyCapture{}
	if body == nil || limit <= 0 {
		return c, http.NoBody
	}
	head, err := io.ReadAll(io.LimitReader(body, limit))
	c.head = head
	c.total.Store(uint64(len(head)))
	if err != nil {
		body.Close()
		return c, io.NopCloser(bytes.NewReader(head))
	}
	// Probe one byte past the cap to learn whether anything was left behind.
	probe := make([]byte, 1)
	n, _ := io.ReadFull(body, probe)
	if n == 0 {
		body.Close()
		return c, io.NopCloser(bytes.NewReader(head))
	}
	c.truncated = true
	// The probe byte is replayed through the counting reader, so it is counted
	// there rather than here.
	rest := &countingReader{r: io.MultiReader(bytes.NewReader(probe[:n]), body), c: c}
	return c, &multiReadCloser{
		Reader: io.MultiReader(bytes.NewReader(head), rest),
		closer: body,
	}
}

// Body returns the captured prefix.
func (c *bodyCapture) Body() []byte { return c.head }

// Total returns the number of body bytes seen so far.
func (c *bodyCapture) Total() uint64 { return c.total.Load() }

// Truncated reports whether the body exceeded the capture cap.
func (c *bodyCapture) Truncated() bool { return c.truncated }

type countingReader struct {
	r io.Reader
	c *bodyCapture
}

func (cr *countingReader) Read(p []byte) (int, error) {
	n, err := cr.r.Read(p)
	if n > 0 {
		cr.c.total.Add(uint64(n))
	}
	return n, err
}

type multiReadCloser struct {
	io.Reader
	closer io.Closer
}

func (m *multiReadCloser) Close() error { return m.closer.Close() }

// countingWriter tracks how many response bytes were relayed.
type countingWriter struct {
	w io.Writer
	n uint64
}

func (cw *countingWriter) Write(p []byte) (int, error) {
	n, err := cw.w.Write(p)
	cw.n += uint64(n)
	return n, err
}
