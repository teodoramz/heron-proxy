package proxy

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/amzteodor/proxy-waf/internal/config"
	"github.com/amzteodor/proxy-waf/internal/pipeline/blob"
	"github.com/amzteodor/proxy-waf/internal/pipeline/event"
	"github.com/amzteodor/proxy-waf/internal/proxy/router"
	"github.com/amzteodor/proxy-waf/internal/proxy/waf"
)

type captureSink struct {
	mu     sync.Mutex
	events []event.Event
}

func (c *captureSink) Submit(e event.Event) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, e)
}

func (c *captureSink) wait(t *testing.T) event.Event {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		c.mu.Lock()
		n := len(c.events)
		if n > 0 {
			e := c.events[n-1]
			c.mu.Unlock()
			return e
		}
		c.mu.Unlock()
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("no event was recorded")
	return event.Event{}
}

type harness struct {
	proxy    *httptest.Server
	upstream *httptest.Server
	sink     *captureSink
	app      *config.App
	blobs    *blob.Store
}

func newHarness(t *testing.T, upstream http.Handler, mutate func(*config.App)) *harness {
	t.Helper()
	up := httptest.NewServer(upstream)
	t.Cleanup(up.Close)

	app := config.App{
		ID:          "app1",
		Name:        "test",
		Hostnames:   []string{"app.example"},
		UpstreamURL: up.URL,
		Enabled:     true,
		Capture:     config.DefaultCapture(),
		Redaction:   config.DefaultRedaction(),
		WAF:         config.WAFPolicy{Enabled: false},
	}
	if mutate != nil {
		mutate(&app)
	}
	rt := router.New()
	rt.Replace([]config.App{app})
	resolved, _ := rt.Match("app.example")

	sink := &captureSink{}
	blobs := blob.New(t.TempDir())
	srv := New(Options{
		Router: rt,
		WAF:    waf.NewEngine(t.TempDir()),
		Sink:   sink,
		Blobs:  blobs,
	})
	ps := httptest.NewServer(srv)
	t.Cleanup(ps.Close)

	return &harness{proxy: ps, upstream: up, sink: sink, app: resolved, blobs: blobs}
}

// do sends a request through the proxy with the routed Host header.
func (h *harness) do(t *testing.T, req *http.Request) *http.Response {
	t.Helper()
	req.Host = "app.example"
	resp, err := h.proxy.Client().Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	return resp
}

func (h *harness) get(t *testing.T, path string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, h.proxy.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	return h.do(t, req)
}

func TestProxiesToUpstream(t *testing.T) {
	h := newHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Upstream", "yes")
		w.WriteHeader(http.StatusTeapot)
		io.WriteString(w, "hello from upstream")
	}), nil)

	resp := h.get(t, "/path?a=1")
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusTeapot {
		t.Errorf("status = %d, want 418", resp.StatusCode)
	}
	if string(body) != "hello from upstream" {
		t.Errorf("body = %q", body)
	}
	if resp.Header.Get("X-Upstream") != "yes" {
		t.Error("upstream response header not relayed")
	}
	if resp.Header.Get("X-Request-Id") == "" {
		t.Error("X-Request-Id not set on the response")
	}
}

func TestForwardedHeadersInjected(t *testing.T) {
	got := make(chan http.Header, 1)
	h := newHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- r.Header.Clone()
	}), nil)

	resp := h.get(t, "/")
	resp.Body.Close()

	hdr := <-got
	for _, name := range []string{"X-Real-Ip", "X-Forwarded-For", "X-Forwarded-Proto", "X-Forwarded-Host", "X-Request-Id"} {
		if hdr.Get(name) == "" {
			t.Errorf("%s not forwarded", name)
		}
	}
	if hdr.Get("X-Forwarded-Host") != "app.example" {
		t.Errorf("X-Forwarded-Host = %q", hdr.Get("X-Forwarded-Host"))
	}
	if hdr.Get("X-Real-Ip") != "127.0.0.1" {
		t.Errorf("X-Real-Ip = %q, want the TCP peer", hdr.Get("X-Real-Ip"))
	}
}

func TestCustomClientIPHeader(t *testing.T) {
	got := make(chan http.Header, 1)
	h := newHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- r.Header.Clone()
	}), func(a *config.App) { a.ClientIPHeader = "X-WAF-Client-IP" })

	h.get(t, "/").Body.Close()
	if v := (<-got).Get("X-WAF-Client-IP"); v != "127.0.0.1" {
		t.Errorf("custom header = %q", v)
	}
}

func TestSpoofedXFFNotBelieved(t *testing.T) {
	h := newHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}), nil)

	req, _ := http.NewRequest(http.MethodGet, h.proxy.URL+"/", nil)
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	h.do(t, req).Body.Close()

	e := h.sink.wait(t)
	if e.ClientIP.String() != "127.0.0.1" {
		t.Errorf("ClientIP = %s, want the TCP peer", e.ClientIP)
	}
	if e.ClientIPClaimed.String() != "1.2.3.4" {
		t.Errorf("ClientIPClaimed = %s, want the spoofed value preserved", e.ClientIPClaimed)
	}
}

func TestTrustedProxyXFFBelieved(t *testing.T) {
	h := newHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
		func(a *config.App) { a.TrustedCIDRs = []string{"127.0.0.0/8"} })

	req, _ := http.NewRequest(http.MethodGet, h.proxy.URL+"/", nil)
	req.Header.Set("X-Forwarded-For", "198.51.100.7")
	h.do(t, req).Body.Close()

	e := h.sink.wait(t)
	if e.ClientIP.String() != "198.51.100.7" {
		t.Errorf("ClientIP = %s, want the forwarded address", e.ClientIP)
	}
}

func TestHopByHopHeadersStripped(t *testing.T) {
	got := make(chan http.Header, 1)
	h := newHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- r.Header.Clone()
	}), nil)

	req, _ := http.NewRequest(http.MethodGet, h.proxy.URL+"/", nil)
	req.Header.Set("Connection", "X-Custom-Hop")
	req.Header.Set("X-Custom-Hop", "value")
	req.Header.Set("Proxy-Authorization", "secret")
	h.do(t, req).Body.Close()

	hdr := <-got
	for _, name := range []string{"X-Custom-Hop", "Proxy-Authorization", "Connection"} {
		if hdr.Get(name) != "" {
			t.Errorf("%s was forwarded: %q", name, hdr.Get(name))
		}
	}
}

func TestEventFieldsRecorded(t *testing.T) {
	h := newHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusCreated)
		io.WriteString(w, `{"ok":true}`)
	}), nil)

	h.get(t, "/api/items?page=2&sort=asc").Body.Close()

	e := h.sink.wait(t)
	if e.Method != http.MethodGet || e.Path != "/api/items" || e.Query != "page=2&sort=asc" {
		t.Errorf("request fields wrong: %+v", e)
	}
	if e.Host != "app.example" || e.AppID != "app1" {
		t.Errorf("routing fields wrong: host=%s app=%s", e.Host, e.AppID)
	}
	if e.Status != http.StatusCreated {
		t.Errorf("Status = %d", e.Status)
	}
	if e.RespContentType != "application/json" {
		t.Errorf("RespContentType = %q", e.RespContentType)
	}
	if e.RespSize != 11 {
		t.Errorf("RespSize = %d, want 11", e.RespSize)
	}
	if e.ID == "" || e.TS.IsZero() {
		t.Error("ID or TS unset")
	}
	if e.RetentionDays != 90 {
		t.Errorf("RetentionDays = %d", e.RetentionDays)
	}
}

func TestRequestBodyCaptured(t *testing.T) {
	var received string
	h := newHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		received = string(b)
	}), nil)

	req, _ := http.NewRequest(http.MethodPost, h.proxy.URL+"/submit", strings.NewReader("name=value"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.do(t, req).Body.Close()

	e := h.sink.wait(t)
	if e.ReqBody != "name=value" {
		t.Errorf("ReqBody = %q", e.ReqBody)
	}
	if e.ReqBodySize != 10 {
		t.Errorf("ReqBodySize = %d, want 10", e.ReqBodySize)
	}
	if received != "name=value" {
		t.Errorf("upstream received %q", received)
	}
	if e.ReqBodySHA == "" {
		t.Error("ReqBodySHA unset")
	}
}

func TestOversizedBodyTruncatedButForwardedWhole(t *testing.T) {
	const size = 20000
	var receivedLen int
	h := newHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		receivedLen = len(b)
	}), func(a *config.App) { a.Capture.BodyCapBytes = 1000 })

	payload := strings.Repeat("A", size)
	req, _ := http.NewRequest(http.MethodPost, h.proxy.URL+"/upload", strings.NewReader(payload))
	req.Header.Set("Content-Type", "text/plain")
	h.do(t, req).Body.Close()

	e := h.sink.wait(t)
	if !e.ReqTruncated {
		t.Error("ReqTruncated = false for an oversized body")
	}
	if e.ReqBodySize != size {
		t.Errorf("ReqBodySize = %d, want %d", e.ReqBodySize, size)
	}
	if receivedLen != size {
		t.Errorf("upstream received %d bytes, want the whole %d", receivedLen, size)
	}
}

func TestBodySpillsToBlobStore(t *testing.T) {
	h := newHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
	}), func(a *config.App) {
		a.Capture.InlineMaxBytes = 100
		a.Capture.BodyCapBytes = 100000
	})

	payload := strings.Repeat("B", 5000)
	req, _ := http.NewRequest(http.MethodPost, h.proxy.URL+"/upload", strings.NewReader(payload))
	req.Header.Set("Content-Type", "text/plain")
	h.do(t, req).Body.Close()

	e := h.sink.wait(t)
	if e.ReqBodyBlob == "" {
		t.Fatal("body was not spilled to the blob store")
	}
	if e.ReqBody != "" {
		t.Error("body stored inline as well as in the blob store")
	}
	stored, err := h.blobs.Get(e.ReqBodyBlob)
	if err != nil {
		t.Fatalf("blob Get: %v", err)
	}
	if string(stored) != payload {
		t.Error("blob content mismatch")
	}
}

func TestBinaryBodyStoresHashOnly(t *testing.T) {
	h := newHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
	}), nil)

	req, _ := http.NewRequest(http.MethodPost, h.proxy.URL+"/upload", strings.NewReader("\x89PNG\r\n\x1a\n binary"))
	req.Header.Set("Content-Type", "image/png")
	h.do(t, req).Body.Close()

	e := h.sink.wait(t)
	if e.ReqBody != "" || e.ReqBodyBlob != "" {
		t.Errorf("binary body was stored: inline=%q blob=%q", e.ReqBody, e.ReqBodyBlob)
	}
	if e.ReqBodySHA == "" {
		t.Error("binary body hash not recorded")
	}
}

func TestRedactionAppliedBeforeSubmit(t *testing.T) {
	h := newHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}), nil)

	req, _ := http.NewRequest(http.MethodPost, h.proxy.URL+"/login?token=abc123",
		strings.NewReader(`{"user":"a","password":"hunter2"}`))
	req.Header.Set("Authorization", "Bearer supersecret")
	req.Header.Set("Content-Type", "application/json")
	h.do(t, req).Body.Close()

	e := h.sink.wait(t)
	if e.ReqHeaders["authorization"] != "[REDACTED]" {
		t.Errorf("Authorization = %q", e.ReqHeaders["authorization"])
	}
	if strings.Contains(e.Query, "abc123") {
		t.Errorf("query token not redacted: %q", e.Query)
	}
	if strings.Contains(e.ReqBody, "hunter2") {
		t.Errorf("body password not redacted: %q", e.ReqBody)
	}
}

func TestUnknownHostReturns421AndIsRecorded(t *testing.T) {
	h := newHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}), nil)

	req, _ := http.NewRequest(http.MethodGet, h.proxy.URL+"/", nil)
	req.Host = "unconfigured.example"
	resp, err := h.proxy.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusMisdirectedRequest {
		t.Errorf("status = %d, want 421", resp.StatusCode)
	}
	e := h.sink.wait(t)
	if e.AppID != "" || e.Error == "" {
		t.Errorf("unrouted event wrong: app=%q err=%q", e.AppID, e.Error)
	}
	if e.Host != "unconfigured.example" {
		t.Errorf("Host = %q", e.Host)
	}
}

func TestUpstreamFailureRecorded(t *testing.T) {
	h := newHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}), nil)
	h.upstream.Close() // make the upstream unreachable

	resp := h.get(t, "/")
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", resp.StatusCode)
	}
	if e := h.sink.wait(t); e.Error == "" {
		t.Error("upstream error not recorded")
	}
}

func TestWAFRecordsMatchedRules(t *testing.T) {
	h := newHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
		func(a *config.App) { a.WAF = config.DefaultWAF() })

	h.get(t, "/search?id=1%27%20OR%20%271%27%3D%271%20--%20").Body.Close()

	e := h.sink.wait(t)
	if len(e.RuleIDs) == 0 {
		t.Fatalf("no rules recorded: %+v", e)
	}
	if e.AnomalyScore == 0 {
		t.Error("AnomalyScore = 0 for a SQLi payload")
	}
	if !e.WouldBlock {
		t.Error("WouldBlock = false for a SQLi payload at the default threshold")
	}
	if len(e.RuleTags) == 0 {
		t.Error("no rule tags recorded")
	}
}

func TestWAFDoesNotBlock(t *testing.T) {
	h := newHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "reached upstream")
	}), func(a *config.App) { a.WAF = config.DefaultWAF() })

	resp := h.get(t, "/search?id=1%27%20OR%20%271%27%3D%271%20--%20")
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK || string(body) != "reached upstream" {
		t.Errorf("detection mode blocked the request: status=%d body=%q", resp.StatusCode, body)
	}
}

func TestCaptureDisabledSkipsBody(t *testing.T) {
	h := newHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
	}), func(a *config.App) { a.Capture.Enabled = false })

	req, _ := http.NewRequest(http.MethodPost, h.proxy.URL+"/x", strings.NewReader("secret payload"))
	h.do(t, req).Body.Close()

	if e := h.sink.wait(t); e.ReqBody != "" {
		t.Errorf("body captured with capture disabled: %q", e.ReqBody)
	}
}

func TestSkipPathsExcludeBody(t *testing.T) {
	h := newHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
	}), func(a *config.App) { a.Capture.SkipPaths = []string{"/static/*"} })

	req, _ := http.NewRequest(http.MethodPost, h.proxy.URL+"/static/upload", strings.NewReader("data"))
	h.do(t, req).Body.Close()

	if e := h.sink.wait(t); e.ReqBody != "" {
		t.Errorf("body captured for a skipped path: %q", e.ReqBody)
	}
}

func TestPreserveHost(t *testing.T) {
	got := make(chan string, 1)
	h := newHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- r.Host
	}), func(a *config.App) { a.PreserveHost = true })

	h.get(t, "/").Body.Close()
	if v := <-got; v != "app.example" {
		t.Errorf("upstream Host = %q, want the original", v)
	}
}

func TestRewritesHostByDefault(t *testing.T) {
	got := make(chan string, 1)
	h := newHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- r.Host
	}), nil)

	h.get(t, "/").Body.Close()
	if v := <-got; v == "app.example" {
		t.Error("Host was preserved without PreserveHost")
	}
}

// TestResponseIsStreamedNotBuffered proves the proxy relays chunks as they
// arrive rather than waiting for the upstream to finish.
func TestResponseIsStreamedNotBuffered(t *testing.T) {
	release := make(chan struct{})
	h := newHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rc := http.NewResponseController(w)
		io.WriteString(w, "first-chunk\n")
		rc.Flush()
		<-release
		io.WriteString(w, "second-chunk\n")
	}), nil)

	resp := h.get(t, "/stream")
	defer resp.Body.Close()

	line, err := bufio.NewReader(resp.Body).ReadString('\n')
	if err != nil {
		t.Fatalf("reading first chunk: %v", err)
	}
	if strings.TrimSpace(line) != "first-chunk" {
		t.Errorf("first chunk = %q", line)
	}
	close(release)
}

// TestWebSocketRelay runs a real upgrade through the proxy against a raw
// websocket-style upstream that echoes bytes.
func TestWebSocketRelay(t *testing.T) {
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isWebSocketUpgrade(r) {
			http.Error(w, "expected upgrade", http.StatusBadRequest)
			return
		}
		conn, _, err := http.NewResponseController(w).Hijack()
		if err != nil {
			t.Errorf("upstream hijack: %v", err)
			return
		}
		defer conn.Close()
		fmt.Fprint(conn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		io.Copy(conn, conn)
	})
	h := newHarness(t, upstream, nil)

	addr := strings.TrimPrefix(h.proxy.URL, "http://")
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	fmt.Fprint(conn, "GET /ws HTTP/1.1\r\nHost: app.example\r\nUpgrade: websocket\r\n"+
		"Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("reading upgrade response: %v", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d, want 101", resp.StatusCode)
	}

	fmt.Fprint(conn, "ping")
	buf := make([]byte, 4)
	if _, err := io.ReadFull(br, buf); err != nil {
		t.Fatalf("reading echo: %v", err)
	}
	if string(buf) != "ping" {
		t.Errorf("echo = %q", buf)
	}
	conn.Close()

	e := h.sink.wait(t)
	if !e.IsWebsocket {
		t.Error("IsWebsocket = false")
	}
	if e.Status != http.StatusSwitchingProtocols {
		t.Errorf("Status = %d, want 101", e.Status)
	}
}
