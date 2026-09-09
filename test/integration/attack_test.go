// Package integration exercises the proxy end to end: a real request goes
// through TLS-less HTTP, the WAF, the spool and into ClickHouse, and is then
// read back through the query layer.
package integration

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/amzteodor/proxy-waf/internal/api/query"
	"github.com/amzteodor/proxy-waf/internal/api/reader"
	"github.com/amzteodor/proxy-waf/internal/config"
	"github.com/amzteodor/proxy-waf/internal/pipeline"
	"github.com/amzteodor/proxy-waf/internal/pipeline/blob"
	"github.com/amzteodor/proxy-waf/internal/pipeline/chsink"
	"github.com/amzteodor/proxy-waf/internal/pipeline/event"
	"github.com/amzteodor/proxy-waf/internal/pipeline/spool"
	"github.com/amzteodor/proxy-waf/internal/proxy"
	"github.com/amzteodor/proxy-waf/internal/proxy/router"
	"github.com/amzteodor/proxy-waf/internal/proxy/waf"
)

type stack struct {
	proxy    *httptest.Server
	upstream *httptest.Server
	reader   *reader.Reader
	pipeline *pipeline.Pipeline
	appID    string
}

// newStack wires the real proxy to a real ClickHouse through the real pipeline.
func newStack(t *testing.T) *stack {
	t.Helper()
	return newStackWithUpstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "upstream saw %s %s", r.Method, r.URL.Path)
	}))
}

// newStackWithUpstream is newStack with a caller-supplied upstream handler.
func newStackWithUpstream(t *testing.T, handler http.Handler) *stack {
	t.Helper()
	dsn := os.Getenv("CLICKHOUSE_TEST_DSN")
	if dsn == "" {
		t.Skip("CLICKHOUSE_TEST_DSN not set")
	}
	ctx := context.Background()

	ch, err := chsink.Open(dsn)
	if err != nil {
		t.Fatalf("chsink.Open: %v", err)
	}
	t.Cleanup(func() { ch.Close() })
	if err := ch.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	appID := fmt.Sprintf("it-%d", time.Now().UnixNano())

	upstream := httptest.NewServer(handler)
	t.Cleanup(upstream.Close)

	rt := router.New()
	rt.Replace([]config.App{{
		ID:          appID,
		Name:        appID,
		Hostnames:   []string{"app.test"},
		UpstreamURL: upstream.URL,
		Enabled:     true,
		Capture:     config.DefaultCapture(),
		Redaction:   config.DefaultRedaction(),
		WAF:         config.DefaultWAF(),
	}})

	sp, err := spool.Open(t.TempDir(), spool.Options{SegmentBytes: 8 << 20, MaxBytes: 64 << 20})
	if err != nil {
		t.Fatalf("spool.Open: %v", err)
	}
	t.Cleanup(func() { sp.Close() })

	pipe := pipeline.New(sp, &chSink{ch}, pipeline.Options{BatchInterval: 50 * time.Millisecond})
	pipe.Start(ctx)
	t.Cleanup(func() { pipe.Close() })

	srv := httptest.NewServer(proxy.New(proxy.Options{
		Router: rt,
		WAF:    waf.NewEngine(t.TempDir()),
		Sink:   pipe,
		Blobs:  blob.New(t.TempDir()),
	}))
	t.Cleanup(srv.Close)

	return &stack{proxy: srv, upstream: upstream, reader: reader.New(ch.Conn()), pipeline: pipe, appID: appID}
}

type chSink struct{ w *chsink.Writer }

func (c *chSink) WriteBatch(ctx context.Context, events []event.Event) error {
	return c.w.WriteBatch(ctx, events)
}

// send issues a request through the proxy with the routed Host header.
func (s *stack) send(t *testing.T, method, target, body string) *http.Response {
	t.Helper()
	var reader *strings.Reader
	if body != "" {
		reader = strings.NewReader(body)
	} else {
		reader = strings.NewReader("")
	}
	req, err := http.NewRequest(method, s.proxy.URL+target, reader)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "app.test"
	req.Header.Set("User-Agent", "integration-test")
	if body != "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	resp, err := s.proxy.Client().Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, target, err)
	}
	return resp
}

// waitForEvents polls until the expected number of events for this app is
// queryable, so the assertions never race the shipper.
func (s *stack) waitForEvents(t *testing.T, want int) []event.Event {
	t.Helper()
	f := query.Filter{
		From: time.Now().Add(-10 * time.Minute),
		To:   time.Now().Add(time.Minute),
		Apps: []string{s.appID},
		Root: query.Group{Op: "and"},
	}
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		page, err := s.reader.List(context.Background(), f)
		if err == nil && len(page.Events) >= want {
			return page.Events
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("only saw fewer than %d events within 20s", want)
	return nil
}

func hasRule(e event.Event, prefix string) bool {
	for _, id := range e.RuleIDs {
		if strings.HasPrefix(fmt.Sprint(id), prefix) {
			return true
		}
	}
	return false
}

// TestAttackPayloadsReachClickHouse is the full-path assertion: a hostile
// request is proxied, detected, spooled, shipped and read back with the CRS
// rule that caught it.
func TestAttackPayloadsReachClickHouse(t *testing.T) {
	s := newStack(t)

	cases := []struct {
		name   string
		target string
		prefix string
	}{
		{"sqli", "/search?id=1%27%20OR%20%271%27%3D%271%20--%20", "942"},
		{"xss", "/q?s=%3Cscript%3Ealert%281%29%3C%2Fscript%3E", "941"},
		{"traversal", "/static?file=../../../../etc/passwd", "930"},
	}
	for _, c := range cases {
		resp := s.send(t, http.MethodGet, c.target, "")
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: proxy returned %d; detection mode must not block", c.name, resp.StatusCode)
		}
	}
	// One clean request, so the assertions can tell detection from noise.
	s.send(t, http.MethodGet, "/index.html", "").Body.Close()

	events := s.waitForEvents(t, 4)
	byPath := make(map[string]event.Event, len(events))
	for _, e := range events {
		byPath[e.Path] = e
	}

	for _, c := range cases {
		path := strings.SplitN(c.target, "?", 2)[0]
		e, ok := byPath[path]
		if !ok {
			t.Errorf("%s: no event recorded for %s", c.name, path)
			continue
		}
		if !hasRule(e, c.prefix) {
			t.Errorf("%s: expected a %sxxx rule, got %v", c.name, c.prefix, e.RuleIDs)
		}
		if e.AnomalyScore == 0 {
			t.Errorf("%s: anomaly score is zero", c.name)
		}
		if !e.WouldBlock {
			t.Errorf("%s: would_block is false at the default threshold", c.name)
		}
	}

	clean, ok := byPath["/index.html"]
	if !ok {
		t.Fatal("the clean request was not recorded")
	}
	if len(clean.RuleIDs) != 0 || clean.WouldBlock {
		t.Errorf("clean request flagged: rules=%v block=%v", clean.RuleIDs, clean.WouldBlock)
	}
	if clean.Status != http.StatusOK || clean.Method != http.MethodGet {
		t.Errorf("clean event fields wrong: %+v", clean)
	}
}

func TestBodyAttackDetectedAndStored(t *testing.T) {
	s := newStack(t)

	body := "comment=%3Cscript%3Ealert%281%29%3C%2Fscript%3E"
	resp := s.send(t, http.MethodPost, "/comment", body)
	resp.Body.Close()

	events := s.waitForEvents(t, 1)
	e := events[0]

	if !hasRule(e, "941") {
		t.Errorf("request body not inspected: %v", e.RuleIDs)
	}
	if e.ReqBodySize != uint64(len(body)) {
		t.Errorf("ReqBodySize = %d, want %d", e.ReqBodySize, len(body))
	}

	// The list projection omits bodies by design; the detail query carries them.
	detail, err := s.reader.Get(context.Background(), e.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if detail.ReqBody == "" {
		t.Error("request body not stored")
	}
}

func TestRedactionAppliesEndToEnd(t *testing.T) {
	s := newStack(t)

	req, _ := http.NewRequest(http.MethodPost, s.proxy.URL+"/login?token=super-secret-token",
		strings.NewReader("user=a&password=hunter2"))
	req.Host = "app.test"
	req.Header.Set("Authorization", "Bearer another-secret")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := s.proxy.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	events := s.waitForEvents(t, 1)
	e := events[0]

	detail, err := s.reader.Get(context.Background(), e.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if strings.Contains(detail.Query, "super-secret-token") {
		t.Errorf("query token stored in the clear: %q", detail.Query)
	}
	if strings.Contains(detail.ReqBody, "hunter2") {
		t.Errorf("password stored in the clear: %q", detail.ReqBody)
	}
	if detail.ReqHeaders["authorization"] != "[REDACTED]" {
		t.Errorf("authorization header = %q", detail.ReqHeaders["authorization"])
	}
}

func TestForwardedHeadersReachUpstream(t *testing.T) {
	dsn := os.Getenv("CLICKHOUSE_TEST_DSN")
	if dsn == "" {
		t.Skip("CLICKHOUSE_TEST_DSN not set")
	}
	seen := make(chan http.Header, 1)
	s := newStackWithUpstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))

	s.send(t, http.MethodGet, "/probe", "").Body.Close()

	select {
	case h := <-seen:
		for _, name := range []string{"X-Real-Ip", "X-Forwarded-For", "X-Forwarded-Proto", "X-Request-Id"} {
			if h.Get(name) == "" {
				t.Errorf("%s not forwarded", name)
			}
		}
	case <-time.After(5 * time.Second):
		t.Fatal("upstream never received the request")
	}
}
