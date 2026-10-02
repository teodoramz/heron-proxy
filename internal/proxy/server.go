// Package proxy implements the TLS-terminating reverse proxy that evaluates
// every request against the WAF and records it.
package proxy

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/amzteodor/heron/internal/config"
	"github.com/amzteodor/heron/internal/pipeline/blob"
	"github.com/amzteodor/heron/internal/pipeline/event"
	"github.com/amzteodor/heron/internal/pipeline/redact"
	"github.com/amzteodor/heron/internal/proxy/router"
	"github.com/amzteodor/heron/internal/proxy/tlsx"
	"github.com/amzteodor/heron/internal/proxy/waf"
)

// Sink receives recorded events.
type Sink interface {
	Submit(event.Event)
}

// Enricher annotates an event with geo and network intelligence.
type Enricher interface {
	Apply(*event.Event)
}

// Options configures a Server.
type Options struct {
	Router   *router.Router
	WAF      *waf.Engine
	Sink     Sink
	Blobs    *blob.Store
	Enricher Enricher
	Logger   *slog.Logger

	UpstreamTimeout time.Duration
	IdleTimeout     time.Duration
}

// Server proxies requests to configured upstreams.
type Server struct {
	opts Options
	log  *slog.Logger

	verifying *http.Transport
	insecure  *http.Transport
}

// New builds a Server.
func New(o Options) *Server {
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	if o.UpstreamTimeout == 0 {
		o.UpstreamTimeout = 30 * time.Second
	}
	if o.IdleTimeout == 0 {
		o.IdleTimeout = 90 * time.Second
	}
	return &Server{
		opts:      o,
		log:       o.Logger,
		verifying: newTransport(o, false),
		insecure:  newTransport(o, true),
	}
}

func newTransport(o Options, skipVerify bool) *http.Transport {
	return &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: skipVerify},
		MaxIdleConns:          512,
		MaxIdleConnsPerHost:   64,
		IdleConnTimeout:       o.IdleTimeout,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
		ForceAttemptHTTP2:     false,
	}
}

func (s *Server) transportFor(app *config.App) *http.Transport {
	if app.UpstreamTLSVerify {
		return s.verifying
	}
	return s.insecure
}

// ServeHTTP handles one proxied request.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	id := uuid.NewString()

	app, ok := s.opts.Router.Match(r.Host)
	if !ok {
		s.recordUnrouted(r, id, start)
		http.Error(w, "unknown host", http.StatusMisdirectedRequest)
		return
	}
	if isWebSocketUpgrade(r) {
		s.serveWebSocket(w, r, app, id, start)
		return
	}
	s.serveHTTP(w, r, app, id, start)
}

func (s *Server) serveHTTP(w http.ResponseWriter, r *http.Request, app *config.App, id string, start time.Time) {
	e := s.newEvent(r, app, id, start)

	capture := app.Capture
	limit := capture.BodyCapBytes
	if !capture.Enabled || skipPath(capture.SkipPaths, r.URL.Path) {
		limit = 0
	}
	body, upstreamBody := captureBody(r.Body, limit)

	var tx *waf.Tx
	if app.WAF.Enabled {
		var err error
		tx, err = s.opts.WAF.NewTransaction(app.WAF, int(max64(limit, 1<<20)), id)
		if err != nil {
			s.log.Error("waf transaction failed", "err", err, "app", app.ID)
		}
	}
	if tx != nil {
		defer tx.Close()
		tx.ProcessRequest(r, e.ClientIP.String(), int(e.ClientPort), localAddr(r), localPort(r))
		tx.WriteRequestBody(body.Body())
		tx.ProcessRequestBody()

		// The verdict is taken before forwarding, from the same anomaly score
		// the simulator reports, so enforcing does what the simulation said.
		if app.WAF.Blocks() && tx.Interim().WouldBlock {
			e.Blocked = true
			e.Error = "rejected: anomaly score reached this application's threshold"
			s.reject(w, e.ID)
			s.finish(&e, tx, body, http.StatusForbidden, w.Header(), 0, start, time.Time{})
			return
		}
	}

	outReq, err := s.buildUpstreamRequest(r, app, upstreamBody, e)
	if err != nil {
		e.Error = err.Error()
		s.finish(&e, tx, body, 0, http.Header{}, 0, start, time.Time{})
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}
	e.Upstream = outReq.URL.String()

	upstreamStart := time.Now()
	resp, err := s.transportFor(app).RoundTrip(outReq)
	if err != nil {
		e.Error = err.Error()
		s.finish(&e, tx, body, 0, http.Header{}, 0, start, upstreamStart)
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	if tx != nil {
		tx.ProcessResponseHeaders(resp.StatusCode, resp.Proto, resp.Header)
	}

	respHeaders := resp.Header.Clone()
	copyHeader(w.Header(), resp.Header)
	stripHopByHop(w.Header())
	w.Header().Set("X-Request-Id", id)
	w.WriteHeader(resp.StatusCode)

	written := s.stream(w, resp)
	s.finish(&e, tx, body, resp.StatusCode, respHeaders, written, start, upstreamStart)
}

// reject answers a request the policy refuses to forward. The request id is
// returned so whoever was blocked can be told what to quote.
func (s *Server) reject(w http.ResponseWriter, id string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Request-Id", id)
	w.WriteHeader(http.StatusForbidden)
	_, _ = fmt.Fprintf(w, "Request rejected.\nReference: %s\n", id)
}

// stream relays the response body without buffering it.
func (s *Server) stream(w http.ResponseWriter, resp *http.Response) uint64 {
	cw := &countingWriter{w: w}
	if resp.Header.Get("Content-Length") == "" {
		// Length-less responses may be streaming, so flush as data arrives.
		rc := http.NewResponseController(w)
		buf := make([]byte, 32<<10)
		for {
			n, err := resp.Body.Read(buf)
			if n > 0 {
				if _, werr := cw.Write(buf[:n]); werr != nil {
					break
				}
				_ = rc.Flush()
			}
			if err != nil {
				break
			}
		}
		return cw.n
	}
	_, _ = io.Copy(cw, resp.Body)
	return cw.n
}

func (s *Server) buildUpstreamRequest(r *http.Request, app *config.App, body io.ReadCloser, e event.Event) (*http.Request, error) {
	target, err := url.Parse(app.UpstreamURL)
	if err != nil {
		return nil, fmt.Errorf("invalid upstream url %q: %w", app.UpstreamURL, err)
	}
	if target.Host == "" {
		return nil, fmt.Errorf("upstream url %q has no host", app.UpstreamURL)
	}
	out := r.Clone(r.Context())
	out.RequestURI = ""
	out.URL.Scheme = target.Scheme
	out.URL.Host = target.Host
	out.URL.Path = joinPath(target.Path, r.URL.Path)
	out.Body = body
	out.ContentLength = -1
	out.Close = false

	stripHopByHop(out.Header)
	if app.PreserveHost {
		out.Host = r.Host
	} else {
		out.Host = target.Host
	}

	header := app.ClientIPHeader
	if header == "" {
		header = "X-Real-IP"
	}
	out.Header.Set(header, e.ClientIP.String())
	out.Header.Set("X-Forwarded-For", appendForwarded(r.Header.Get("X-Forwarded-For"), e.ClientIP.String()))
	out.Header.Set("X-Forwarded-Proto", e.Scheme)
	out.Header.Set("X-Forwarded-Host", r.Host)
	out.Header.Set("X-Request-Id", e.ID)

	// Last, so an application that needs its own headers can override even the
	// forwarding ones. Anything that frames the connection is refused when the
	// app is saved and skipped again here.
	for _, h := range app.ExtraHeaders {
		if config.ValidHeaderName(h.Name) != nil || config.ValidHeaderValue(h.Value) != nil {
			continue
		}
		out.Header.Set(h.Name, h.Value)
	}
	return out, nil
}

func (s *Server) newEvent(r *http.Request, app *config.App, id string, start time.Time) event.Event {
	real, claimed := router.ResolveClientIP(r.RemoteAddr, r.Header.Get("X-Forwarded-For"), app.TrustedPrefixes())

	e := event.Event{
		TS:              start.UTC(),
		ID:              id,
		AppID:           app.ID,
		RetentionDays:   uint16(app.RetentionDays),
		ClientIP:        real,
		ClientIPClaimed: claimed,
		ClientPort:      peerPort(r.RemoteAddr),
		Method:          r.Method,
		Scheme:          requestScheme(r),
		Host:            r.Host,
		Path:            r.URL.Path,
		Query:           r.URL.RawQuery,
		HTTPVersion:     r.Proto,
		ReqHeaders:      headerMap(r.Header),
		UserAgent:       r.UserAgent(),
	}
	if fp, ok := tlsx.FingerprintFromContext(r.Context()); ok {
		e.JA3, e.JA4 = fp.JA3, fp.JA4
	}
	return e
}

// finish completes an event and hands it to the pipeline.
func (s *Server) finish(e *event.Event, tx *waf.Tx, body *bodyCapture, status int, respHeaders http.Header, written uint64, start, upstreamStart time.Time) {
	e.Status = uint16(status)
	e.RespHeaders = headerMap(respHeaders)
	e.RespSize = written
	e.RespContentType = contentType(respHeaders.Get("Content-Type"))
	e.DurationMS = uint32(time.Since(start).Milliseconds())
	if !upstreamStart.IsZero() {
		e.UpstreamMS = uint32(time.Since(upstreamStart).Milliseconds())
	}
	if !e.IsWebsocket {
		// A websocket event carries relayed byte counts, not a request body.
		e.ReqBodySize = body.Total()
		e.ReqTruncated = body.Truncated()
	}

	if tx != nil {
		res := tx.Result()
		e.AnomalyScore = res.AnomalyScore
		e.RuleIDs = res.RuleIDs
		e.RuleMsgs = res.Messages
		e.RuleTags = res.Tags
		e.RuleSeverity = res.Severity
		e.ParanoiaMax = res.ParanoiaMax
		e.WouldBlock = res.WouldBlock
		e.WAFMS = uint32(res.Elapsed.Milliseconds())
	}
	s.storeBody(e, body)
	s.submit(e)
}

// storeBody keeps small bodies inline and spills larger ones to the blob store.
func (s *Server) storeBody(e *event.Event, body *bodyCapture) {
	app, ok := s.opts.Router.ByID(e.AppID)
	if !ok || len(body.Body()) == 0 {
		return
	}
	if isBinary(app.Capture.BinaryTypes, e.ReqHeaders["content-type"]) {
		e.ReqBodySHA = blob.Key(body.Body())
		return
	}
	e.ReqBodySHA = blob.Key(body.Body())
	if int64(len(body.Body())) <= app.Capture.InlineMaxBytes {
		e.ReqBody = string(body.Body())
		return
	}
	if s.opts.Blobs == nil {
		e.ReqBody = string(body.Body()[:app.Capture.InlineMaxBytes])
		e.ReqTruncated = true
		return
	}
	key, err := s.opts.Blobs.Put(body.Body())
	if err != nil {
		s.log.Error("blob write failed", "err", err, "id", e.ID)
		return
	}
	e.ReqBodyBlob = key
}

func (s *Server) submit(e *event.Event) {
	if app, ok := s.opts.Router.ByID(e.AppID); ok {
		redact.New(app.Redaction).Apply(e)
	}
	if s.opts.Enricher != nil {
		s.opts.Enricher.Apply(e)
	}
	if s.opts.Sink != nil {
		s.opts.Sink.Submit(*e)
	}
}

// recordUnrouted logs a request for a hostname that matches no app.
func (s *Server) recordUnrouted(r *http.Request, id string, start time.Time) {
	e := event.Event{
		TS:            start.UTC(),
		ID:            id,
		AppID:         "",
		RetentionDays: 90,
		ClientIP:      router.PeerAddr(r.RemoteAddr),
		ClientPort:    peerPort(r.RemoteAddr),
		Method:        r.Method,
		Scheme:        requestScheme(r),
		Host:          r.Host,
		Path:          r.URL.Path,
		Query:         r.URL.RawQuery,
		HTTPVersion:   r.Proto,
		ReqHeaders:    headerMap(r.Header),
		UserAgent:     r.UserAgent(),
		Status:        http.StatusMisdirectedRequest,
		RespHeaders:   map[string]string{},
		DurationMS:    uint32(time.Since(start).Milliseconds()),
		Error:         "no app configured for host",
	}
	if fp, ok := tlsx.FingerprintFromContext(r.Context()); ok {
		e.JA3, e.JA4 = fp.JA3, fp.JA4
	}
	if s.opts.Enricher != nil {
		s.opts.Enricher.Apply(&e)
	}
	if s.opts.Sink != nil {
		s.opts.Sink.Submit(e)
	}
}

func copyHeader(dst, src http.Header) {
	for k, vs := range src {
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}

func appendForwarded(existing, ip string) string {
	if existing == "" {
		return ip
	}
	return existing + ", " + ip
}

func joinPath(base, path string) string {
	base = strings.TrimSuffix(base, "/")
	if base == "" {
		return path
	}
	return base + path
}

func requestScheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

func peerPort(remoteAddr string) uint16 {
	_, port, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return 0
	}
	var n int
	if _, err := fmt.Sscanf(port, "%d", &n); err != nil || n < 0 || n > 65535 {
		return 0
	}
	return uint16(n)
}

func localAddr(r *http.Request) string {
	if addr, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr); ok {
		host, _, err := net.SplitHostPort(addr.String())
		if err == nil {
			return host
		}
	}
	return ""
}

func localPort(r *http.Request) int {
	if addr, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr); ok {
		_, port, err := net.SplitHostPort(addr.String())
		if err == nil {
			var n int
			fmt.Sscanf(port, "%d", &n)
			return n
		}
	}
	return 0
}

func contentType(v string) string {
	if i := strings.IndexByte(v, ';'); i >= 0 {
		v = v[:i]
	}
	return strings.ToLower(strings.TrimSpace(v))
}

func isBinary(types []string, ct string) bool {
	ct = contentType(ct)
	if ct == "" {
		return false
	}
	for _, t := range types {
		if strings.HasPrefix(ct, strings.ToLower(t)) {
			return true
		}
	}
	return false
}

func skipPath(patterns []string, path string) bool {
	for _, p := range patterns {
		if p == "" {
			continue
		}
		if strings.HasSuffix(p, "*") {
			if strings.HasPrefix(path, strings.TrimSuffix(p, "*")) {
				return true
			}
			continue
		}
		if path == p {
			return true
		}
	}
	return false
}

func isWebSocketUpgrade(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket") &&
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade")
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

var errHijackUnsupported = errors.New("proxy: connection hijacking not supported")
