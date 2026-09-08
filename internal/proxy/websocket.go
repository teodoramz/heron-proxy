package proxy

import (
	"bufio"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/amzteodor/proxy-waf/internal/config"
	"github.com/amzteodor/proxy-waf/internal/pipeline/event"
	"github.com/amzteodor/proxy-waf/internal/proxy/waf"
)

// serveWebSocket evaluates the upgrade handshake, then relays the connection
// bidirectionally. Frames are not inspected or recorded; the transaction is
// logged once, on close, with the bytes moved in each direction.
func (s *Server) serveWebSocket(w http.ResponseWriter, r *http.Request, app *config.App, id string, start time.Time) {
	e := s.newEvent(r, app, id, start)
	e.IsWebsocket = true

	body, _ := captureBody(r.Body, 0)

	var tx *waf.Tx
	if app.WAF.Enabled {
		if t, err := s.opts.WAF.NewTransaction(app.WAF, 1<<20, id); err == nil {
			tx = t
			defer tx.Close()
			tx.ProcessRequest(r, e.ClientIP.String(), int(e.ClientPort), localAddr(r), localPort(r))
		}
	}

	target, err := url.Parse(app.UpstreamURL)
	if err != nil {
		e.Error = err.Error()
		s.finishWS(&e, tx, body, http.StatusBadGateway, nil, 0, start)
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}
	e.Upstream = target.String()

	upstream, err := dialUpstream(target, app.UpstreamTLSVerify)
	if err != nil {
		e.Error = err.Error()
		s.finishWS(&e, tx, body, http.StatusBadGateway, nil, 0, start)
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}
	defer upstream.Close()

	outReq, err := s.buildUpstreamRequest(r, app, http.NoBody, e)
	if err != nil {
		e.Error = err.Error()
		s.finishWS(&e, tx, body, http.StatusBadGateway, nil, 0, start)
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}
	// The upgrade headers are hop-by-hop and were stripped; restore them.
	outReq.Header.Set("Connection", "Upgrade")
	outReq.Header.Set("Upgrade", "websocket")
	for _, h := range []string{"Sec-Websocket-Key", "Sec-Websocket-Version", "Sec-Websocket-Protocol", "Sec-Websocket-Extensions"} {
		if v := r.Header.Get(h); v != "" {
			outReq.Header.Set(h, v)
		}
	}

	if err := outReq.Write(upstream); err != nil {
		e.Error = err.Error()
		s.finishWS(&e, tx, body, http.StatusBadGateway, nil, 0, start)
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}
	upstreamReader := bufio.NewReader(upstream)
	resp, err := http.ReadResponse(upstreamReader, outReq)
	if err != nil {
		e.Error = err.Error()
		s.finishWS(&e, tx, body, http.StatusBadGateway, nil, 0, start)
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}
	if tx != nil {
		tx.ProcessResponseHeaders(resp.StatusCode, resp.Proto, resp.Header)
	}

	if resp.StatusCode != http.StatusSwitchingProtocols {
		defer resp.Body.Close()
		copyHeader(w.Header(), resp.Header)
		w.WriteHeader(resp.StatusCode)
		written := s.stream(w, resp)
		s.finishWS(&e, tx, body, resp.StatusCode, resp.Header, written, start)
		return
	}

	client, _, err := http.NewResponseController(w).Hijack()
	if err != nil {
		e.Error = errHijackUnsupported.Error()
		s.finishWS(&e, tx, body, http.StatusInternalServerError, resp.Header, 0, start)
		http.Error(w, "websocket unsupported", http.StatusInternalServerError)
		return
	}
	defer client.Close()

	if err := resp.Write(client); err != nil {
		e.Error = err.Error()
		s.finishWS(&e, tx, body, resp.StatusCode, resp.Header, 0, start)
		return
	}

	var toClient, toUpstream atomic.Uint64
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		n, _ := io.Copy(client, upstreamReader)
		toClient.Add(uint64(n))
		closeWrite(client)
	}()
	go func() {
		defer wg.Done()
		n, _ := io.Copy(upstream, client)
		toUpstream.Add(uint64(n))
		closeWrite(upstream)
	}()
	wg.Wait()

	e.ReqBodySize = toUpstream.Load()
	s.finishWS(&e, tx, body, resp.StatusCode, resp.Header, toClient.Load(), start)
}

// wsTx carries the WAF transaction for a websocket handshake.
type wsTx struct {
	t interface{ Result() wafResult }
}

type wafResult = struct {
	AnomalyScore uint16
	Matched      []wafMatched
	RuleIDs      []uint32
	Messages     []string
	Tags         []string
	Severity     uint8
	ParanoiaMax  uint8
	WouldBlock   bool
	Elapsed      time.Duration
}

type wafMatched = struct {
	ID       uint32   `json:"id"`
	Message  string   `json:"message"`
	Data     string   `json:"data"`
	Severity uint8    `json:"severity"`
	Paranoia uint8    `json:"paranoia"`
	Tags     []string `json:"tags"`
	Phase    uint8    `json:"phase"`
}

func dialUpstream(target *url.URL, verify bool) (net.Conn, error) {
	host := target.Host
	if target.Port() == "" {
		if target.Scheme == "https" {
			host = net.JoinHostPort(host, "443")
		} else {
			host = net.JoinHostPort(host, "80")
		}
	}
	d := &net.Dialer{Timeout: 10 * time.Second}
	if target.Scheme == "https" {
		return tls.DialWithDialer(d, "tcp", host, &tls.Config{
			InsecureSkipVerify: !verify,
			ServerName:         target.Hostname(),
		})
	}
	return d.Dial("tcp", host)
}

func closeWrite(c net.Conn) {
	type closeWriter interface{ CloseWrite() error }
	if cw, ok := c.(closeWriter); ok {
		_ = cw.CloseWrite()
	}
}

// finishWS completes a websocket event. Unlike an HTTP request, ReqBodySize
// carries the bytes sent to the upstream over the lifetime of the connection.
func (s *Server) finishWS(e *event.Event, tx *waf.Tx, body *bodyCapture, status int, respHeaders http.Header, toClient uint64, start time.Time) {
	if respHeaders == nil {
		respHeaders = http.Header{}
	}
	s.finish(e, tx, body, status, respHeaders, toClient, start, time.Time{})
}
