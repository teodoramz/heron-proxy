package handlers

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/amzteodor/proxy-waf/internal/store"
)

// ReplayRequest describes a request to send, based on a recorded event.
//
// Raw is the whole request as typed by an analyst: request line, headers, blank
// line, body. When present it supersedes Method, Path, Query, Headers and Body,
// which remain for callers that would rather change one field.
type ReplayRequest struct {
	Raw      string            `json:"raw,omitempty"`
	Method   string            `json:"method,omitempty"`
	Target   string            `json:"target,omitempty"`
	Path     string            `json:"path,omitempty"`
	Query    string            `json:"query,omitempty"`
	Headers  map[string]string `json:"headers,omitempty"`
	Body     string            `json:"body,omitempty"`
	NoBody   bool              `json:"no_body,omitempty"`
	Insecure bool              `json:"insecure,omitempty"`
}

// ReplayResponse is the result of a replay, with a diff against the recording.
type ReplayResponse struct {
	URL         string            `json:"url"`
	Status      int               `json:"status"`
	Headers     map[string]string `json:"headers"`
	Body        string            `json:"body"`
	Truncated   bool              `json:"truncated"`
	DurationMS  int64             `json:"duration_ms"`
	OriginalRes struct {
		Status  uint16 `json:"status"`
		Size    uint64 `json:"size"`
		Elapsed uint32 `json:"duration_ms"`
	} `json:"original"`
	Diff ReplayDiff `json:"diff"`
}

// ReplayDiff summarizes how the replay differed from the recorded transaction.
type ReplayDiff struct {
	StatusChanged bool   `json:"status_changed"`
	StatusFrom    uint16 `json:"status_from"`
	StatusTo      int    `json:"status_to"`
	SizeDelta     int64  `json:"size_delta"`
}

// replayBodyCap bounds how much of the replayed response is returned.
const replayBodyCap = 256 << 10

// Replay re-sends a recorded request, optionally modified, and diffs the result.
//
// By default it targets the app's own upstream. Sending to an arbitrary target
// requires the admin role, and addresses that are loopback, private or
// link-local are refused either way, so replay cannot be turned into a probe of
// the host's internal network.
func (h *Handler) Replay(w http.ResponseWriter, r *http.Request) {
	var req ReplayRequest
	if err := decodeBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Raw != "" {
		parsed, err := parseRawRequest(req.Raw)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		req.Method = parsed.Method
		req.Path, req.Query = splitTarget(parsed.Target)
		req.Headers = parsed.Headers
		req.Body = parsed.Body
		req.NoBody = parsed.Body == ""
	}

	e, err := h.Reader.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "event not found")
		return
	}
	s := session(r)
	if !s.CanSeeApp(e.AppID) {
		writeError(w, http.StatusForbidden, "no access to this app")
		return
	}

	app, err := h.Store.GetApp(r.Context(), e.AppID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "the app for this event no longer exists")
		return
	}
	target := app.UpstreamURL
	if req.Target != "" {
		if !s.User.Role.AtLeast(store.RoleAdmin) {
			writeError(w, http.StatusForbidden, "only an admin may replay to a custom target")
			return
		}
		target = req.Target
	}
	base, err := url.Parse(target)
	if err != nil || base.Host == "" {
		writeError(w, http.StatusBadRequest, "invalid target URL")
		return
	}
	if err := guardTarget(r.Context(), base.Hostname(), req.Target != ""); err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}

	method := firstNonEmpty(req.Method, e.Method, http.MethodGet)
	path := firstNonEmpty(req.Path, e.Path, "/")
	rawQuery := req.Query
	if rawQuery == "" && req.Path == "" {
		rawQuery = e.Query
	}
	base.Path = strings.TrimSuffix(base.Path, "/") + path
	base.RawQuery = rawQuery

	body := req.Body
	if body == "" && !req.NoBody {
		body, _ = h.loadBody(e)
	}

	outReq, err := http.NewRequestWithContext(r.Context(), method, base.String(), strings.NewReader(body))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	headers := req.Headers
	if headers == nil {
		headers = e.ReqHeaders
	}
	for k, v := range headers {
		switch strings.ToLower(k) {
		case "host", "content-length", "connection", "transfer-encoding":
			continue
		}
		outReq.Header.Set(k, v)
	}
	if host := headers["host"]; host != "" {
		outReq.Host = host
	} else if e.Host != "" {
		outReq.Host = e.Host
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: req.Insecure || !app.UpstreamTLSVerify},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	start := time.Now()
	resp, err := client.Do(outReq)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, replayBodyCap+1))
	truncated := len(respBody) > replayBodyCap
	if truncated {
		respBody = respBody[:replayBodyCap]
	}

	out := ReplayResponse{
		URL:        base.String(),
		Status:     resp.StatusCode,
		Headers:    flattenHeaders(resp.Header),
		Body:       string(respBody),
		Truncated:  truncated,
		DurationMS: time.Since(start).Milliseconds(),
	}
	out.OriginalRes.Status = e.Status
	out.OriginalRes.Size = e.RespSize
	out.OriginalRes.Elapsed = e.DurationMS
	out.Diff = ReplayDiff{
		StatusChanged: int(e.Status) != resp.StatusCode,
		StatusFrom:    e.Status,
		StatusTo:      resp.StatusCode,
		SizeDelta:     int64(len(respBody)) - int64(e.RespSize),
	}

	h.audit(r, "event.replay", map[string]any{
		"event_id": e.ID, "url": base.String(), "status": resp.StatusCode, "custom_target": req.Target != "",
	})
	writeJSON(w, http.StatusOK, out)
}

// guardTarget refuses addresses that would let replay reach the host's own
// network or a cloud metadata service.
func guardTarget(ctx context.Context, host string, custom bool) error {
	resolver := net.DefaultResolver
	addrs, err := resolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return fmt.Errorf("cannot resolve %q", host)
	}
	for _, a := range addrs {
		a = a.Unmap()
		if a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() {
			return fmt.Errorf("refusing to replay to a link-local address (%s)", a)
		}
		if custom && (a.IsLoopback() || a.IsPrivate() || a.IsUnspecified()) {
			return fmt.Errorf("refusing to replay to a private address (%s)", a)
		}
		if a == netip.MustParseAddr("169.254.169.254") {
			return fmt.Errorf("refusing to replay to the metadata service")
		}
	}
	return nil
}

func flattenHeaders(h http.Header) map[string]string {
	out := make(map[string]string, len(h))
	for k, v := range h {
		out[strings.ToLower(k)] = strings.Join(v, ", ")
	}
	return out
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
