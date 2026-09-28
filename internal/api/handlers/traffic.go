package handlers

import (
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/amzteodor/heron/internal/api/reader"
	"github.com/amzteodor/heron/internal/pipeline/event"
	"github.com/amzteodor/heron/internal/store"
)

// ListTraffic returns one keyset page of events.
func (h *Handler) ListTraffic(w http.ResponseWriter, r *http.Request) {
	f, err := h.filterFromRequest(r)
	if err != nil {
		h.writeFilterError(w, err)
		return
	}
	page, err := h.Reader.List(r.Context(), f)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, page)
}

// CountTraffic returns an exact count up to the cap.
func (h *Handler) CountTraffic(w http.ResponseWriter, r *http.Request) {
	f, err := h.filterFromRequest(r)
	if err != nil {
		h.writeFilterError(w, err)
		return
	}
	n, capped, err := h.Reader.Count(r.Context(), f)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"count": n, "capped": capped, "cap": reader.CountCap})
}

// EventDetail is one event with its stored body and annotations.
type EventDetail struct {
	event.Event
	Body        string            `json:"body,omitempty"`
	BodySource  string            `json:"body_source,omitempty"`
	Annotation  *store.Annotation `json:"annotation,omitempty"`
	FPMarks     []store.FPMark    `json:"fp_marks,omitempty"`
	MatchedRule []MatchedRule     `json:"matched_rules,omitempty"`
}

// MatchedRule pairs a rule ID with its recorded message.
type MatchedRule struct {
	RuleID  uint32 `json:"rule_id"`
	Message string `json:"message,omitempty"`
}

// GetTraffic returns one event in full.
func (h *Handler) GetTraffic(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	e, err := h.Reader.Get(r.Context(), id)
	if err != nil {
		if errors.Is(err, reader.ErrNotFound) {
			writeError(w, http.StatusNotFound, "event not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s := session(r)
	if !s.CanSeeApp(e.AppID) {
		writeError(w, http.StatusForbidden, "no access to this app")
		return
	}

	detail := EventDetail{Event: e}
	for i, ruleID := range e.RuleIDs {
		m := MatchedRule{RuleID: ruleID}
		if i < len(e.RuleMsgs) {
			m.Message = e.RuleMsgs[i]
		}
		detail.MatchedRule = append(detail.MatchedRule, m)
	}

	detail.Body, detail.BodySource = h.loadBody(e)

	if marks, err := h.Store.FPMarksForEvents(r.Context(), []string{id}); err == nil {
		detail.FPMarks = marks[id]
	}
	if notes, err := h.Store.AnnotationsForEvents(r.Context(), []string{id}); err == nil {
		if a, ok := notes[id]; ok {
			detail.Annotation = &a
		}
	}
	writeJSON(w, http.StatusOK, detail)
}

// loadBody returns the request body, fetching from the blob store when the
// event only holds a reference.
func (h *Handler) loadBody(e event.Event) (string, string) {
	if e.ReqBody != "" {
		return e.ReqBody, "inline"
	}
	if e.ReqBodyBlob == "" || h.Blobs == nil {
		return "", ""
	}
	data, err := h.Blobs.Get(e.ReqBodyBlob)
	if err != nil {
		h.Logger.Warn("blob fetch failed", "id", e.ID, "key", e.ReqBodyBlob, "err", err)
		return "", ""
	}
	return string(data), "blob"
}

// ExportTraffic renders one event as raw HTTP, a curl command, or HAR.
func (h *Handler) ExportTraffic(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	e, err := h.Reader.Get(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "event not found")
		return
	}
	if !session(r).CanSeeApp(e.AppID) {
		writeError(w, http.StatusForbidden, "no access to this app")
		return
	}
	body, _ := h.loadBody(e)

	switch r.URL.Query().Get("format") {
	case "curl":
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte(renderCurl(e, body)))
	case "har":
		writeJSON(w, http.StatusOK, renderHAR(e, body))
	default:
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte(renderRawHTTP(e, body)))
	}
}

func renderRawHTTP(e event.Event, body string) string {
	var b strings.Builder
	target := e.Path
	if e.Query != "" {
		target += "?" + e.Query
	}
	version := e.HTTPVersion
	if version == "" {
		version = "HTTP/1.1"
	}
	fmt.Fprintf(&b, "%s %s %s\r\n", e.Method, target, version)
	for _, k := range sortedKeys(e.ReqHeaders) {
		fmt.Fprintf(&b, "%s: %s\r\n", k, e.ReqHeaders[k])
	}
	b.WriteString("\r\n")
	b.WriteString(body)
	return b.String()
}

func renderCurl(e event.Event, body string) string {
	var b strings.Builder
	url := e.Scheme + "://" + e.Host + e.Path
	if e.Query != "" {
		url += "?" + e.Query
	}
	fmt.Fprintf(&b, "curl -X %s %s", e.Method, shellQuote(url))
	for _, k := range sortedKeys(e.ReqHeaders) {
		if k == "content-length" {
			continue
		}
		fmt.Fprintf(&b, " \\\n  -H %s", shellQuote(k+": "+e.ReqHeaders[k]))
	}
	if body != "" {
		fmt.Fprintf(&b, " \\\n  --data-raw %s", shellQuote(body))
	}
	return b.String()
}

// renderHAR emits a single-entry HAR 1.2 log.
func renderHAR(e event.Event, body string) map[string]any {
	headers := func(m map[string]string) []map[string]string {
		out := make([]map[string]string, 0, len(m))
		for _, k := range sortedKeys(m) {
			out = append(out, map[string]string{"name": k, "value": m[k]})
		}
		return out
	}
	url := e.Scheme + "://" + e.Host + e.Path
	if e.Query != "" {
		url += "?" + e.Query
	}
	return map[string]any{
		"log": map[string]any{
			"version": "1.2",
			"creator": map[string]string{"name": "heron", "version": "1"},
			"entries": []map[string]any{{
				"startedDateTime": e.TS.Format("2006-01-02T15:04:05.000Z07:00"),
				"time":            e.DurationMS,
				"request": map[string]any{
					"method":      e.Method,
					"url":         url,
					"httpVersion": e.HTTPVersion,
					"headers":     headers(e.ReqHeaders),
					"postData":    map[string]any{"mimeType": e.ReqHeaders["content-type"], "text": body},
					"bodySize":    e.ReqBodySize,
				},
				"response": map[string]any{
					"status":      e.Status,
					"httpVersion": e.HTTPVersion,
					"headers":     headers(e.RespHeaders),
					"content":     map[string]any{"size": e.RespSize, "mimeType": e.RespContentType},
					"bodySize":    e.RespSize,
				},
				"timings": map[string]any{"send": 0, "wait": e.UpstreamMS, "receive": 0},
			}},
		},
	}
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// Annotate stores tags, a note and the bookmark flag for one event.
func (h *Handler) Annotate(w http.ResponseWriter, r *http.Request) {
	var a store.Annotation
	if err := decodeBody(r, &a); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	a.EventID = r.PathValue("id")
	a.UserID = session(r).User.ID
	appID, err := h.eventApp(r, a.EventID)
	if err != nil {
		writeError(w, statusFor(err), err.Error())
		return
	}
	a.AppID = appID
	if !session(r).CanSeeApp(a.AppID) {
		writeError(w, http.StatusForbidden, "no access to this app")
		return
	}
	if err := h.Store.SaveAnnotation(r.Context(), a); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.audit(r, "event.annotate", map[string]any{"event_id": a.EventID})
	writeJSON(w, http.StatusOK, a)
}

// Bookmarks lists events flagged for follow-up.
func (h *Handler) Bookmarks(w http.ResponseWriter, r *http.Request) {
	apps, err := appScope(r)
	if err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	ids, err := h.Store.BookmarkedEventIDs(r.Context(), apps, intParam(r, "limit", 100))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"event_ids": ids})
}

// eventApp returns the app an event belongs to, so authorisation is decided by
// the record rather than by what the caller claims.
func (h *Handler) eventApp(r *http.Request, id string) (string, error) {
	e, err := h.Reader.Get(r.Context(), id)
	if err != nil {
		return "", err
	}
	return e.AppID, nil
}
