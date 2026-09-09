// Package handlers implements the API's HTTP endpoints.
package handlers

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/amzteodor/heron/internal/api/auth"
	"github.com/amzteodor/heron/internal/api/query"
	"github.com/amzteodor/heron/internal/api/reader"
	"github.com/amzteodor/heron/internal/api/tail"
	"github.com/amzteodor/heron/internal/pipeline/blob"
	"github.com/amzteodor/heron/internal/store"
)

// maxBodyBytes bounds a request body the API will parse.
const maxBodyBytes = 1 << 20

// Handler holds the API's dependencies.
type Handler struct {
	Reader *reader.Reader
	Store  *store.Store
	Blobs  *blob.Store
	Auth   *auth.Middleware
	Tail   *tail.Hub
	Logger *slog.Logger

	// AllowedOrigins are the cross-origin sites permitted to open the live-tail
	// websocket. Same-origin is always allowed and needs no entry here.
	AllowedOrigins []string
}

// filterFromRequest decodes a filter from the body (POST) or query string (GET)
// and restricts it to the apps the caller may see.
func (h *Handler) filterFromRequest(r *http.Request) (query.Filter, error) {
	var f query.Filter

	if r.Method == http.MethodPost {
		body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes))
		if err != nil {
			return f, err
		}
		if len(body) > 0 {
			if f, err = query.ParseFilter(body); err != nil {
				return f, err
			}
		}
	} else if raw := r.URL.Query().Get("filter"); raw != "" {
		var err error
		if f, err = query.ParseFilter([]byte(raw)); err != nil {
			return f, err
		}
	}

	applyQueryParams(&f, r)
	f.Normalize()
	if err := scopeToSession(&f, r); err != nil {
		return f, err
	}
	return f, nil
}

// applyQueryParams lets simple pagination and range controls come from the URL
// even when the filter body is present.
func applyQueryParams(f *query.Filter, r *http.Request) {
	q := r.URL.Query()
	if v := q.Get("cursor"); v != "" {
		f.Cursor = v
	}
	if v := q.Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			f.Limit = n
		}
	}
	if v := q.Get("order"); v != "" {
		f.Order = v
	}
	if v := q.Get("from"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			f.From = t
		}
	}
	if v := q.Get("to"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			f.To = t
		}
	}
	if apps := q["app"]; len(apps) > 0 {
		f.Apps = apps
	}
}

// scopeToSession intersects the requested apps with the caller's grants, so a
// scoped user cannot widen their own visibility through the filter.
func scopeToSession(f *query.Filter, r *http.Request) error {
	s, ok := auth.FromContext(r.Context())
	if !ok {
		return errors.New("no session")
	}
	if len(s.Apps) == 0 {
		return nil
	}
	if len(f.Apps) == 0 {
		f.Apps = append([]string(nil), s.Apps...)
		return nil
	}
	allowed := make([]string, 0, len(f.Apps))
	for _, id := range f.Apps {
		if s.CanSeeApp(id) {
			allowed = append(allowed, id)
		}
	}
	if len(allowed) == 0 {
		return errForbiddenScope
	}
	f.Apps = allowed
	return nil
}

var errForbiddenScope = errors.New("no access to the requested apps")

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if v != nil {
		_ = json.NewEncoder(w).Encode(v)
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// writeFilterError maps a filter or scope failure to a status code.
func (h *Handler) writeFilterError(w http.ResponseWriter, err error) {
	if errors.Is(err, errForbiddenScope) {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	writeError(w, http.StatusBadRequest, err.Error())
}

func decodeBody(r *http.Request, v any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, maxBodyBytes))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

func intParam(r *http.Request, name string, def int) int {
	if v := r.URL.Query().Get(name); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

// session returns the authenticated caller, which the middleware guarantees.
func session(r *http.Request) auth.Session {
	s, _ := auth.FromContext(r.Context())
	return s
}

// audit records an action, logging rather than failing if the write errors.
func (h *Handler) audit(r *http.Request, action string, detail any) {
	if h.Store == nil {
		return
	}
	if err := h.Store.Audit(r.Context(), session(r).User.ID, action, detail); err != nil {
		h.Logger.Warn("audit write failed", "action", action, "err", err)
	}
}
