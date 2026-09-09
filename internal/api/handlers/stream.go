package handlers

import (
	"context"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/gorilla/websocket"

	"github.com/amzteodor/heron/internal/api/query"
)

// upgrader authorizes the handshake by Origin. This is the only cross-site
// defense on this route: a WebSocket handshake is a GET that cannot carry a
// custom header, so the CSRF middleware deliberately does not apply to it.
// Without an Origin check, any page a signed-in analyst visits could open this
// socket with their session cookie and stream every recorded request.
var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 32 << 10,
	CheckOrigin:     func(r *http.Request) bool { return originAllowed(r, allowedOrigins(r)) },
}

// originAllowed permits same-origin handshakes and any origin the operator has
// configured. Browsers always send Origin on a WebSocket handshake, so a
// missing one is rejected rather than trusted.
func originAllowed(r *http.Request, allowed []string) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return false
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	if strings.EqualFold(u.Host, r.Host) {
		return true
	}
	return slices.ContainsFunc(allowed, func(a string) bool { return strings.EqualFold(a, origin) })
}

type originsKey struct{}

// allowedOrigins reads the configured origins that withOrigins placed on the
// request, so the upgrader's CheckOrigin callback can reach them.
func allowedOrigins(r *http.Request) []string {
	v, _ := r.Context().Value(originsKey{}).([]string)
	return v
}

// Stream pushes matching events to the client as they are recorded. The filter
// is evaluated on the server, so a client never receives traffic it filtered out
// or is not scoped to see.
func (h *Handler) Stream(w http.ResponseWriter, r *http.Request) {
	f, err := h.filterFromRequest(r)
	if err != nil {
		h.writeFilterError(w, err)
		return
	}
	matcher, err := query.NewMatcher(f)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s := session(r)
	if h.Tail == nil {
		writeError(w, http.StatusServiceUnavailable, "live tail unavailable")
		return
	}
	// Checked here as well as in the upgrader so the caller gets a clear reason.
	r = r.WithContext(context.WithValue(r.Context(), originsKey{}, h.AllowedOrigins))
	if !originAllowed(r, h.AllowedOrigins) {
		writeError(w, http.StatusForbidden, "origin not allowed")
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	events, cancel := h.Tail.Subscribe(512)
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}()

	ping := time.NewTicker(30 * time.Second)
	defer ping.Stop()

	for {
		select {
		case <-done:
			return
		case <-r.Context().Done():
			return
		case <-ping.C:
			if err := conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(5*time.Second)); err != nil {
				return
			}
		case e, ok := <-events:
			if !ok {
				return
			}
			if !s.CanSeeApp(e.AppID) || !matcher.Match(&e) {
				continue
			}
			if err := conn.WriteJSON(e); err != nil {
				return
			}
		}
	}
}

// StreamStatus reports whether the API is connected to the proxy's event stream.
func (h *Handler) StreamStatus(w http.ResponseWriter, r *http.Request) {
	connected := h.Tail != nil && h.Tail.Connected()
	writeJSON(w, http.StatusOK, map[string]any{"connected": connected})
}
