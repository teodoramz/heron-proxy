package handlers

import (
	"net/http"
	"time"

	"github.com/gorilla/websocket"

	"github.com/amzteodor/proxy-waf/internal/api/query"
	"github.com/amzteodor/proxy-waf/internal/store"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 32 << 10,
	CheckOrigin:     func(*http.Request) bool { return true },
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
			if !s.User.Role.AtLeast(store.RoleAnalyst) {
				e.ReqBody = ""
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
