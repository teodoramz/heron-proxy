package proxy

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/gorilla/websocket"

	"github.com/amzteodor/proxy-waf/internal/pipeline"
	"github.com/amzteodor/proxy-waf/internal/pipeline/event"
)

// Admin serves health, metrics and the internal event stream the API consumes
// for live tail. It is bound to a private address, never the public listener.
type Admin struct {
	Pipeline *pipeline.Pipeline
	Loader   *Loader
	Token    string
	Logger   *slog.Logger
}

// Handler returns the admin routes.
func (a *Admin) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", a.health)
	mux.HandleFunc("GET /metrics", a.metrics)
	mux.HandleFunc("GET /internal/stream", a.stream)
	return mux
}

func (a *Admin) health(w http.ResponseWriter, _ *http.Request) {
	if a.Loader != nil && !a.Loader.Ready() {
		http.Error(w, "configuration not loaded", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func (a *Admin) metrics(w http.ResponseWriter, _ *http.Request) {
	stats := struct {
		pipeline.Stats
		ConfigVersion int64 `json:"config_version"`
	}{ConfigVersion: -1}
	if a.Pipeline != nil {
		stats.Stats = a.Pipeline.Stats()
	}
	if a.Loader != nil {
		stats.ConfigVersion = a.Loader.Version()
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(stats)
}

// upgrader rejects any handshake carrying an Origin header. The only client of
// this endpoint is the API service, which sends none; a browser always sends
// one. The bearer token below is the primary control, since a browser cannot
// set Authorization on a websocket handshake, but refusing browser origins
// outright removes the question.
var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 32 << 10,
	CheckOrigin:     func(r *http.Request) bool { return r.Header.Get("Origin") == "" },
}

// stream pushes every recorded event to the API for live tail.
func (a *Admin) stream(w http.ResponseWriter, r *http.Request) {
	if a.Token != "" && r.Header.Get("Authorization") != "Bearer "+a.Token {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if a.Pipeline == nil {
		http.Error(w, "no pipeline", http.StatusServiceUnavailable)
		return
	}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	events, cancel := a.Pipeline.Subscribe(1024)
	defer cancel()

	// Reading is only needed to observe the peer closing.
	go func() {
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				conn.Close()
				return
			}
		}
	}()

	for e := range events {
		if err := conn.WriteJSON(streamEvent(e)); err != nil {
			return
		}
	}
}

// streamEvent trims fields that are large and not useful in a live tail.
func streamEvent(e event.Event) event.Event {
	e.ReqBody = ""
	e.RuleMsgs = nil
	return e
}
