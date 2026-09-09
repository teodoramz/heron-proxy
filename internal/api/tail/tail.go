// Package tail relays the proxy's internal event stream to API clients.
package tail

import (
	"context"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"

	"github.com/amzteodor/heron/internal/pipeline/event"
)

// Hub keeps one upstream connection to the proxy and fans events out to
// subscribers. It reconnects with backoff if the proxy restarts.
type Hub struct {
	url   string
	token string
	log   *slog.Logger

	mu   sync.RWMutex
	next uint64
	subs map[uint64]chan event.Event

	connected atomic.Bool
}

// New builds a Hub for the proxy's internal stream endpoint.
func New(url, token string, log *slog.Logger) *Hub {
	if log == nil {
		log = slog.Default()
	}
	return &Hub{url: url, token: token, log: log, subs: make(map[uint64]chan event.Event)}
}

// Connected reports whether the upstream stream is currently established.
func (h *Hub) Connected() bool { return h.connected.Load() }

// Run maintains the upstream connection until the context is cancelled.
func (h *Hub) Run(ctx context.Context) {
	backoff := time.Second
	for {
		if ctx.Err() != nil {
			return
		}
		if err := h.connect(ctx); err != nil && ctx.Err() == nil {
			h.log.Warn("event stream disconnected", "err", err, "retry_in", backoff)
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return
			}
			if backoff < 30*time.Second {
				backoff *= 2
			}
			continue
		}
		backoff = time.Second
	}
}

func (h *Hub) connect(ctx context.Context) error {
	header := http.Header{}
	if h.token != "" {
		header.Set("Authorization", "Bearer "+h.token)
	}
	dialer := &websocket.Dialer{HandshakeTimeout: 10 * time.Second}
	conn, _, err := dialer.DialContext(ctx, h.url, header)
	if err != nil {
		return err
	}
	defer conn.Close()

	h.connected.Store(true)
	defer h.connected.Store(false)
	h.log.Info("event stream connected", "url", h.url)

	go func() {
		<-ctx.Done()
		conn.Close()
	}()
	for {
		var e event.Event
		if err := conn.ReadJSON(&e); err != nil {
			return err
		}
		h.broadcast(e)
	}
}

// Subscribe returns a channel of live events and a function to release it.
func (h *Hub) Subscribe(buffer int) (<-chan event.Event, func()) {
	if buffer <= 0 {
		buffer = 256
	}
	ch := make(chan event.Event, buffer)

	h.mu.Lock()
	id := h.next
	h.next++
	h.subs[id] = ch
	h.mu.Unlock()

	var once sync.Once
	return ch, func() {
		once.Do(func() {
			h.mu.Lock()
			delete(h.subs, id)
			h.mu.Unlock()
			close(ch)
		})
	}
}

// broadcast never blocks: a slow subscriber misses events rather than stalling
// the stream for everyone.
func (h *Hub) broadcast(e event.Event) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, ch := range h.subs {
		select {
		case ch <- e:
		default:
		}
	}
}
