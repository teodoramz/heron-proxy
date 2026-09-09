package pipeline

import (
	"sync"

	"github.com/amzteodor/heron/internal/pipeline/event"
)

// hub fans events out to live-tail subscribers.
type hub struct {
	mu   sync.RWMutex
	next uint64
	subs map[uint64]chan event.Event
}

func newHub() *hub {
	return &hub{subs: make(map[uint64]chan event.Event)}
}

func (h *hub) subscribe(buffer int) (<-chan event.Event, func()) {
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

// broadcast never blocks: a subscriber whose buffer is full misses the event.
func (h *hub) broadcast(e event.Event) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, ch := range h.subs {
		select {
		case ch <- e:
		default:
		}
	}
}

func (h *hub) count() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.subs)
}
