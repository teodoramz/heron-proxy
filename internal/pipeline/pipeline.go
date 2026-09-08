// Package pipeline moves captured events from the request path to durable
// storage without blocking the proxy.
//
// Submit hands an event to a bounded channel. A writer goroutine encodes it and
// appends it to the spool, then broadcasts it to live-tail subscribers. A
// shipper goroutine drains the spool in batches into the sink and commits the
// spool cursor only after a successful write.
package pipeline

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/amzteodor/proxy-waf/internal/pipeline/event"
	"github.com/amzteodor/proxy-waf/internal/pipeline/spool"
)

// Sink is the durable destination for batches of events.
type Sink interface {
	WriteBatch(context.Context, []event.Event) error
}

// Options tunes the pipeline.
type Options struct {
	QueueSize     int
	BatchSize     int
	BatchInterval time.Duration
	SyncInterval  time.Duration
	BlockOnFull   bool
	Logger        *slog.Logger
}

// Stats reports pipeline counters.
type Stats struct {
	Submitted    uint64 `json:"submitted"`
	Dropped      uint64 `json:"dropped"`
	Spooled      uint64 `json:"spooled"`
	Shipped      uint64 `json:"shipped"`
	SinkErrors   uint64 `json:"sink_errors"`
	SpoolDropped uint64 `json:"spool_dropped_bytes"`
	SpoolBytes   int64  `json:"spool_bytes"`
	Subscribers  int    `json:"subscribers"`
}

// Pipeline is the ingestion path. The zero value is not usable; call New.
type Pipeline struct {
	spool *spool.Spool
	sink  Sink
	opts  Options
	log   *slog.Logger

	ch          chan event.Event
	hub         *hub
	stopWriter  chan struct{}
	stopShipper chan struct{}
	writerDone  chan struct{}
	shipperDone chan struct{}
	once        sync.Once

	started    atomic.Bool
	submitted  atomic.Uint64
	dropped    atomic.Uint64
	spooled    atomic.Uint64
	shipped    atomic.Uint64
	sinkErrors atomic.Uint64
}

// New builds a pipeline. Start must be called to begin draining.
func New(sp *spool.Spool, sink Sink, opts Options) *Pipeline {
	if opts.QueueSize <= 0 {
		opts.QueueSize = 50000
	}
	if opts.BatchSize <= 0 {
		opts.BatchSize = 5000
	}
	if opts.BatchInterval <= 0 {
		opts.BatchInterval = 500 * time.Millisecond
	}
	if opts.SyncInterval <= 0 {
		opts.SyncInterval = time.Second
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	return &Pipeline{
		spool:       sp,
		sink:        sink,
		opts:        opts,
		log:         opts.Logger,
		ch:          make(chan event.Event, opts.QueueSize),
		hub:         newHub(),
		stopWriter:  make(chan struct{}),
		stopShipper: make(chan struct{}),
		writerDone:  make(chan struct{}),
		shipperDone: make(chan struct{}),
	}
}

// Start launches the writer and shipper goroutines.
func (p *Pipeline) Start(ctx context.Context) {
	if !p.started.CompareAndSwap(false, true) {
		return
	}
	go p.runWriter()
	go p.runShipper(ctx)
}

// Submit queues an event. In non-blocking mode a full queue drops the event and
// increments the dropped counter rather than delaying the request.
func (p *Pipeline) Submit(e event.Event) {
	p.submitted.Add(1)
	if p.opts.BlockOnFull {
		select {
		case p.ch <- e:
		case <-p.stopWriter:
		}
		return
	}
	select {
	case p.ch <- e:
	default:
		p.dropped.Add(1)
	}
}

// Subscribe returns a channel of live events and a function to release it.
// A subscriber that cannot keep up misses events; it never blocks the producer.
func (p *Pipeline) Subscribe(buffer int) (<-chan event.Event, func()) {
	return p.hub.subscribe(buffer)
}

// Stats returns a snapshot of the counters.
func (p *Pipeline) Stats() Stats {
	s := Stats{
		Submitted:   p.submitted.Load(),
		Dropped:     p.dropped.Load(),
		Spooled:     p.spooled.Load(),
		Shipped:     p.shipped.Load(),
		SinkErrors:  p.sinkErrors.Load(),
		Subscribers: p.hub.count(),
	}
	if p.spool != nil {
		s.SpoolDropped = p.spool.Dropped()
		s.SpoolBytes = p.spool.Size()
	}
	return s
}

// Close drains the queue to the spool, gives the shipper a final chance to
// flush, and syncs. Anything the sink refuses stays spooled for the next start.
func (p *Pipeline) Close() error {
	p.once.Do(func() {
		// Stop the writer first so the queue is fully spooled before the
		// shipper makes its final pass.
		close(p.stopWriter)
		if p.started.Load() {
			<-p.writerDone
		}
		close(p.stopShipper)
		if p.started.Load() {
			<-p.shipperDone
		}
	})
	if p.spool == nil {
		return nil
	}
	return p.spool.Sync()
}

func (p *Pipeline) runWriter() {
	defer close(p.writerDone)
	sync := time.NewTicker(p.opts.SyncInterval)
	defer sync.Stop()

	for {
		select {
		case e := <-p.ch:
			p.persist(e)
		case <-sync.C:
			if err := p.spool.Sync(); err != nil {
				p.log.Error("spool sync failed", "err", err)
			}
		case <-p.stopWriter:
			for {
				select {
				case e := <-p.ch:
					p.persist(e)
				default:
					if err := p.spool.Sync(); err != nil {
						p.log.Error("spool sync failed", "err", err)
					}
					return
				}
			}
		}
	}
}

func (p *Pipeline) persist(e event.Event) {
	data, err := json.Marshal(e)
	if err != nil {
		p.log.Error("event encode failed", "err", err, "id", e.ID)
		return
	}
	if err := p.spool.Append(data); err != nil {
		p.log.Error("spool append failed", "err", err, "id", e.ID)
		return
	}
	p.spooled.Add(1)
	p.hub.broadcast(e)
}

func (p *Pipeline) runShipper(ctx context.Context) {
	defer close(p.shipperDone)
	tick := time.NewTicker(p.opts.BatchInterval)
	defer tick.Stop()

	backoff := time.Duration(0)
	for {
		select {
		case <-tick.C:
		case <-p.stopShipper:
			for {
				n, err := p.shipOnce(ctx)
				if err != nil || n == 0 {
					return
				}
			}
		case <-ctx.Done():
			return
		}
		if backoff > 0 {
			select {
			case <-time.After(backoff):
			case <-p.stopShipper:
				return
			}
		}
		if _, err := p.shipOnce(ctx); err != nil {
			backoff = nextBackoff(backoff)
		} else {
			backoff = 0
		}
	}
}

// shipOnce writes at most one batch and returns how many events it shipped.
func (p *Pipeline) shipOnce(ctx context.Context) (int, error) {
	recs, err := p.spool.Read(p.opts.BatchSize)
	if err != nil {
		p.log.Error("spool read failed", "err", err)
		return 0, err
	}
	if len(recs) == 0 {
		return 0, nil
	}
	events := make([]event.Event, 0, len(recs))
	for _, r := range recs {
		var e event.Event
		if err := json.Unmarshal(r.Data, &e); err != nil {
			p.log.Error("event decode failed", "err", err)
			continue
		}
		events = append(events, e)
	}
	if len(events) > 0 {
		if err := p.sink.WriteBatch(ctx, events); err != nil {
			p.sinkErrors.Add(1)
			p.log.Error("sink write failed", "err", err, "batch", len(events))
			return 0, err
		}
		p.shipped.Add(uint64(len(events)))
	}
	if err := p.spool.Commit(recs[len(recs)-1].Next); err != nil {
		p.log.Error("spool commit failed", "err", err)
		return 0, err
	}
	return len(events), nil
}

func nextBackoff(cur time.Duration) time.Duration {
	switch {
	case cur == 0:
		return 250 * time.Millisecond
	case cur >= 30*time.Second:
		return 30 * time.Second
	default:
		return cur * 2
	}
}
