package pipeline

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/amzteodor/proxy-waf/internal/pipeline/event"
	"github.com/amzteodor/proxy-waf/internal/pipeline/spool"
)

type fakeSink struct {
	mu     sync.Mutex
	got    []event.Event
	failN  int
	calls  int
	failed error
}

func (f *fakeSink) WriteBatch(_ context.Context, ev []event.Event) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.calls <= f.failN {
		f.failed = errors.New("sink down")
		return f.failed
	}
	f.got = append(f.got, ev...)
	return nil
}

func (f *fakeSink) events() []event.Event {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]event.Event(nil), f.got...)
}

func newPipeline(t *testing.T, sink Sink, opts Options) *Pipeline {
	t.Helper()
	sp, err := spool.Open(t.TempDir(), spool.Options{SegmentBytes: 1 << 20, MaxBytes: 8 << 20})
	if err != nil {
		t.Fatalf("spool.Open: %v", err)
	}
	p := New(sp, sink, opts)
	t.Cleanup(func() { p.Close(); sp.Close() })
	return p
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition not met within 3s")
}

func TestSubmitReachesSink(t *testing.T) {
	sink := &fakeSink{}
	p := newPipeline(t, sink, Options{BatchInterval: 10 * time.Millisecond})
	p.Start(context.Background())

	p.Submit(event.Event{ID: "a", Host: "example.test"})
	p.Submit(event.Event{ID: "b"})

	waitFor(t, func() bool { return len(sink.events()) == 2 })
	if sink.events()[0].Host != "example.test" {
		t.Errorf("event content lost: %+v", sink.events()[0])
	}
}

func TestFullQueueDropsAndCounts(t *testing.T) {
	p := newPipeline(t, &fakeSink{}, Options{QueueSize: 2})
	for range 10 {
		p.Submit(event.Event{ID: "x"})
	}
	if got := p.Stats().Dropped; got != 8 {
		t.Errorf("Dropped = %d, want 8", got)
	}
	if got := p.Stats().Submitted; got != 10 {
		t.Errorf("Submitted = %d, want 10", got)
	}
}

func TestBlockingModeAppliesBackpressure(t *testing.T) {
	p := newPipeline(t, &fakeSink{}, Options{QueueSize: 1, BlockOnFull: true})
	done := make(chan struct{})
	go func() {
		p.Submit(event.Event{ID: "1"})
		p.Submit(event.Event{ID: "2"})
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("Submit returned without a consumer; expected it to block")
	case <-time.After(150 * time.Millisecond):
	}
	p.Close() // releases the blocked Submit
	<-done
	if got := p.Stats().Dropped; got != 0 {
		t.Errorf("Dropped = %d, want 0 in blocking mode", got)
	}
}

func TestSubscriberReceivesLiveEvents(t *testing.T) {
	p := newPipeline(t, &fakeSink{}, Options{BatchInterval: time.Hour})
	p.Start(context.Background())
	ch, cancel := p.Subscribe(4)
	defer cancel()

	p.Submit(event.Event{ID: "live"})
	select {
	case e := <-ch:
		if e.ID != "live" {
			t.Errorf("ID = %q", e.ID)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("subscriber received nothing")
	}
}

func TestSlowSubscriberDoesNotBlockProducer(t *testing.T) {
	p := newPipeline(t, &fakeSink{}, Options{BatchInterval: time.Hour})
	p.Start(context.Background())
	_, cancel := p.Subscribe(1)
	defer cancel()

	for i := range 500 {
		p.Submit(event.Event{ID: string(rune('a' + i%26))})
	}
	waitFor(t, func() bool { return p.Stats().Spooled >= 500 })
}

func TestCancelUnsubscribes(t *testing.T) {
	p := newPipeline(t, &fakeSink{}, Options{})
	_, cancel := p.Subscribe(1)
	if p.Stats().Subscribers != 1 {
		t.Fatalf("Subscribers = %d, want 1", p.Stats().Subscribers)
	}
	cancel()
	cancel() // idempotent
	if p.Stats().Subscribers != 0 {
		t.Errorf("Subscribers = %d, want 0", p.Stats().Subscribers)
	}
}

func TestSinkFailureRetainsEventsAndRetries(t *testing.T) {
	sink := &fakeSink{failN: 2}
	p := newPipeline(t, sink, Options{BatchInterval: 10 * time.Millisecond})
	p.Start(context.Background())

	p.Submit(event.Event{ID: "retry-me"})
	waitFor(t, func() bool { return len(sink.events()) == 1 })
	if sink.events()[0].ID != "retry-me" {
		t.Errorf("wrong event delivered: %+v", sink.events()[0])
	}
	if p.Stats().SinkErrors < 2 {
		t.Errorf("SinkErrors = %d, want at least 2", p.Stats().SinkErrors)
	}
}

func TestEventsSurviveRestart(t *testing.T) {
	dir := t.TempDir()
	opts := spool.Options{SegmentBytes: 1 << 20, MaxBytes: 8 << 20}

	// A sink that always fails models a crash: nothing is committed, so every
	// event must still be in the spool after restart.
	sp, _ := spool.Open(dir, opts)
	p := New(sp, &fakeSink{failN: 1 << 30}, Options{BatchInterval: 10 * time.Millisecond})
	p.Start(context.Background())
	for i := range 50 {
		p.Submit(event.Event{ID: string(rune('a' + i%26)), Status: uint16(200 + i)})
	}
	waitFor(t, func() bool { return p.Stats().Spooled == 50 })
	p.Close()
	sp.Close()

	sink := &fakeSink{}
	sp2, _ := spool.Open(dir, opts)
	defer sp2.Close()
	p2 := New(sp2, sink, Options{BatchInterval: 10 * time.Millisecond})
	p2.Start(context.Background())
	defer p2.Close()

	waitFor(t, func() bool { return len(sink.events()) == 50 })
}

func TestNextBackoffCaps(t *testing.T) {
	d := time.Duration(0)
	for range 20 {
		d = nextBackoff(d)
	}
	if d != 30*time.Second {
		t.Errorf("backoff = %s, want 30s cap", d)
	}
}
