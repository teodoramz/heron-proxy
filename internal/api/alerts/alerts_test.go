package alerts

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/amzteodor/proxy-waf/internal/pipeline/event"
	"github.com/amzteodor/proxy-waf/internal/store"
)

func testEvent() event.Event {
	return event.Event{
		ID:           "evt-1",
		AppID:        "api",
		Path:         "/v1/login",
		Status:       403,
		AnomalyScore: 15,
		RuleIDs:      []uint32{942100},
		RuleTags:     []string{"attack-sqli"},
		WouldBlock:   true,
	}
}

func rule(cond store.AlertCondition) store.AlertRule {
	return store.AlertRule{
		ID: "r1", Name: "test", Channel: "webhook", TargetURL: "https://hook.example",
		Enabled: true, Condition: cond,
	}
}

func TestMatchesConditions(t *testing.T) {
	e := testEvent()
	cases := []struct {
		name string
		rule store.AlertRule
		want bool
	}{
		{"empty condition matches", rule(store.AlertCondition{}), true},
		{"rule id", rule(store.AlertCondition{RuleIDs: []uint32{942100}}), true},
		{"other rule id", rule(store.AlertCondition{RuleIDs: []uint32{930120}}), false},
		{"rule tag", rule(store.AlertCondition{RuleTags: []string{"attack-sqli"}}), true},
		{"other rule tag", rule(store.AlertCondition{RuleTags: []string{"attack-xss"}}), false},
		{"anomaly met", rule(store.AlertCondition{MinAnomaly: 10}), true},
		{"anomaly not met", rule(store.AlertCondition{MinAnomaly: 20}), false},
		{"would block", rule(store.AlertCondition{WouldBlock: true}), true},
		{"status at least", rule(store.AlertCondition{StatusAtLeast: 400}), true},
		{"status too high", rule(store.AlertCondition{StatusAtLeast: 500}), false},
		{"path prefix", rule(store.AlertCondition{PathPrefix: "/v1/"}), true},
		{"other path", rule(store.AlertCondition{PathPrefix: "/admin"}), false},
		{"all conditions", rule(store.AlertCondition{
			RuleTags: []string{"attack-sqli"}, MinAnomaly: 10, WouldBlock: true, PathPrefix: "/v1/",
		}), true},
		{"one condition fails", rule(store.AlertCondition{
			RuleTags: []string{"attack-sqli"}, MinAnomaly: 100,
		}), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Matches(c.rule, e); got != c.want {
				t.Errorf("got %v, want %v", got, c.want)
			}
		})
	}
}

func TestMatchesAppScope(t *testing.T) {
	e := testEvent()
	r := rule(store.AlertCondition{})
	r.AppID = "web"
	if Matches(r, e) {
		t.Error("rule for another app matched")
	}
	r.AppID = "api"
	if !Matches(r, e) {
		t.Error("rule for the event's app did not match")
	}
}

// fakeRules serves a fixed rule set and records fired timestamps.
type fakeRules struct {
	mu    sync.Mutex
	rules []store.AlertRule
	fired []string
}

func (f *fakeRules) ListAlertRules(context.Context) ([]store.AlertRule, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]store.AlertRule(nil), f.rules...), nil
}

func (f *fakeRules) TouchAlertFired(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fired = append(f.fired, id)
	return nil
}

func (f *fakeRules) firedCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.fired)
}

// fakeSource replays a fixed set of events.
type fakeSource struct{ ch chan event.Event }

func (f *fakeSource) Subscribe(int) (<-chan event.Event, func()) { return f.ch, func() {} }

// recorder captures webhook deliveries.
type recorder struct {
	mu     sync.Mutex
	bodies []string
	server *httptest.Server
}

func newRecorder(t *testing.T) *recorder {
	t.Helper()
	r := &recorder{}
	r.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)
		r.mu.Lock()
		r.bodies = append(r.bodies, string(body))
		r.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(r.server.Close)
	return r
}

func (r *recorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.bodies)
}

func (r *recorder) first() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.bodies) == 0 {
		return ""
	}
	return r.bodies[0]
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

func TestEngineDeliversWebhook(t *testing.T) {
	rec := newRecorder(t)
	rules := &fakeRules{rules: []store.AlertRule{{
		ID: "r1", Name: "sqli", Channel: "webhook", TargetURL: rec.server.URL,
		Enabled: true, ThrottleSeconds: 1,
		Condition: store.AlertCondition{RuleTags: []string{"attack-sqli"}},
	}}}
	src := &fakeSource{ch: make(chan event.Event, 4)}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go New(src, rules, nil).Run(ctx)

	src.ch <- testEvent()
	waitFor(t, func() bool { return rec.count() == 1 })

	var payload Payload
	if err := json.Unmarshal([]byte(rec.first()), &payload); err != nil {
		t.Fatalf("payload: %v", err)
	}
	if payload.Alert != "sqli" || payload.EventID != "evt-1" || payload.Path != "/v1/login" {
		t.Errorf("payload = %+v", payload)
	}
	if rules.firedCount() != 1 {
		t.Errorf("fired count = %d", rules.firedCount())
	}
}

func TestEngineSkipsNonMatching(t *testing.T) {
	rec := newRecorder(t)
	rules := &fakeRules{rules: []store.AlertRule{{
		ID: "r1", Name: "xss", Channel: "webhook", TargetURL: rec.server.URL,
		Enabled: true, ThrottleSeconds: 1,
		Condition: store.AlertCondition{RuleTags: []string{"attack-xss"}},
	}}}
	src := &fakeSource{ch: make(chan event.Event, 4)}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go New(src, rules, nil).Run(ctx)

	src.ch <- testEvent()
	time.Sleep(200 * time.Millisecond)
	if rec.count() != 0 {
		t.Errorf("delivered %d notifications for a non-matching rule", rec.count())
	}
}

func TestEngineSkipsDisabledRule(t *testing.T) {
	rec := newRecorder(t)
	rules := &fakeRules{rules: []store.AlertRule{{
		ID: "r1", Name: "off", Channel: "webhook", TargetURL: rec.server.URL, Enabled: false,
	}}}
	src := &fakeSource{ch: make(chan event.Event, 4)}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go New(src, rules, nil).Run(ctx)

	src.ch <- testEvent()
	time.Sleep(200 * time.Millisecond)
	if rec.count() != 0 {
		t.Errorf("disabled rule delivered %d notifications", rec.count())
	}
}

func TestEngineThrottles(t *testing.T) {
	rec := newRecorder(t)
	rules := &fakeRules{rules: []store.AlertRule{{
		ID: "r1", Name: "sqli", Channel: "webhook", TargetURL: rec.server.URL,
		Enabled: true, ThrottleSeconds: 3600,
		Condition: store.AlertCondition{RuleTags: []string{"attack-sqli"}},
	}}}
	src := &fakeSource{ch: make(chan event.Event, 16)}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go New(src, rules, nil).Run(ctx)

	for range 5 {
		src.ch <- testEvent()
	}
	waitFor(t, func() bool { return rec.count() >= 1 })
	time.Sleep(200 * time.Millisecond)
	if rec.count() != 1 {
		t.Errorf("delivered %d notifications, want 1 under throttle", rec.count())
	}
}

func TestSlackPayloadShape(t *testing.T) {
	rec := newRecorder(t)
	rules := &fakeRules{rules: []store.AlertRule{{
		ID: "r1", Name: "sqli", Channel: "slack", TargetURL: rec.server.URL,
		Enabled: true, ThrottleSeconds: 1,
	}}}
	src := &fakeSource{ch: make(chan event.Event, 4)}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go New(src, rules, nil).Run(ctx)

	src.ch <- testEvent()
	waitFor(t, func() bool { return rec.count() == 1 })

	var body map[string]string
	if err := json.Unmarshal([]byte(rec.first()), &body); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body["text"], "/v1/login") {
		t.Errorf("slack text = %q", body["text"])
	}
	if body["content"] == "" {
		t.Error("discord content field missing")
	}
}

func TestDeliveryFailureDoesNotMarkFired(t *testing.T) {
	failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer failing.Close()

	rules := &fakeRules{rules: []store.AlertRule{{
		ID: "r1", Name: "sqli", Channel: "webhook", TargetURL: failing.URL,
		Enabled: true, ThrottleSeconds: 1,
	}}}
	src := &fakeSource{ch: make(chan event.Event, 4)}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go New(src, rules, nil).Run(ctx)

	src.ch <- testEvent()
	time.Sleep(300 * time.Millisecond)
	if rules.firedCount() != 0 {
		t.Errorf("failed delivery marked as fired %d times", rules.firedCount())
	}
}
