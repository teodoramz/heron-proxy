// Package alerts evaluates alert rules against the live event stream and
// delivers notifications.
package alerts

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/amzteodor/heron/internal/pipeline/event"
	"github.com/amzteodor/heron/internal/store"
)

// Source supplies the live event stream.
type Source interface {
	Subscribe(buffer int) (<-chan event.Event, func())
}

// RuleStore supplies and updates alert rules.
type RuleStore interface {
	ListAlertRules(ctx context.Context) ([]store.AlertRule, error)
	TouchAlertFired(ctx context.Context, id string) error
}

// Engine matches events against alert rules and dispatches notifications.
type Engine struct {
	src     Source
	store   RuleStore
	client  *http.Client
	log     *slog.Logger
	refresh time.Duration

	mu      sync.RWMutex
	rules   []store.AlertRule
	lastRun map[string]time.Time
}

// New builds an Engine.
func New(src Source, rules RuleStore, log *slog.Logger) *Engine {
	if log == nil {
		log = slog.Default()
	}
	return &Engine{
		src:     src,
		store:   rules,
		client:  &http.Client{Timeout: 10 * time.Second},
		log:     log,
		refresh: 30 * time.Second,
		lastRun: make(map[string]time.Time),
	}
}

// Run consumes the event stream until the context is cancelled.
func (e *Engine) Run(ctx context.Context) {
	e.reload(ctx)

	events, cancel := e.src.Subscribe(1024)
	defer cancel()

	ticker := time.NewTicker(e.refresh)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.reload(ctx)
		case ev, ok := <-events:
			if !ok {
				return
			}
			e.evaluate(ctx, ev)
		}
	}
}

func (e *Engine) reload(ctx context.Context) {
	rules, err := e.store.ListAlertRules(ctx)
	if err != nil {
		e.log.Error("alert rule reload failed", "err", err)
		return
	}
	e.mu.Lock()
	e.rules = rules
	e.mu.Unlock()
}

// evaluate dispatches every rule the event satisfies, subject to throttling.
func (e *Engine) evaluate(ctx context.Context, ev event.Event) {
	e.mu.RLock()
	rules := e.rules
	e.mu.RUnlock()

	for _, rule := range rules {
		if !rule.Enabled || !Matches(rule, ev) {
			continue
		}
		if !e.allow(rule) {
			continue
		}
		if err := e.deliver(ctx, rule, ev); err != nil {
			e.log.Error("alert delivery failed", "rule", rule.Name, "err", err)
			continue
		}
		if err := e.store.TouchAlertFired(ctx, rule.ID); err != nil {
			e.log.Warn("alert timestamp not recorded", "rule", rule.Name, "err", err)
		}
	}
}

// allow enforces the per-rule throttle.
func (e *Engine) allow(rule store.AlertRule) bool {
	e.mu.Lock()
	defer e.mu.Unlock()

	throttle := time.Duration(rule.ThrottleSeconds) * time.Second
	last, ok := e.lastRun[rule.ID]
	if !ok && rule.LastFiredAt != nil {
		last = *rule.LastFiredAt
	}
	if time.Since(last) < throttle {
		return false
	}
	e.lastRun[rule.ID] = time.Now()
	return true
}

// Matches reports whether an event satisfies every set field of a condition.
func Matches(rule store.AlertRule, ev event.Event) bool {
	if rule.AppID != "" && rule.AppID != ev.AppID {
		return false
	}
	c := rule.Condition

	if c.WouldBlock && !ev.WouldBlock {
		return false
	}
	if c.MinAnomaly > 0 && ev.AnomalyScore < c.MinAnomaly {
		return false
	}
	if c.StatusAtLeast > 0 && ev.Status < c.StatusAtLeast {
		return false
	}
	if c.PathPrefix != "" && !strings.HasPrefix(ev.Path, c.PathPrefix) {
		return false
	}
	if len(c.RuleIDs) > 0 && !hasAnyUint(ev.RuleIDs, c.RuleIDs) {
		return false
	}
	if len(c.RuleTags) > 0 && !hasAnyString(ev.RuleTags, c.RuleTags) {
		return false
	}
	return true
}

func hasAnyUint(have, want []uint32) bool {
	for _, w := range want {
		for _, h := range have {
			if h == w {
				return true
			}
		}
	}
	return false
}

func hasAnyString(have, want []string) bool {
	for _, w := range want {
		for _, h := range have {
			if h == w {
				return true
			}
		}
	}
	return false
}

// deliver posts the notification in the channel's expected shape.
func (e *Engine) deliver(ctx context.Context, rule store.AlertRule, ev event.Event) error {
	payload, err := buildPayload(rule, ev)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rule.TargetURL, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("alerts: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := e.client.Do(req)
	if err != nil {
		return fmt.Errorf("alerts: post: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("alerts: %s returned %s", rule.Channel, resp.Status)
	}
	return nil
}

// Payload is the body sent to a plain webhook.
type Payload struct {
	Alert      string    `json:"alert"`
	AppID      string    `json:"app_id"`
	EventID    string    `json:"event_id"`
	TS         time.Time `json:"ts"`
	ClientIP   string    `json:"client_ip"`
	Method     string    `json:"method"`
	Host       string    `json:"host"`
	Path       string    `json:"path"`
	Status     uint16    `json:"status"`
	Anomaly    uint16    `json:"anomaly_score"`
	WouldBlock bool      `json:"would_block"`
	RuleIDs    []uint32  `json:"rule_ids,omitempty"`
	RuleTags   []string  `json:"rule_tags,omitempty"`
}

func buildPayload(rule store.AlertRule, ev event.Event) ([]byte, error) {
	p := Payload{
		Alert: rule.Name, AppID: ev.AppID, EventID: ev.ID, TS: ev.TS,
		ClientIP: ev.ClientIP.String(), Method: ev.Method, Host: ev.Host, Path: ev.Path,
		Status: ev.Status, Anomaly: ev.AnomalyScore, WouldBlock: ev.WouldBlock,
		RuleIDs: ev.RuleIDs, RuleTags: ev.RuleTags,
	}

	text := summarize(p)
	if rule.Template != "" {
		rendered, err := render(rule.Template, p)
		if err != nil {
			return nil, err
		}
		text = rendered
	}

	switch rule.Channel {
	// Mattermost and Slack both read "text"; Discord reads "content".
	case "slack", "mattermost":
		return json.Marshal(map[string]string{"text": text})
	case "discord":
		return json.Marshal(map[string]string{"content": text})
	default:
		// A template on a plain webhook is the whole body, so any shape the
		// receiver wants can be written out directly.
		if rule.Template != "" {
			return []byte(text), nil
		}
		return json.Marshal(p)
	}
}

// render fills a rule's template from the event. Fields are named as in
// Payload, for example {{.Method}} {{.Host}}{{.Path}} from {{.ClientIP}}.
func render(tmpl string, p Payload) (string, error) {
	t, err := template.New("alert").Option("missingkey=error").Parse(tmpl)
	if err != nil {
		return "", fmt.Errorf("alerts: template: %w", err)
	}
	var b strings.Builder
	if err := t.Execute(&b, p); err != nil {
		return "", fmt.Errorf("alerts: template: %w", err)
	}
	return b.String(), nil
}

// ValidTemplate reports whether a template parses and runs, so a rule can be
// rejected when it is saved rather than when it first fires.
func ValidTemplate(tmpl string) error {
	if tmpl == "" {
		return nil
	}
	_, err := render(tmpl, Payload{TS: time.Now()})
	return err
}

func summarize(p Payload) string {
	return fmt.Sprintf("[%s] %s %s%s from %s → %d (anomaly %d, rules %v)",
		p.Alert, p.Method, p.Host, p.Path, p.ClientIP, p.Status, p.Anomaly, p.RuleIDs)
}
