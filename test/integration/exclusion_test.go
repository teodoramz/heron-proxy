package integration

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/amzteodor/heron/internal/api/query"
	"github.com/amzteodor/heron/internal/pipeline/event"
	"github.com/amzteodor/heron/internal/store"
)

const (
	sqliPath = "/get?id=1%27%20OR%20%271%27%3D%271%20--%20"
	xssPath  = "/find?q=%3Cscript%3Ealert(1)%3C/script%3E"
)

// latestFor waits for a recorded event for a path other than notID.
//
// Identity, not time, is what separates the requests here: a test runs inside a
// few milliseconds and ClickHouse stores millisecond precision, so a timestamp
// bound cannot tell one request from the next.
func (s *stack) latestFor(t *testing.T, path, notID string) event.Event {
	t.Helper()
	f := query.Filter{
		From: time.Now().Add(-10 * time.Minute),
		To:   time.Now().Add(time.Minute),
		Apps: []string{s.appID},
		Root: query.Group{Op: "and", Conditions: []query.Condition{
			{Field: "path", Op: query.OpEq, Value: path},
		}},
	}
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		page, err := s.reader.List(context.Background(), f)
		if err == nil {
			for _, e := range page.Events {
				if e.ID != notID {
					return e
				}
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("no new event recorded for %s", path)
	return event.Event{}
}

// TestExclusionSilencesOnlyItsRule is the guarantee behind the tuning page: an
// exclusion must stop the rule it names, leave every other detection working,
// and never change what the application returns.
func TestExclusionSilencesOnlyItsRule(t *testing.T) {
	s := newStack(t)

	// Before: both attacks are detected and both reach the upstream.
	sqliBefore := s.send(t, http.MethodGet, sqliPath, "")
	xssBefore := s.send(t, http.MethodGet, xssPath, "")
	bodyBefore := readBody(t, sqliBefore)
	xssBefore.Body.Close()

	sqliEvent := s.latestFor(t, "/get", "")
	xssEvent := s.latestFor(t, "/find", "")

	if !hasRule(sqliEvent, "942") {
		t.Fatalf("no SQLi rule before the exclusion: %v", sqliEvent.RuleIDs)
	}
	if !hasRule(xssEvent, "941") {
		t.Fatalf("no XSS rule before the exclusion: %v", xssEvent.RuleIDs)
	}

	// Exclude the SQLi rule the way the UI would.
	rule := ruleIDWithPrefix(sqliEvent, "942")
	directive := store.BuildSecLang(store.Exclusion{RuleID: int64(rule)}, 10000000)
	if directive != "SecRuleRemoveById "+itoa(rule) {
		t.Fatalf("unexpected directive %q", directive)
	}
	s.reconfigure([]string{directive})

	// After: the excluded rule is silent.
	sqliAfter := s.send(t, http.MethodGet, sqliPath+"&pass=2", "")
	afterBody := readBody(t, sqliAfter)

	excluded := s.latestFor(t, "/get", sqliEvent.ID)
	for _, id := range excluded.RuleIDs {
		if id == rule {
			t.Errorf("rule %d still fired after being excluded: %v", rule, excluded.RuleIDs)
		}
	}

	// The application is untouched: same status, same body, still proxied.
	if sqliAfter.StatusCode != sqliBefore.StatusCode {
		t.Errorf("status changed after excluding a rule: %d then %d",
			sqliBefore.StatusCode, sqliAfter.StatusCode)
	}
	if !strings.Contains(afterBody, "upstream saw") || !strings.Contains(bodyBefore, "upstream saw") {
		t.Errorf("the request stopped reaching the upstream: %q", afterBody)
	}

	// Every other detection still works.
	s.send(t, http.MethodGet, xssPath+"&pass=2", "").Body.Close()
	xssAfter := s.latestFor(t, "/find", xssEvent.ID)
	if !hasRule(xssAfter, "941") {
		t.Errorf("excluding a SQLi rule silenced XSS detection too: %v", xssAfter.RuleIDs)
	}
}

// TestTargetedExclusionKeepsTheRuleWorkingElsewhere checks the narrow form: the
// rule stops looking at one parameter and keeps working on the others.
func TestTargetedExclusionKeepsTheRuleWorkingElsewhere(t *testing.T) {
	s := newStack(t)

	const payload = "1%27%20OR%20%271%27%3D%271%20--%20"
	s.send(t, http.MethodGet, "/probe?editor="+payload, "").Body.Close()
	first := s.latestFor(t, "/probe", "")

	rule := ruleIDWithPrefix(first, "942")
	if rule == 0 {
		t.Fatalf("no SQLi rule fired: %v", first.RuleIDs)
	}

	s.reconfigure([]string{
		store.BuildSecLang(store.Exclusion{RuleID: int64(rule), Target: "ARGS:editor"}, 10000000),
	})

	// The excluded parameter is now ignored by that rule.
	s.send(t, http.MethodGet, "/quiet?editor="+payload, "").Body.Close()
	quiet := s.latestFor(t, "/quiet", "")
	for _, id := range quiet.RuleIDs {
		if id == rule {
			t.Errorf("rule %d still inspected the excluded parameter", rule)
		}
	}

	// A different parameter still trips the same rule.
	s.send(t, http.MethodGet, "/loud?other="+payload, "").Body.Close()
	loud := s.latestFor(t, "/loud", "")
	var stillFires bool
	for _, id := range loud.RuleIDs {
		if id == rule {
			stillFires = true
		}
	}
	if !stillFires {
		t.Errorf("rule %d stopped working on other parameters: %v", rule, loud.RuleIDs)
	}
}

// TestDisablingAnExclusionRestoresTheRule covers the undo path.
func TestDisablingAnExclusionRestoresTheRule(t *testing.T) {
	s := newStack(t)

	s.send(t, http.MethodGet, "/on?id=1%27%20OR%20%271%27%3D%271", "").Body.Close()
	rule := ruleIDWithPrefix(s.latestFor(t, "/on", ""), "942")
	if rule == 0 {
		t.Fatal("no SQLi rule fired")
	}

	s.reconfigure([]string{store.BuildSecLang(store.Exclusion{RuleID: int64(rule)}, 10000000)})
	s.send(t, http.MethodGet, "/off?id=1%27%20OR%20%271%27%3D%271", "").Body.Close()
	if containsRule(s.latestFor(t, "/off", ""), rule) {
		t.Fatal("the exclusion did not take effect")
	}

	// Removing the exclusion, as disabling it in the UI does, brings the rule back.
	s.reconfigure(nil)
	s.send(t, http.MethodGet, "/back?id=1%27%20OR%20%271%27%3D%271", "").Body.Close()
	if !containsRule(s.latestFor(t, "/back", ""), rule) {
		t.Errorf("rule %d did not come back after the exclusion was removed", rule)
	}
}

func ruleIDWithPrefix(e event.Event, prefix string) uint32 {
	for _, id := range e.RuleIDs {
		if strings.HasPrefix(itoa(id), prefix) {
			return id
		}
	}
	return 0
}

func containsRule(e event.Event, want uint32) bool {
	for _, id := range e.RuleIDs {
		if id == want {
			return true
		}
	}
	return false
}

func itoa(v uint32) string { return strconv.FormatUint(uint64(v), 10) }

func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	var sb strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(buf)
		sb.Write(buf[:n])
		if err != nil {
			break
		}
	}
	return sb.String()
}
