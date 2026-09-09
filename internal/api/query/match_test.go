package query

import (
	"net/netip"
	"testing"

	"github.com/amzteodor/heron/internal/pipeline/event"
)

func sampleEvent() *event.Event {
	return &event.Event{
		ID:           "3a1f2b4c-5d6e-4f70-8192-a3b4c5d6e7f8",
		AppID:        "api",
		ClientIP:     netip.MustParseAddr("203.0.113.7"),
		Country:      "DE",
		ASN:          64512,
		JA4:          "t13d1516h2_8daaf6152771_02713d6af862",
		Method:       "POST",
		Host:         "api.example",
		Path:         "/v1/login",
		Query:        "debug=1",
		UserAgent:    "sqlmap/1.7",
		Status:       403,
		AnomalyScore: 12,
		RuleIDs:      []uint32{942100, 949110},
		RuleTags:     []string{"attack-sqli", "paranoia-level/1"},
		WouldBlock:   true,
		ReqHeaders:   map[string]string{"content-type": "application/json", "x-api-key": "abc"},
		ReqBody:      `{"user":"' OR 1=1"}`,
	}
}

func match(t *testing.T, f Filter, e *event.Event) bool {
	t.Helper()
	m, err := NewMatcher(f)
	if err != nil {
		t.Fatalf("NewMatcher: %v", err)
	}
	return m.Match(e)
}

func filterWith(conds ...Condition) Filter {
	return Filter{Root: Group{Op: "and", Conditions: conds}}
}

func TestMatcherFieldsAndOperators(t *testing.T) {
	e := sampleEvent()
	cases := []struct {
		name string
		cond Condition
		want bool
	}{
		{"status eq", Condition{Field: "status", Op: OpEq, Value: 403}, true},
		{"status ne", Condition{Field: "status", Op: OpEq, Value: 200}, false},
		{"status gte", Condition{Field: "status", Op: OpGte, Value: 400}, true},
		{"status lt", Condition{Field: "status", Op: OpLt, Value: 400}, false},
		{"status in", Condition{Field: "status", Op: OpIn, Value: []any{401, 403}}, true},
		{"method eq", Condition{Field: "method", Op: OpEq, Value: "POST"}, true},
		{"path prefix", Condition{Field: "path", Op: OpPrefix, Value: "/v1/"}, true},
		{"path suffix", Condition{Field: "path", Op: OpSuffix, Value: "/login"}, true},
		{"path contains", Condition{Field: "path", Op: OpContains, Value: "LOG"}, true},
		{"path regex", Condition{Field: "path", Op: OpRegex, Value: `^/v\d+/login$`}, true},
		{"path regex no match", Condition{Field: "path", Op: OpRegex, Value: `^/admin`}, false},
		{"ua contains", Condition{Field: "user_agent", Op: OpContains, Value: "sqlmap"}, true},
		{"body contains", Condition{Field: "body", Op: OpContains, Value: "or 1=1"}, true},
		{"rule id has", Condition{Field: "rule_id", Op: OpHas, Value: 942100}, true},
		{"rule id absent", Condition{Field: "rule_id", Op: OpHas, Value: 930120}, false},
		{"rule id any", Condition{Field: "rule_id", Op: OpIn, Value: []any{930120, 942100}}, true},
		{"rule tag has", Condition{Field: "rule_tag", Op: OpHas, Value: "attack-sqli"}, true},
		{"would block", Condition{Field: "would_block", Op: OpEq, Value: true}, true},
		{"not websocket", Condition{Field: "is_websocket", Op: OpEq, Value: false}, true},
		{"anomaly gte", Condition{Field: "anomaly_score", Op: OpGte, Value: 5}, true},
		{"ip eq", Condition{Field: "client_ip", Op: OpEq, Value: "203.0.113.7"}, true},
		{"ip cidr", Condition{Field: "client_ip", Op: OpCIDR, Value: "203.0.113.0/24"}, true},
		{"ip cidr outside", Condition{Field: "client_ip", Op: OpCIDR, Value: "10.0.0.0/8"}, false},
		{"country eq", Condition{Field: "country", Op: OpEq, Value: "DE"}, true},
		{"asn eq", Condition{Field: "asn", Op: OpEq, Value: 64512}, true},
		{"ja4 prefix", Condition{Field: "ja4", Op: OpPrefix, Value: "t13d"}, true},
		{"header eq", Condition{Field: "req_header", Op: OpEq, Key: "Content-Type", Value: "application/json"}, true},
		{"header exists", Condition{Field: "req_header", Op: OpExists, Key: "X-Api-Key"}, true},
		{"header absent", Condition{Field: "req_header", Op: OpExists, Key: "Authorization"}, false},
		{"error exists", Condition{Field: "error", Op: OpExists}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := match(t, filterWith(c.cond), e); got != c.want {
				t.Errorf("got %v, want %v", got, c.want)
			}
		})
	}
}

func TestMatcherAndRequiresAll(t *testing.T) {
	e := sampleEvent()
	f := filterWith(
		Condition{Field: "status", Op: OpEq, Value: 403},
		Condition{Field: "method", Op: OpEq, Value: "GET"},
	)
	if match(t, f, e) {
		t.Error("AND matched when one condition failed")
	}
}

func TestMatcherOrRequiresAny(t *testing.T) {
	e := sampleEvent()
	f := Filter{Root: Group{Op: "or", Conditions: []Condition{
		{Field: "method", Op: OpEq, Value: "GET"},
		{Field: "status", Op: OpEq, Value: 403},
	}}}
	if !match(t, f, e) {
		t.Error("OR did not match when one condition held")
	}
}

func TestMatcherOrAllFalse(t *testing.T) {
	e := sampleEvent()
	f := Filter{Root: Group{Op: "or", Conditions: []Condition{
		{Field: "method", Op: OpEq, Value: "GET"},
		{Field: "status", Op: OpEq, Value: 200},
	}}}
	if match(t, f, e) {
		t.Error("OR matched with every condition false")
	}
}

func TestMatcherNestedGroups(t *testing.T) {
	e := sampleEvent()
	f := Filter{Root: Group{
		Op:         "and",
		Conditions: []Condition{{Field: "status", Op: OpGte, Value: 400}},
		Groups: []Group{{Op: "or", Conditions: []Condition{
			{Field: "rule_tag", Op: OpHas, Value: "attack-xss"},
			{Field: "rule_tag", Op: OpHas, Value: "attack-sqli"},
		}}},
	}}
	if !match(t, f, e) {
		t.Error("nested OR inside AND did not match")
	}
}

func TestMatcherNegation(t *testing.T) {
	e := sampleEvent()
	f := Filter{Root: Group{Op: "and", Groups: []Group{{
		Op:         "and",
		Not:        true,
		Conditions: []Condition{{Field: "path", Op: OpPrefix, Value: "/static/"}},
	}}}}
	if !match(t, f, e) {
		t.Error("negated non-matching group should pass")
	}

	f2 := Filter{Root: Group{Op: "and", Groups: []Group{{
		Op:         "and",
		Not:        true,
		Conditions: []Condition{{Field: "path", Op: OpPrefix, Value: "/v1/"}},
	}}}}
	if match(t, f2, e) {
		t.Error("negated matching group should fail")
	}
}

func TestMatcherAppScope(t *testing.T) {
	e := sampleEvent()
	f := Filter{Apps: []string{"other"}, Root: Group{Op: "and"}}
	if match(t, f, e) {
		t.Error("event from another app matched")
	}
	f.Apps = []string{"api", "other"}
	if !match(t, f, e) {
		t.Error("event in scope did not match")
	}
}

func TestMatcherEmptyFilterMatchesEverything(t *testing.T) {
	if !match(t, Filter{}, sampleEvent()) {
		t.Error("empty filter did not match")
	}
}

func TestMatcherRejectsInvalidFilter(t *testing.T) {
	if _, err := NewMatcher(filterWith(Condition{Field: "nope", Op: OpEq, Value: 1})); err == nil {
		t.Error("invalid filter accepted")
	}
}

func TestMatcherAgreesWithSQLFieldSet(t *testing.T) {
	// Every filterable field must be reachable by the matcher, so live tail and
	// the stored query cannot diverge.
	e := sampleEvent()
	for _, field := range Fields() {
		col := columns[field]
		var cond Condition
		switch col.kind {
		case kBool:
			cond = Condition{Field: field, Op: OpEq, Value: false}
		case kUInt:
			cond = Condition{Field: field, Op: OpGte, Value: 0}
		case kIP:
			cond = Condition{Field: field, Op: OpCIDR, Value: "0.0.0.0/0"}
		case kArrUInt32:
			cond = Condition{Field: field, Op: OpHas, Value: 1}
		case kArrString:
			cond = Condition{Field: field, Op: OpHas, Value: "x"}
		case kMap:
			cond = Condition{Field: field, Op: OpExists, Key: "content-type"}
		case kDateTime:
			continue // the live tail ignores the time range by design
		default:
			cond = Condition{Field: field, Op: OpContains, Value: ""}
		}
		if _, err := NewMatcher(filterWith(cond)); err != nil {
			t.Errorf("field %q not usable in a matcher: %v", field, err)
			continue
		}
		m, _ := NewMatcher(filterWith(cond))
		m.Match(e) // must not panic
	}
}
