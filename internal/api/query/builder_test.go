package query

import (
	"strings"
	"testing"
	"time"
)

func baseFilter(conds ...Condition) Filter {
	return Filter{
		From: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		To:   time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC),
		Root: Group{Op: "and", Conditions: conds},
	}
}

func mustWhere(t *testing.T, f Filter) (string, []any) {
	t.Helper()
	clause, args, err := Where(f)
	if err != nil {
		t.Fatalf("Where: %v", err)
	}
	return clause, args
}

func TestTimeRangeAlwaysBound(t *testing.T) {
	clause, args := mustWhere(t, baseFilter())
	if !strings.Contains(clause, "ts >= ? AND ts <= ?") {
		t.Errorf("clause = %q", clause)
	}
	if len(args) != 2 {
		t.Errorf("args = %v", args)
	}
}

func TestAppScoping(t *testing.T) {
	f := baseFilter()
	f.Apps = []string{"a", "b"}
	clause, args := mustWhere(t, f)
	if !strings.Contains(clause, "app_id IN (?)") {
		t.Errorf("clause = %q", clause)
	}
	if len(args) != 3 {
		t.Errorf("args = %v", args)
	}
}

func TestOperatorRendering(t *testing.T) {
	cases := []struct {
		name string
		cond Condition
		want string
	}{
		{"status eq", Condition{Field: "status", Op: OpEq, Value: 404}, "status = ?"},
		{"status gte", Condition{Field: "status", Op: OpGte, Value: 500}, "status >= ?"},
		{"status in", Condition{Field: "status", Op: OpIn, Value: []any{401, 403}}, "status IN (?)"},
		{"path prefix", Condition{Field: "path", Op: OpPrefix, Value: "/api"}, "startsWith(path, ?)"},
		{"path contains", Condition{Field: "path", Op: OpContains, Value: "admin"}, "positionCaseInsensitive(path, ?) > 0"},
		{"path regex", Condition{Field: "path", Op: OpRegex, Value: "^/v[0-9]+/"}, "match(path, ?)"},
		{"body contains", Condition{Field: "body", Op: OpContains, Value: "union select"}, "positionCaseInsensitive(req_body_inline, ?) > 0"},
		{"rule id", Condition{Field: "rule_id", Op: OpHas, Value: 942100}, "has(rule_ids, ?)"},
		{"rule tag", Condition{Field: "rule_tag", Op: OpHas, Value: "attack-sqli"}, "has(rule_tags, ?)"},
		{"rule any", Condition{Field: "rule_id", Op: OpIn, Value: []any{942100, 941100}}, "hasAny(rule_ids, ?)"},
		{"would block", Condition{Field: "would_block", Op: OpEq, Value: true}, "would_block = ?"},
		{"ip eq", Condition{Field: "client_ip", Op: OpEq, Value: "203.0.113.5"}, "client_ip = toIPv6(?)"},
		{"ip cidr", Condition{Field: "client_ip", Op: OpCIDR, Value: "10.0.0.0/8"}, "isIPAddressInRange(IPv6NumToString(client_ip), ?)"},
		{"header eq", Condition{Field: "req_header", Op: OpEq, Key: "X-Api-Key", Value: "k"}, "req_headers[?] = ?"},
		{"header exists", Condition{Field: "req_header", Op: OpExists, Key: "Authorization"}, "mapContains(req_headers, ?)"},
		{"error exists", Condition{Field: "error", Op: OpExists}, "error != ''"},
		{"anomaly gte", Condition{Field: "anomaly_score", Op: OpGte, Value: 5}, "anomaly_score >= ?"},
		{"websocket", Condition{Field: "is_websocket", Op: OpEq, Value: true}, "is_websocket = ?"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			clause, _ := mustWhere(t, baseFilter(c.cond))
			if !strings.Contains(clause, c.want) {
				t.Errorf("clause %q does not contain %q", clause, c.want)
			}
		})
	}
}

func TestHeaderKeyLowercased(t *testing.T) {
	_, args := mustWhere(t, baseFilter(Condition{Field: "req_header", Op: OpEq, Key: "X-Api-Key", Value: "k"}))
	if args[2] != "x-api-key" {
		t.Errorf("key arg = %v, want lowercased", args[2])
	}
}

func TestBooleanCoercion(t *testing.T) {
	for _, v := range []any{true, float64(1), "true", "1"} {
		_, args := mustWhere(t, baseFilter(Condition{Field: "would_block", Op: OpEq, Value: v}))
		if args[2] != uint8(1) {
			t.Errorf("value %v became %v, want 1", v, args[2])
		}
	}
	for _, v := range []any{false, float64(0), "false"} {
		_, args := mustWhere(t, baseFilter(Condition{Field: "would_block", Op: OpEq, Value: v}))
		if args[2] != uint8(0) {
			t.Errorf("value %v became %v, want 0", v, args[2])
		}
	}
}

func TestUnknownFieldRejected(t *testing.T) {
	_, _, err := Where(baseFilter(Condition{Field: "password_hash; DROP TABLE traffic", Op: OpEq, Value: "x"}))
	if err == nil {
		t.Fatal("unknown field accepted")
	}
	if !strings.Contains(err.Error(), "unknown field") {
		t.Errorf("err = %v", err)
	}
}

func TestUnknownOperatorRejected(t *testing.T) {
	if _, _, err := Where(baseFilter(Condition{Field: "status", Op: Op("; DROP TABLE"), Value: 1})); err == nil {
		t.Fatal("unknown operator accepted")
	}
}

func TestOperatorNotAllowedForKind(t *testing.T) {
	if _, _, err := Where(baseFilter(Condition{Field: "status", Op: OpRegex, Value: ".*"})); err == nil {
		t.Fatal("regex accepted on a numeric column")
	}
	if _, _, err := Where(baseFilter(Condition{Field: "client_ip", Op: OpContains, Value: "10."})); err == nil {
		t.Fatal("contains accepted on an IP column")
	}
}

// TestInjectionAttemptStaysAParameter is the core safety property: hostile input
// must appear only in args, never in the statement.
func TestInjectionAttemptStaysAParameter(t *testing.T) {
	payload := "x' OR 1=1 --"
	clause, args := mustWhere(t, baseFilter(Condition{Field: "path", Op: OpContains, Value: payload}))

	if strings.Contains(clause, payload) || strings.Contains(clause, "OR 1=1") {
		t.Fatalf("payload leaked into SQL: %q", clause)
	}
	var found bool
	for _, a := range args {
		if a == payload {
			found = true
		}
	}
	if !found {
		t.Error("payload did not reach the bound arguments")
	}
}

func TestMapFieldRequiresKey(t *testing.T) {
	if _, _, err := Where(baseFilter(Condition{Field: "req_header", Op: OpEq, Value: "v"})); err == nil {
		t.Fatal("map field accepted without a key")
	}
}

func TestOversizedRegexRejected(t *testing.T) {
	long := strings.Repeat("a", maxRegexLen+1)
	if _, _, err := Where(baseFilter(Condition{Field: "path", Op: OpRegex, Value: long})); err == nil {
		t.Fatal("oversized regex accepted")
	}
}

func TestNestedGroupsAndOr(t *testing.T) {
	f := Filter{
		From: time.Now().Add(-time.Hour), To: time.Now(),
		Root: Group{
			Op:         "and",
			Conditions: []Condition{{Field: "status", Op: OpGte, Value: 400}},
			Groups: []Group{{
				Op: "or",
				Conditions: []Condition{
					{Field: "rule_tag", Op: OpHas, Value: "attack-sqli"},
					{Field: "rule_tag", Op: OpHas, Value: "attack-xss"},
				},
			}},
		},
	}
	clause, args := mustWhere(t, f)
	if !strings.Contains(clause, " OR ") {
		t.Errorf("OR group not rendered: %q", clause)
	}
	if !strings.Contains(clause, " AND ") {
		t.Errorf("AND join not rendered: %q", clause)
	}
	if len(args) != 5 {
		t.Errorf("args = %d, want 5", len(args))
	}
}

func TestNegatedGroup(t *testing.T) {
	f := baseFilter()
	f.Root.Groups = []Group{{Op: "or", Not: true, Conditions: []Condition{
		{Field: "path", Op: OpPrefix, Value: "/static/"},
	}}}
	clause, _ := mustWhere(t, f)
	if !strings.Contains(clause, "NOT (") {
		t.Errorf("negation not rendered: %q", clause)
	}
}

func TestEmptyGroupProducesNoClause(t *testing.T) {
	f := baseFilter()
	f.Root.Groups = []Group{{Op: "and"}}
	clause, args := mustWhere(t, f)
	if strings.Contains(clause, "()") {
		t.Errorf("empty group rendered: %q", clause)
	}
	if len(args) != 2 {
		t.Errorf("args = %v", args)
	}
}

func TestDepthLimit(t *testing.T) {
	g := Group{Op: "and"}
	cur := &g
	for range maxDepth + 2 {
		cur.Groups = []Group{{Op: "and"}}
		cur = &cur.Groups[0]
	}
	f := Filter{From: time.Now().Add(-time.Hour), To: time.Now(), Root: g}
	if _, _, err := Where(f); err == nil {
		t.Fatal("excessive nesting accepted")
	}
}

func TestUnknownGroupOperatorRejected(t *testing.T) {
	f := baseFilter()
	f.Root.Op = "xor"
	if _, _, err := Where(f); err == nil {
		t.Fatal("unknown group operator accepted")
	}
}

func TestListUsesKeysetNotOffset(t *testing.T) {
	sql, _, err := List(baseFilter())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToUpper(sql), "OFFSET") {
		t.Errorf("query uses OFFSET: %s", sql)
	}
	if !strings.Contains(sql, "ORDER BY ts DESC, id DESC") {
		t.Errorf("ordering wrong: %s", sql)
	}
}

func TestListFetchesOneExtraRow(t *testing.T) {
	f := baseFilter()
	f.Limit = 50
	sql, _, _ := List(f)
	if !strings.Contains(sql, "LIMIT 51") {
		t.Errorf("want LIMIT 51 to detect a next page, got: %s", sql)
	}
}

func TestListAppliesCursor(t *testing.T) {
	f := baseFilter()
	f.Cursor = EncodeCursor(Cursor{TS: time.Now().UTC(), ID: "3a1f2b4c-5d6e-4f70-8192-a3b4c5d6e7f8"})
	sql, args, err := List(f)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sql, "(ts, id) < (?, ?)") {
		t.Errorf("keyset predicate missing: %s", sql)
	}
	if len(args) != 4 {
		t.Errorf("args = %d, want 4", len(args))
	}
}

func TestAscendingOrderFlipsComparison(t *testing.T) {
	f := baseFilter()
	f.Order = "asc"
	f.Cursor = EncodeCursor(Cursor{TS: time.Now().UTC(), ID: "3a1f2b4c-5d6e-4f70-8192-a3b4c5d6e7f8"})
	sql, _, _ := List(f)
	if !strings.Contains(sql, "(ts, id) > (?, ?)") || !strings.Contains(sql, "ORDER BY ts ASC") {
		t.Errorf("ascending order wrong: %s", sql)
	}
}

func TestListRejectsBadCursor(t *testing.T) {
	f := baseFilter()
	f.Cursor = "!!!not-base64!!!"
	if _, _, err := List(f); err == nil {
		t.Fatal("invalid cursor accepted")
	}
}

func TestLimitCapped(t *testing.T) {
	f := baseFilter()
	f.Limit = 100000
	f.Normalize()
	if f.Limit != MaxLimit {
		t.Errorf("Limit = %d, want %d", f.Limit, MaxLimit)
	}
}

func TestCountIsCapped(t *testing.T) {
	sql, _, err := Count(baseFilter(), 10000)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sql, "LIMIT 10000") {
		t.Errorf("count not capped: %s", sql)
	}
}

func TestCursorRoundTrip(t *testing.T) {
	want := Cursor{TS: time.UnixMilli(1767225600123).UTC(), ID: "3a1f2b4c-5d6e-4f70-8192-a3b4c5d6e7f8"}
	got, err := DecodeCursor(EncodeCursor(want))
	if err != nil {
		t.Fatalf("DecodeCursor: %v", err)
	}
	if !got.TS.Equal(want.TS) || got.ID != want.ID {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestCursorRejectsBadInput(t *testing.T) {
	for _, token := range []string{"", "%%%", "bm90LWEtY3Vyc29y", EncodeCursor(Cursor{ID: "not-a-uuid"})} {
		if _, err := DecodeCursor(token); err == nil {
			t.Errorf("DecodeCursor(%q) accepted", token)
		}
	}
}

func TestParseFilterValidates(t *testing.T) {
	good := `{"root":{"op":"and","conditions":[{"field":"status","op":"eq","value":404}]}}`
	if _, err := ParseFilter([]byte(good)); err != nil {
		t.Errorf("valid filter rejected: %v", err)
	}
	bad := `{"root":{"op":"and","conditions":[{"field":"secret","op":"eq","value":1}]}}`
	if _, err := ParseFilter([]byte(bad)); err == nil {
		t.Error("filter with unknown field accepted")
	}
	if _, err := ParseFilter([]byte(`not json`)); err == nil {
		t.Error("malformed JSON accepted")
	}
}

func TestNormalizeDefaults(t *testing.T) {
	var f Filter
	f.Normalize()
	if f.Limit != DefaultLimit || f.Order != "desc" || f.Root.Op != "and" {
		t.Errorf("defaults wrong: %+v", f)
	}
	if f.From.IsZero() || f.To.IsZero() || !f.From.Before(f.To) {
		t.Errorf("time defaults wrong: %s -> %s", f.From, f.To)
	}
}

func TestFieldsListed(t *testing.T) {
	if len(Fields()) < 30 {
		t.Errorf("only %d filterable fields", len(Fields()))
	}
}

func TestRegexIsValidatedBeforeReachingTheDatabase(t *testing.T) {
	// A pattern the database would reject must be caught here, with a message
	// naming the problem rather than a query failure.
	_, _, err := Where(baseFilter(Condition{Field: "path", Op: OpRegex, Value: "(unclosed"}))
	if err == nil {
		t.Fatal("an invalid regular expression was accepted")
	}
	if !strings.Contains(err.Error(), "invalid regular expression") {
		t.Errorf("err = %v", err)
	}
}

func TestValidRegexAccepted(t *testing.T) {
	for _, pattern := range []string{`^/api/v\d+/`, `\.(php|asp)$`, `(?i)admin`, `[a-z]{3,8}`} {
		if _, _, err := Where(baseFilter(Condition{Field: "path", Op: OpRegex, Value: pattern})); err != nil {
			t.Errorf("pattern %q rejected: %v", pattern, err)
		}
	}
}

func TestRegexAllowedOnEnumeratedColumns(t *testing.T) {
	// Method and app are short enumerated columns, but matching them by pattern
	// is still a reasonable thing to want.
	for _, field := range []string{"method", "app_id", "country", "resp_content_type"} {
		if _, _, err := Where(baseFilter(Condition{Field: field, Op: OpRegex, Value: "^A"})); err != nil {
			t.Errorf("regex on %q rejected: %v", field, err)
		}
	}
}
