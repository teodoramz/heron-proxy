package reader

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/amzteodor/proxy-waf/internal/api/query"
	"github.com/amzteodor/proxy-waf/internal/pipeline/chsink"
	"github.com/amzteodor/proxy-waf/internal/pipeline/event"
)

var (
	baseTime = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	testApps = []string{"api", "web"}
)

var testReader *Reader

// TestMain prepares the schema and loads the fixture once. Every test in this
// package is read-only, so rebuilding the table per test would only add time
// and, because DROP is deferred on the Atomic engine, flakiness.
func TestMain(m *testing.M) {
	dsn := os.Getenv("CLICKHOUSE_TEST_DSN")
	if dsn == "" {
		os.Exit(m.Run())
	}
	ctx := context.Background()
	w, err := chsink.Open(dsn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "chsink.Open: %v\n", err)
		os.Exit(1)
	}
	defer w.Close()

	// The migrations are idempotent, so the fixture truncates rather than drops.
	// Dropping is unreliable here: on the Atomic database engine a DROP is
	// deferred, and a CREATE IF NOT EXISTS issued straight after can land rows
	// in a table already queued for deletion.
	if err := w.Migrate(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "migrate: %v\n", err)
		os.Exit(1)
	}
	for _, table := range []string{"traffic", "traffic_stats_1m", "rule_hits_1h", "ip_stats_1h"} {
		if err := w.Conn().Exec(ctx, "TRUNCATE TABLE IF EXISTS "+table); err != nil {
			fmt.Fprintf(os.Stderr, "truncate %s: %v\n", table, err)
			os.Exit(1)
		}
	}
	if err := w.WriteBatch(ctx, fixtures()); err != nil {
		fmt.Fprintf(os.Stderr, "seed: %v\n", err)
		os.Exit(1)
	}
	var seeded uint64
	if err := w.Conn().QueryRow(ctx, "SELECT count() FROM traffic").Scan(&seeded); err != nil {
		fmt.Fprintf(os.Stderr, "verify seed: %v\n", err)
		os.Exit(1)
	}
	if seeded == 0 {
		fmt.Fprintln(os.Stderr, "seed did not land")
		os.Exit(1)
	}
	testReader = New(w.Conn())
	os.Exit(m.Run())
}

// newReader returns the shared reader, skipping when no test database is set.
func newReader(t *testing.T) *Reader {
	t.Helper()
	if testReader == nil {
		t.Skip("CLICKHOUSE_TEST_DSN not set")
	}
	return testReader
}

// msgsFor pairs one message with each rule, as the proxy records them.
func msgsFor(rules []uint32) []string {
	out := make([]string, 0, len(rules))
	for _, id := range rules {
		out = append(out, fmt.Sprintf("rule %d matched", id))
	}
	return out
}

// fixtures builds a small, deterministic traffic set.
func fixtures() []event.Event {
	mk := func(i int, app, method, path string, status uint16, anomaly uint16, ip string, rules []uint32, tags []string, block bool) event.Event {
		return event.Event{
			TS:              baseTime.Add(time.Duration(i) * time.Minute),
			ID:              uuid.NewSHA1(uuid.NameSpaceURL, []byte(fmt.Sprintf("event-%d", i))).String(),
			AppID:           app,
			RetentionDays:   90,
			ClientIP:        netip.MustParseAddr(ip),
			ClientIPClaimed: netip.MustParseAddr("0.0.0.0"),
			ClientPort:      40000 + uint16(i),
			Country:         "DE",
			ASN:             64512,
			ASOrg:           "Example AS",
			JA3:             "aaaabbbbccccddddeeeeffff00001111",
			JA4:             "t13d1516h2_8daaf6152771_02713d6af862",
			Method:          method,
			Scheme:          "https",
			Host:            app + ".example",
			Path:            path,
			Query:           "page=1",
			HTTPVersion:     "HTTP/1.1",
			ReqHeaders:      map[string]string{"user-agent": "curl/8", "content-type": "application/json"},
			ReqBodySize:     11,
			ReqBody:         `{"a":"b"}`,
			ReqBodySHA:      "0000000000000000000000000000000000000000000000000000000000000000",
			UserAgent:       "curl/8",
			Status:          status,
			RespHeaders:     map[string]string{"server": "nginx"},
			RespSize:        uint64(100 + i),
			RespContentType: "application/json",
			DurationMS:      uint32(10 + i),
			UpstreamMS:      uint32(5 + i),
			WAFMS:           1,
			AnomalyScore:    anomaly,
			RuleIDs:         rules,
			RuleMsgs:        msgsFor(rules),
			RuleTags:        tags,
			RuleSeverity:    5,
			ParanoiaMax:     1,
			WouldBlock:      block,
			Upstream:        "http://10.0.0.5:8080",
		}
	}
	return []event.Event{
		mk(0, "api", "GET", "/v1/users", 200, 0, "203.0.113.1", nil, nil, false),
		mk(1, "api", "POST", "/v1/login", 403, 15, "203.0.113.9", []uint32{942100, 949110}, []string{"attack-sqli"}, true),
		mk(2, "api", "GET", "/v1/login", 404, 5, "203.0.113.9", []uint32{941100}, []string{"attack-xss"}, true),
		mk(3, "web", "GET", "/index.html", 200, 0, "198.51.100.4", nil, nil, false),
		mk(4, "web", "GET", "/admin", 500, 3, "198.51.100.4", []uint32{930120}, []string{"attack-lfi"}, false),
	}
}

func fullRange() query.Filter {
	return query.Filter{
		From: baseTime.Add(-time.Hour),
		To:   baseTime.Add(time.Hour),
		Root: query.Group{Op: "and"},
	}
}

func TestListReturnsNewestFirst(t *testing.T) {
	r := newReader(t)
	page, err := r.List(context.Background(), fullRange())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(page.Events) != 5 {
		t.Fatalf("got %d events, want 5", len(page.Events))
	}
	for i := 1; i < len(page.Events); i++ {
		if page.Events[i].TS.After(page.Events[i-1].TS) {
			t.Errorf("events not newest-first at %d", i)
		}
	}
	if page.HasMore {
		t.Error("HasMore = true with everything returned")
	}
}

func TestListRoundTripsFields(t *testing.T) {
	r := newReader(t)
	f := fullRange()
	f.Root.Conditions = []query.Condition{{Field: "path", Op: query.OpEq, Value: "/v1/login"}, {Field: "status", Op: query.OpEq, Value: 403}}
	page, err := r.List(context.Background(), f)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(page.Events) != 1 {
		t.Fatalf("got %d events, want 1", len(page.Events))
	}
	e := page.Events[0]
	if e.Method != "POST" || e.Host != "api.example" {
		t.Errorf("request fields wrong: %+v", e)
	}
	if e.ClientIP.String() != "203.0.113.9" {
		t.Errorf("ClientIP = %s (IPv4 should be unmapped)", e.ClientIP)
	}
	if e.AnomalyScore != 15 || !e.WouldBlock {
		t.Errorf("waf fields wrong: score=%d block=%v", e.AnomalyScore, e.WouldBlock)
	}
	if len(e.RuleIDs) != 2 || e.RuleIDs[0] != 942100 {
		t.Errorf("RuleIDs = %v", e.RuleIDs)
	}
	if len(e.RuleTags) != 1 || e.RuleTags[0] != "attack-sqli" {
		t.Errorf("RuleTags = %v", e.RuleTags)
	}
	if e.JA4 == "" || e.Country != "DE" || e.ASN != 64512 {
		t.Errorf("enrichment fields lost: %+v", e)
	}
}

func TestKeysetPaginationWalksEveryRowOnce(t *testing.T) {
	r := newReader(t)
	ctx := context.Background()

	f := fullRange()
	f.Limit = 2

	seen := make(map[string]bool)
	pages := 0
	for {
		page, err := r.List(ctx, f)
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		for _, e := range page.Events {
			if seen[e.ID] {
				t.Fatalf("event %s returned twice", e.ID)
			}
			seen[e.ID] = true
		}
		pages++
		if !page.HasMore || pages > 10 {
			break
		}
		f.Cursor = page.NextCursor
	}
	if len(seen) != 5 {
		t.Errorf("walked %d distinct events, want 5", len(seen))
	}
	if pages != 3 {
		t.Errorf("took %d pages for 5 rows at limit 2, want 3", pages)
	}
}

func TestGetReturnsDetail(t *testing.T) {
	r := newReader(t)
	ctx := context.Background()
	page, _ := r.List(ctx, fullRange())

	got, err := r.Get(ctx, page.Events[0].ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ReqHeaders["user-agent"] != "curl/8" {
		t.Errorf("ReqHeaders = %v", got.ReqHeaders)
	}
	if got.RespHeaders["server"] != "nginx" {
		t.Errorf("RespHeaders = %v", got.RespHeaders)
	}
	if got.ReqBody == "" || got.ClientPort == 0 || got.RetentionDays != 90 {
		t.Errorf("detail fields missing: %+v", got)
	}
}

func TestGetMissing(t *testing.T) {
	r := newReader(t)
	_, err := r.Get(context.Background(), uuid.NewString())
	if err != ErrNotFound {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestCount(t *testing.T) {
	r := newReader(t)
	n, capped, err := r.Count(context.Background(), fullRange())
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if n != 5 || capped {
		t.Errorf("count = %d capped = %v, want 5 false", n, capped)
	}
}

func TestAppScopeFilter(t *testing.T) {
	r := newReader(t)
	f := fullRange()
	f.Apps = []string{"web"}
	page, err := r.List(context.Background(), f)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(page.Events) != 2 {
		t.Fatalf("got %d events, want 2", len(page.Events))
	}
	for _, e := range page.Events {
		if e.AppID != "web" {
			t.Errorf("app scope leaked: %s", e.AppID)
		}
	}
}

// TestEveryFilterFieldExecutes runs a representative condition for each
// filterable field against ClickHouse, so a field that generates invalid SQL
// fails here rather than in production.
func TestEveryFilterFieldExecutes(t *testing.T) {
	r := newReader(t)
	ctx := context.Background()

	for _, field := range query.Fields() {
		for _, cond := range representativeConditions(field) {
			f := fullRange()
			f.Root.Conditions = []query.Condition{cond}
			if _, _, err := r.Count(ctx, f); err != nil {
				t.Errorf("field %q with op %q failed: %v", field, cond.Op, err)
			}
		}
	}
}

// representativeConditions returns one usable condition per operator a field
// supports.
func representativeConditions(field string) []query.Condition {
	switch field {
	case "id":
		return []query.Condition{{Field: field, Op: query.OpEq, Value: uuid.Nil.String()}}
	case "ts":
		return nil // the time range is always applied separately
	case "client_ip", "client_ip_claimed":
		return []query.Condition{
			{Field: field, Op: query.OpEq, Value: "203.0.113.9"},
			{Field: field, Op: query.OpCIDR, Value: "203.0.113.0/24"},
			{Field: field, Op: query.OpIn, Value: []any{"203.0.113.9", "198.51.100.4"}},
		}
	case "rule_id":
		return []query.Condition{
			{Field: field, Op: query.OpHas, Value: uint32(942100)},
			{Field: field, Op: query.OpIn, Value: []uint32{942100, 941100}},
		}
	case "rule_tag":
		return []query.Condition{
			{Field: field, Op: query.OpHas, Value: "attack-sqli"},
			{Field: field, Op: query.OpIn, Value: []string{"attack-sqli", "attack-xss"}},
		}
	case "req_header", "resp_header":
		return []query.Condition{
			{Field: field, Op: query.OpExists, Key: "content-type"},
			{Field: field, Op: query.OpEq, Key: "content-type", Value: "application/json"},
			{Field: field, Op: query.OpContains, Key: "content-type", Value: "json"},
		}
	case "would_block", "req_truncated", "is_websocket":
		return []query.Condition{{Field: field, Op: query.OpEq, Value: true}}
	case "asn", "status", "resp_size", "req_body_size", "duration_ms", "upstream_ms",
		"waf_ms", "anomaly_score", "rule_severity", "paranoia_max":
		return []query.Condition{
			{Field: field, Op: query.OpEq, Value: uint64(200)},
			{Field: field, Op: query.OpGte, Value: uint64(1)},
			{Field: field, Op: query.OpIn, Value: []uint64{1, 2}},
		}
	default:
		return []query.Condition{
			{Field: field, Op: query.OpEq, Value: "x"},
			{Field: field, Op: query.OpContains, Value: "x"},
			{Field: field, Op: query.OpPrefix, Value: "x"},
			{Field: field, Op: query.OpIn, Value: []string{"x", "y"}},
		}
	}
}

func TestFilterResultsAreCorrect(t *testing.T) {
	r := newReader(t)
	ctx := context.Background()

	cases := []struct {
		name string
		cond query.Condition
		want uint64
	}{
		{"status gte 400", query.Condition{Field: "status", Op: query.OpGte, Value: 400}, 3},
		{"would block", query.Condition{Field: "would_block", Op: query.OpEq, Value: true}, 2},
		{"rule id", query.Condition{Field: "rule_id", Op: query.OpHas, Value: uint32(942100)}, 1},
		{"rule tag", query.Condition{Field: "rule_tag", Op: query.OpHas, Value: "attack-sqli"}, 1},
		{"path prefix", query.Condition{Field: "path", Op: query.OpPrefix, Value: "/v1/"}, 3},
		{"path contains", query.Condition{Field: "path", Op: query.OpContains, Value: "LOGIN"}, 2},
		{"ip cidr", query.Condition{Field: "client_ip", Op: query.OpCIDR, Value: "203.0.113.0/24"}, 3},
		{"body contains", query.Condition{Field: "body", Op: query.OpContains, Value: `"a"`}, 5},
		{"anomaly gte 5", query.Condition{Field: "anomaly_score", Op: query.OpGte, Value: 5}, 2},
		{"header exists", query.Condition{Field: "req_header", Op: query.OpExists, Key: "user-agent"}, 5},
		{"method", query.Condition{Field: "method", Op: query.OpEq, Value: "POST"}, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := fullRange()
			f.Root.Conditions = []query.Condition{c.cond}
			n, _, err := r.Count(ctx, f)
			if err != nil {
				t.Fatalf("Count: %v", err)
			}
			if n != c.want {
				t.Errorf("count = %d, want %d", n, c.want)
			}
		})
	}
}

func TestOrGroupCounts(t *testing.T) {
	r := newReader(t)
	f := fullRange()
	f.Root.Groups = []query.Group{{Op: "or", Conditions: []query.Condition{
		{Field: "rule_tag", Op: query.OpHas, Value: "attack-sqli"},
		{Field: "rule_tag", Op: query.OpHas, Value: "attack-xss"},
	}}}
	n, _, err := r.Count(context.Background(), f)
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if n != 2 {
		t.Errorf("count = %d, want 2", n)
	}
}

func TestSummary(t *testing.T) {
	r := newReader(t)
	s, err := r.Summary(context.Background(), fullRange())
	if err != nil {
		t.Fatalf("Summary: %v", err)
	}
	if s.Requests != 5 {
		t.Errorf("Requests = %d, want 5", s.Requests)
	}
	if s.Clients != 3 {
		t.Errorf("Clients = %d, want 3", s.Clients)
	}
	if s.WouldBlock != 2 {
		t.Errorf("WouldBlock = %d, want 2", s.WouldBlock)
	}
	if s.Errors != 3 {
		t.Errorf("Errors = %d, want 3", s.Errors)
	}
	if s.P95Duration <= 0 {
		t.Errorf("P95Duration = %f", s.P95Duration)
	}
}

func TestTimeSeries(t *testing.T) {
	r := newReader(t)
	points, err := r.TimeSeries(context.Background(), fullRange(), time.Minute)
	if err != nil {
		t.Fatalf("TimeSeries: %v", err)
	}
	if len(points) != 5 {
		t.Fatalf("got %d buckets, want 5", len(points))
	}
	var total, blocked uint64
	for _, p := range points {
		total += p.Requests
		blocked += p.WouldBlock
	}
	if total != 5 || blocked != 2 {
		t.Errorf("totals wrong: requests=%d blocked=%d", total, blocked)
	}
	for i := 1; i < len(points); i++ {
		if !points[i].Bucket.After(points[i-1].Bucket) {
			t.Errorf("buckets not ascending at %d", i)
		}
	}
}

func TestTimeSeriesBucketSizes(t *testing.T) {
	r := newReader(t)
	for _, d := range []time.Duration{time.Minute, 5 * time.Minute, 15 * time.Minute, time.Hour, 24 * time.Hour} {
		if _, err := r.TimeSeries(context.Background(), fullRange(), d); err != nil {
			t.Errorf("bucket %s failed: %v", d, err)
		}
	}
}

func TestTopRules(t *testing.T) {
	r := newReader(t)
	rules, err := r.TopRules(context.Background(), fullRange(), 10)
	if err != nil {
		t.Fatalf("TopRules: %v", err)
	}
	if len(rules) != 4 {
		t.Fatalf("got %d rules, want 4", len(rules))
	}
	for _, rule := range rules {
		if rule.Hits == 0 {
			t.Errorf("rule %d has no hits", rule.RuleID)
		}
	}
}

func TestTopIPs(t *testing.T) {
	r := newReader(t)
	ips, err := r.TopIPs(context.Background(), fullRange(), 10)
	if err != nil {
		t.Fatalf("TopIPs: %v", err)
	}
	if len(ips) != 3 {
		t.Fatalf("got %d addresses, want 3", len(ips))
	}
	if ips[0].ClientIP != "203.0.113.9" {
		t.Errorf("top address = %s, want the highest anomaly", ips[0].ClientIP)
	}
	if ips[0].Requests != 2 || ips[0].Anomaly != 20 {
		t.Errorf("top address stats wrong: %+v", ips[0])
	}
	if ips[0].FirstSeen.IsZero() || ips[0].LastSeen.IsZero() {
		t.Error("first/last seen not populated")
	}
}

func TestTopByEveryGroupableField(t *testing.T) {
	r := newReader(t)
	ctx := context.Background()
	for _, field := range GroupableFields() {
		rows, err := r.TopBy(ctx, fullRange(), field, 5)
		if err != nil {
			t.Errorf("TopBy(%q): %v", field, err)
			continue
		}
		if len(rows) == 0 {
			t.Errorf("TopBy(%q) returned nothing", field)
		}
	}
}

func TestTopByRejectsUnknownField(t *testing.T) {
	r := newReader(t)
	if _, err := r.TopBy(context.Background(), fullRange(), "password", 5); err == nil {
		t.Error("unknown group field accepted")
	}
}

func TestSimulate(t *testing.T) {
	r := newReader(t)
	ctx := context.Background()

	sim, err := r.Simulate(ctx, fullRange(), 5)
	if err != nil {
		t.Fatalf("Simulate: %v", err)
	}
	if sim.Total != 5 || sim.WouldBlock != 2 {
		t.Errorf("threshold 5: total=%d blocked=%d, want 5 and 2", sim.Total, sim.WouldBlock)
	}
	if sim.Percent < 39 || sim.Percent > 41 {
		t.Errorf("Percent = %f, want ~40", sim.Percent)
	}

	high, _ := r.Simulate(ctx, fullRange(), 100)
	if high.WouldBlock != 0 {
		t.Errorf("threshold 100 blocked %d, want 0", high.WouldBlock)
	}
	low, _ := r.Simulate(ctx, fullRange(), 1)
	if low.WouldBlock != 3 {
		t.Errorf("threshold 1 blocked %d, want 3", low.WouldBlock)
	}
}

func TestIPProfile(t *testing.T) {
	r := newReader(t)
	profile, err := r.IPProfile(context.Background(), fullRange(), "203.0.113.9", 10)
	if err != nil {
		t.Fatalf("IPProfile: %v", err)
	}
	if profile.Stat.Requests != 2 {
		t.Errorf("Requests = %d, want 2", profile.Stat.Requests)
	}
	if len(profile.TopPaths) != 1 {
		t.Errorf("TopPaths = %+v, want one distinct path", profile.TopPaths)
	}
	if len(profile.TopRules) != 3 {
		t.Errorf("TopRules = %d, want 3", len(profile.TopRules))
	}
	if len(profile.Fingerprints) != 1 {
		t.Errorf("Fingerprints = %+v", profile.Fingerprints)
	}
}

func TestEmptyRangeReturnsNothing(t *testing.T) {
	r := newReader(t)
	f := fullRange()
	f.From = baseTime.Add(-48 * time.Hour)
	f.To = baseTime.Add(-24 * time.Hour)

	page, err := r.List(context.Background(), f)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(page.Events) != 0 {
		t.Errorf("got %d events outside the range", len(page.Events))
	}
	if page.NextCursor != "" {
		t.Error("cursor returned for an empty page")
	}
}

// TestTopRulesPairsMessageWithItsRule guards against attributing an arbitrary
// message from an event to every rule that event matched.
func TestTopRulesPairsMessageWithItsRule(t *testing.T) {
	r := newReader(t)
	rules, err := r.TopRules(context.Background(), fullRange(), 10)
	if err != nil {
		t.Fatalf("TopRules: %v", err)
	}
	if len(rules) == 0 {
		t.Fatal("no rules returned")
	}
	// The fixture names each message after its own rule, so a mispaired message
	// is detectable directly.
	for _, rule := range rules {
		want := fmt.Sprintf("rule %d matched", rule.RuleID)
		if rule.Message != want {
			t.Errorf("rule %d reports %q, want %q", rule.RuleID, rule.Message, want)
		}
	}
}
