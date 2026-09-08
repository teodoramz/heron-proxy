package waf

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/amzteodor/proxy-waf/internal/config"
)

func testEngine(t *testing.T) *Engine {
	t.Helper()
	return NewEngine(t.TempDir())
}

// run evaluates one request and returns the result.
func run(t *testing.T, e *Engine, p config.WAFPolicy, r *http.Request, body string) Result {
	t.Helper()
	tx, err := e.NewTransaction(p, 1<<20, "test-tx")
	if err != nil {
		t.Fatalf("NewTransaction: %v", err)
	}
	defer tx.Close()

	tx.ProcessRequest(r, "203.0.113.10", 44444, "10.0.0.1", 443)
	if body != "" {
		tx.WriteRequestBody([]byte(body))
	}
	tx.ProcessRequestBody()
	tx.ProcessResponseHeaders(200, "HTTP/1.1", http.Header{"Content-Type": []string{"text/html"}})
	return tx.Result()
}

func hasRulePrefix(res Result, prefix string) bool {
	for _, id := range res.RuleIDs {
		if strings.HasPrefix(itoa(id), prefix) {
			return true
		}
	}
	return false
}

func itoa(v uint32) string {
	const digits = "0123456789"
	if v == 0 {
		return "0"
	}
	var b [10]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = digits[v%10]
		v /= 10
	}
	return string(b[i:])
}

func TestCleanRequestMatchesNothing(t *testing.T) {
	e := testEngine(t)
	r := httptest.NewRequest(http.MethodGet, "https://app.example/index.html?page=2", nil)
	r.Host = "app.example"
	r.Header.Set("User-Agent", "Mozilla/5.0")
	r.Header.Set("Accept", "text/html")

	res := run(t, e, config.DefaultWAF(), r, "")
	if res.AnomalyScore != 0 {
		t.Errorf("AnomalyScore = %d, want 0. rules=%v msgs=%v", res.AnomalyScore, res.RuleIDs, res.Messages)
	}
	if res.WouldBlock {
		t.Error("clean request flagged as would-block")
	}
}

func TestSQLInjectionDetected(t *testing.T) {
	e := testEngine(t)
	r := httptest.NewRequest(http.MethodGet, "https://app.example/search?id=1%27%20OR%20%271%27%3D%271%20--%20", nil)
	r.Host = "app.example"
	r.Header.Set("User-Agent", "Mozilla/5.0")

	res := run(t, e, config.DefaultWAF(), r, "")
	if !hasRulePrefix(res, "942") {
		t.Errorf("no 942xxx SQLi rule fired. rules=%v msgs=%v", res.RuleIDs, res.Messages)
	}
	if res.AnomalyScore == 0 {
		t.Error("AnomalyScore = 0 for a SQLi payload")
	}
	if !res.WouldBlock {
		t.Errorf("WouldBlock = false at score %d with threshold 5", res.AnomalyScore)
	}
}

func TestXSSDetected(t *testing.T) {
	e := testEngine(t)
	r := httptest.NewRequest(http.MethodGet, "https://app.example/q?s=%3Cscript%3Ealert%281%29%3C%2Fscript%3E", nil)
	r.Host = "app.example"
	r.Header.Set("User-Agent", "Mozilla/5.0")

	res := run(t, e, config.DefaultWAF(), r, "")
	if !hasRulePrefix(res, "941") {
		t.Errorf("no 941xxx XSS rule fired. rules=%v msgs=%v", res.RuleIDs, res.Messages)
	}
}

func TestPathTraversalDetected(t *testing.T) {
	e := testEngine(t)
	r := httptest.NewRequest(http.MethodGet, "https://app.example/static?file=../../../../etc/passwd", nil)
	r.Host = "app.example"
	r.Header.Set("User-Agent", "Mozilla/5.0")

	res := run(t, e, config.DefaultWAF(), r, "")
	if !hasRulePrefix(res, "930") {
		t.Errorf("no 930xxx traversal rule fired. rules=%v msgs=%v", res.RuleIDs, res.Messages)
	}
}

func TestPostBodyInspected(t *testing.T) {
	e := testEngine(t)
	body := "comment=%3Cscript%3Ealert%281%29%3C%2Fscript%3E"
	r := httptest.NewRequest(http.MethodPost, "https://app.example/comment", strings.NewReader(body))
	r.Host = "app.example"
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("User-Agent", "Mozilla/5.0")

	res := run(t, e, config.DefaultWAF(), r, body)
	if !hasRulePrefix(res, "941") {
		t.Errorf("request body not inspected. rules=%v msgs=%v", res.RuleIDs, res.Messages)
	}
}

func TestHighThresholdSuppressesWouldBlock(t *testing.T) {
	e := testEngine(t)
	p := config.DefaultWAF()
	p.Threshold = 1000

	r := httptest.NewRequest(http.MethodGet, "https://app.example/search?id=1%27%20OR%20%271%27%3D%271", nil)
	r.Host = "app.example"
	res := run(t, e, p, r, "")

	if len(res.RuleIDs) == 0 {
		t.Fatal("expected rules to still fire at a high threshold")
	}
	if res.WouldBlock {
		t.Errorf("WouldBlock = true at threshold 1000 with score %d", res.AnomalyScore)
	}
}

func TestMatchedRuleDetail(t *testing.T) {
	e := testEngine(t)
	r := httptest.NewRequest(http.MethodGet, "https://app.example/search?id=1%27%20OR%20%271%27%3D%271", nil)
	r.Host = "app.example"
	res := run(t, e, config.DefaultWAF(), r, "")

	var found bool
	for _, m := range res.Matched {
		if m.Message != "" && m.Severity > 0 && len(m.Tags) > 0 {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("no matched rule carried message, severity and tags: %+v", res.Matched)
	}
	if res.Severity == 0 {
		t.Error("Result.Severity = 0")
	}
}

func TestEngineCachesPerPolicy(t *testing.T) {
	e := testEngine(t)
	p := config.DefaultWAF()
	w1, err := e.For(p, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	w2, _ := e.For(p, 1<<20)
	if w1 != w2 {
		t.Error("identical policies produced different engines")
	}
	p.ParanoiaLevel = 2
	w3, _ := e.For(p, 1<<20)
	if w1 == w3 {
		t.Error("a different paranoia level reused the same engine")
	}
}

func TestReloadDropsCache(t *testing.T) {
	e := testEngine(t)
	p := config.DefaultWAF()
	w1, _ := e.For(p, 1<<20)
	e.Reload()
	w2, _ := e.For(p, 1<<20)
	if w1 == w2 {
		t.Error("Reload did not rebuild the engine")
	}
}

func TestExtraRuleFileLoaded(t *testing.T) {
	dir := t.TempDir()
	rule := `SecRule REQUEST_HEADERS:X-Canary "@streq tripwire" "id:1000001,phase:1,pass,log,severity:CRITICAL,msg:'canary'"`
	if err := writeFile(dir+"/exclusions.conf", rule); err != nil {
		t.Fatal(err)
	}
	e := NewEngine(dir)

	r := httptest.NewRequest(http.MethodGet, "https://app.example/", nil)
	r.Host = "app.example"
	r.Header.Set("X-Canary", "tripwire")
	res := run(t, e, config.DefaultWAF(), r, "")

	var found bool
	for _, id := range res.RuleIDs {
		if id == 1000001 {
			found = true
		}
	}
	if !found {
		t.Errorf("rule from the rules directory did not load. rules=%v", res.RuleIDs)
	}
}

func TestSeverityRankIsHigherIsWorse(t *testing.T) {
	if severityRank(2) <= severityRank(5) {
		t.Error("critical must rank above notice")
	}
}

func TestParanoiaFromTags(t *testing.T) {
	if got := paranoiaFromTags([]string{"attack-sqli", "paranoia-level/2"}); got != 2 {
		t.Errorf("got %d, want 2", got)
	}
	if got := paranoiaFromTags([]string{"attack-sqli"}); got != 0 {
		t.Errorf("got %d, want 0", got)
	}
}

func TestParseTotalScore(t *testing.T) {
	n, ok := parseTotalScore("Inbound Anomaly Score Exceeded (Total Score: 15)")
	if !ok || n != 15 {
		t.Errorf("got %d, %v", n, ok)
	}
	if _, ok := parseTotalScore("no score here"); ok {
		t.Error("matched a message with no score")
	}
}

func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o644)
}
