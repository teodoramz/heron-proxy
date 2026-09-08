// Package waf wraps Coraza and the OWASP Core Rule Set.
//
// The engine always runs in detection-only mode: rules are evaluated and
// recorded, but no request is ever interrupted. Whether CRS would have blocked
// a request is reported as Result.WouldBlock.
package waf

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"

	"github.com/amzteodor/proxy-waf/internal/config"
)

// Rule IDs CRS uses to report that a threshold was crossed.
const (
	ruleInboundBlock  = 949110
	ruleOutboundBlock = 959100
)

var totalScoreRe = regexp.MustCompile(`Total Score:\s*(\d+)`)

// Matched is one rule that fired.
type Matched struct {
	ID       uint32   `json:"id"`
	Message  string   `json:"message"`
	Data     string   `json:"data"`
	Severity uint8    `json:"severity"`
	Paranoia uint8    `json:"paranoia"`
	Tags     []string `json:"tags"`
	Phase    uint8    `json:"phase"`
}

// Result summarizes one transaction.
type Result struct {
	AnomalyScore uint16
	Matched      []Matched
	RuleIDs      []uint32
	Messages     []string
	Tags         []string
	Severity     uint8
	ParanoiaMax  uint8
	WouldBlock   bool
	Elapsed      time.Duration
}

// Engine builds and caches one Coraza instance per distinct policy.
type Engine struct {
	rulesDir string

	mu    sync.RWMutex
	cache map[string]coraza.WAF
}

// NewEngine returns an engine that loads extra .conf files from rulesDir.
func NewEngine(rulesDir string) *Engine {
	return &Engine{rulesDir: rulesDir, cache: make(map[string]coraza.WAF)}
}

// For returns the Coraza instance for a policy, building it on first use.
func (e *Engine) For(p config.WAFPolicy, bodyLimit int) (coraza.WAF, error) {
	key := policyKey(p, bodyLimit)

	e.mu.RLock()
	w, ok := e.cache[key]
	e.mu.RUnlock()
	if ok {
		return w, nil
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	if w, ok := e.cache[key]; ok {
		return w, nil
	}
	directives, err := e.directives(p, bodyLimit)
	if err != nil {
		return nil, err
	}
	w, err = coraza.NewWAF(coraza.NewWAFConfig().
		WithRootFS(coreruleset.FS).
		WithRequestBodyAccess().
		WithRequestBodyLimit(bodyLimit).
		WithRequestBodyInMemoryLimit(bodyLimit).
		WithDirectives(directives))
	if err != nil {
		return nil, fmt.Errorf("waf: build engine: %w", err)
	}
	e.cache[key] = w
	return w, nil
}

// Reload drops every cached engine so the next request rebuilds with current
// rule files.
func (e *Engine) Reload() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.cache = make(map[string]coraza.WAF)
}

func (e *Engine) directives(p config.WAFPolicy, bodyLimit int) (string, error) {
	var b strings.Builder
	b.WriteString("Include @coraza.conf-recommended\n")
	b.WriteString("SecRuleEngine DetectionOnly\n")
	b.WriteString("SecRequestBodyAccess On\n")
	b.WriteString("SecResponseBodyAccess Off\n")
	fmt.Fprintf(&b, "SecRequestBodyLimit %d\n", bodyLimit)
	fmt.Fprintf(&b, "SecRequestBodyNoFilesLimit %d\n", bodyLimit)
	b.WriteString("SecRequestBodyLimitAction ProcessPartial\n")
	b.WriteString("SecAuditEngine Off\n")
	b.WriteString("Include @crs-setup.conf.example\n")

	pl := p.ParanoiaLevel
	if pl < 1 || pl > 4 {
		pl = 1
	}
	threshold := p.Threshold
	if threshold < 1 {
		threshold = 5
	}
	fmt.Fprintf(&b, "SecAction \"id:900000,phase:1,pass,t:none,nolog,setvar:tx.blocking_paranoia_level=%d\"\n", pl)
	fmt.Fprintf(&b, "SecAction \"id:900001,phase:1,pass,t:none,nolog,setvar:tx.detection_paranoia_level=%d\"\n", pl)
	fmt.Fprintf(&b, "SecAction \"id:900002,phase:1,pass,t:none,nolog,setvar:tx.inbound_anomaly_score_threshold=%d\"\n", threshold)
	fmt.Fprintf(&b, "SecAction \"id:900003,phase:1,pass,t:none,nolog,setvar:tx.outbound_anomaly_score_threshold=%d\"\n", threshold)

	b.WriteString("Include @owasp_crs/*.conf\n")

	extra, err := e.extraRules()
	if err != nil {
		return "", err
	}
	b.WriteString(extra)
	for _, r := range p.ExtraRules {
		b.WriteString(r)
		b.WriteByte('\n')
	}
	return b.String(), nil
}

// extraRules concatenates every .conf file in the rules directory, which is
// where generated exclusions are written.
func (e *Engine) extraRules() (string, error) {
	if e.rulesDir == "" {
		return "", nil
	}
	paths, err := filepath.Glob(filepath.Join(e.rulesDir, "*.conf"))
	if err != nil {
		return "", fmt.Errorf("waf: glob rules: %w", err)
	}
	sort.Strings(paths)

	var b strings.Builder
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			return "", fmt.Errorf("waf: read %s: %w", p, err)
		}
		b.Write(data)
		b.WriteByte('\n')
	}
	return b.String(), nil
}

func policyKey(p config.WAFPolicy, bodyLimit int) string {
	return fmt.Sprintf("pl=%d;th=%d;bl=%d;extra=%s",
		p.ParanoiaLevel, p.Threshold, bodyLimit, strings.Join(p.ExtraRules, "\x00"))
}

// Tx is one WAF transaction.
type Tx struct {
	tx    types.Transaction
	start time.Time
}

// NewTransaction starts a transaction for a policy.
func (e *Engine) NewTransaction(p config.WAFPolicy, bodyLimit int, id string) (*Tx, error) {
	w, err := e.For(p, bodyLimit)
	if err != nil {
		return nil, err
	}
	return &Tx{tx: w.NewTransactionWithID(id), start: time.Now()}, nil
}

// ProcessRequest feeds the connection, URI and headers through phases 1 and 2.
func (t *Tx) ProcessRequest(r *http.Request, clientIP string, clientPort int, serverIP string, serverPort int) {
	t.tx.ProcessConnection(clientIP, clientPort, serverIP, serverPort)
	t.tx.SetServerName(hostOnly(r.Host))
	t.tx.ProcessURI(r.URL.RequestURI(), r.Method, protoVersion(r.Proto))

	t.tx.AddRequestHeader("Host", r.Host)
	for name, values := range r.Header {
		for _, v := range values {
			t.tx.AddRequestHeader(name, v)
		}
	}
	t.tx.ProcessRequestHeaders()
}

// WriteRequestBody feeds body bytes to the WAF.
func (t *Tx) WriteRequestBody(b []byte) {
	if len(b) == 0 {
		return
	}
	_, _, _ = t.tx.WriteRequestBody(b)
}

// ProcessRequestBody runs phase 2 body rules.
func (t *Tx) ProcessRequestBody() {
	_, _ = t.tx.ProcessRequestBody()
}

// ProcessResponseHeaders runs phase 3. Response bodies are never inspected.
func (t *Tx) ProcessResponseHeaders(status int, proto string, h http.Header) {
	for name, values := range h {
		for _, v := range values {
			t.tx.AddResponseHeader(name, v)
		}
	}
	t.tx.ProcessResponseHeaders(status, proto)
}

// Result finalizes the transaction and summarizes what matched.
func (t *Tx) Result() Result {
	t.tx.ProcessLogging()

	res := Result{Elapsed: time.Since(t.start), WouldBlock: t.tx.IsInterrupted()}
	tagSet := make(map[string]struct{})
	var score int
	var exact int
	var haveExact bool

	for _, m := range t.tx.MatchedRules() {
		meta := m.Rule()
		id := uint32(meta.ID())
		sev := severityRank(meta.Severity())
		pl := paranoiaFromTags(meta.Tags())

		res.Matched = append(res.Matched, Matched{
			ID:       id,
			Message:  m.Message(),
			Data:     m.Data(),
			Severity: sev,
			Paranoia: pl,
			Tags:     meta.Tags(),
			Phase:    uint8(meta.Phase()),
		})
		res.RuleIDs = append(res.RuleIDs, id)
		if msg := m.Message(); msg != "" {
			res.Messages = append(res.Messages, msg)
		}
		for _, tag := range meta.Tags() {
			tagSet[tag] = struct{}{}
		}
		if sev > res.Severity {
			res.Severity = sev
		}
		if pl > res.ParanoiaMax {
			res.ParanoiaMax = pl
		}
		if id == ruleInboundBlock || id == ruleOutboundBlock {
			res.WouldBlock = true
			if n, ok := parseTotalScore(m.Message()); ok {
				exact, haveExact = n, true
			}
			continue
		}
		score += anomalyWeight(meta)
	}

	if haveExact {
		res.AnomalyScore = clampScore(exact)
	} else {
		res.AnomalyScore = clampScore(score)
	}
	for tag := range tagSet {
		res.Tags = append(res.Tags, tag)
	}
	sort.Strings(res.Tags)
	return res
}

// Close releases transaction resources.
func (t *Tx) Close() { _ = t.tx.Close() }

// severityRank inverts Coraza's scale, where 0 is most severe, so that a higher
// number means more severe. Critical becomes 5, warning 3, notice 2.
func severityRank(s types.RuleSeverity) uint8 {
	if s > 7 {
		return 0
	}
	return 7 - uint8(s)
}

// anomalyWeight reproduces the CRS severity-to-score mapping.
func anomalyWeight(meta types.RuleMetadata) int {
	if !isDetectionRule(meta) {
		return 0
	}
	switch meta.Severity() {
	case types.RuleSeverityCritical:
		return 5
	case types.RuleSeverityError:
		return 4
	case types.RuleSeverityWarning:
		return 3
	case types.RuleSeverityNotice:
		return 2
	default:
		return 0
	}
}

// isDetectionRule excludes CRS scoring, correlation and setup rules, which
// carry a severity but contribute no anomaly points of their own.
func isDetectionRule(meta types.RuleMetadata) bool {
	id := meta.ID()
	if id >= 900000 && id < 901000 {
		return false
	}
	if id >= 949000 && id < 950000 {
		return false
	}
	if id >= 959000 && id < 960000 {
		return false
	}
	if id >= 980000 && id < 981000 {
		return false
	}
	for _, tag := range meta.Tags() {
		if tag == "anomaly-evaluation" {
			return false
		}
	}
	return true
}

func paranoiaFromTags(tags []string) uint8 {
	for _, tag := range tags {
		if v, ok := strings.CutPrefix(tag, "paranoia-level/"); ok {
			if n, err := strconv.Atoi(v); err == nil && n >= 0 && n <= 255 {
				return uint8(n)
			}
		}
	}
	return 0
}

func parseTotalScore(msg string) (int, bool) {
	m := totalScoreRe.FindStringSubmatch(msg)
	if len(m) != 2 {
		return 0, false
	}
	n, err := strconv.Atoi(m[1])
	return n, err == nil
}

func clampScore(n int) uint16 {
	if n < 0 {
		return 0
	}
	if n > 65535 {
		return 65535
	}
	return uint16(n)
}

func hostOnly(host string) string {
	if i := strings.LastIndex(host, ":"); i > 0 && !strings.Contains(host[i:], "]") {
		return host[:i]
	}
	return host
}

func protoVersion(proto string) string {
	if v, ok := strings.CutPrefix(proto, "HTTP/"); ok {
		return v
	}
	return "1.1"
}
