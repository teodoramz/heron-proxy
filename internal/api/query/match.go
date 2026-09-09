package query

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"sync"

	"github.com/amzteodor/proxy-waf/internal/pipeline/event"
)

// Matcher evaluates a filter against events in memory, so the live tail applies
// the same predicates as the stored query.
type Matcher struct {
	filter Filter
	mu     sync.Mutex
	res    map[string]*regexp.Regexp
}

// NewMatcher validates a filter and returns an evaluator for it.
func NewMatcher(f Filter) (*Matcher, error) {
	f.Normalize()
	if err := f.Root.validate(0); err != nil {
		return nil, err
	}
	return &Matcher{filter: f, res: make(map[string]*regexp.Regexp)}, nil
}

// Match reports whether an event satisfies the filter. The time range is
// ignored: a live event is by definition current.
func (m *Matcher) Match(e *event.Event) bool {
	if len(m.filter.Apps) > 0 && !contains(m.filter.Apps, e.AppID) {
		return false
	}
	return m.matchGroup(m.filter.Root, e)
}

func (m *Matcher) matchGroup(g Group, e *event.Event) bool {
	if len(g.Conditions) == 0 && len(g.Groups) == 0 {
		return true
	}
	or := strings.EqualFold(g.Op, "or")
	result := !or // AND folds from true, OR from false

	for _, c := range g.Conditions {
		got := m.matchCondition(c, e)
		if or {
			result = result || got
		} else {
			result = result && got
		}
	}
	for _, sub := range g.Groups {
		got := m.matchGroup(sub, e)
		if or {
			result = result || got
		} else {
			result = result && got
		}
	}
	if g.Not {
		return !result
	}
	return result
}

func (m *Matcher) matchCondition(c Condition, e *event.Event) bool {
	col, ok := columns[c.Field]
	if !ok {
		return false
	}
	switch col.kind {
	case kArrUInt32:
		return matchUintArray(e.RuleIDs, c)
	case kArrString:
		return matchStringArray(e.RuleTags, c)
	case kMap:
		return m.matchMap(mapField(e, col.name), c)
	case kIP:
		return matchIP(ipField(e, col.name), c)
	case kBool:
		return boolField(e, col.name) == (boolToUint8(c.Value) == 1)
	case kUInt:
		return matchUint(uintField(e, col.name), c)
	default:
		return m.matchString(stringField(e, col.name), c)
	}
}

func (m *Matcher) matchString(have string, c Condition) bool {
	switch c.Op {
	case OpEq:
		return have == toString(c.Value)
	case OpNe:
		return have != toString(c.Value)
	case OpContains:
		return strings.Contains(strings.ToLower(have), strings.ToLower(toString(c.Value)))
	case OpPrefix:
		return strings.HasPrefix(have, toString(c.Value))
	case OpSuffix:
		return strings.HasSuffix(have, toString(c.Value))
	case OpExists:
		return have != ""
	case OpIn:
		for _, v := range toSlice(c.Value) {
			if have == toString(v) {
				return true
			}
		}
		return false
	case OpRegex:
		re, err := m.regexp(toString(c.Value))
		if err != nil {
			return false
		}
		return re.MatchString(have)
	}
	return false
}

func (m *Matcher) matchMap(have map[string]string, c Condition) bool {
	key := strings.ToLower(c.Key)
	v, present := have[key]
	switch c.Op {
	case OpExists:
		return present
	case OpEq:
		return present && v == toString(c.Value)
	case OpContains:
		return present && strings.Contains(strings.ToLower(v), strings.ToLower(toString(c.Value)))
	}
	return false
}

func (m *Matcher) regexp(pattern string) (*regexp.Regexp, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if re, ok := m.res[pattern]; ok {
		return re, nil
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	m.res[pattern] = re
	return re, nil
}

func matchUint(have uint64, c Condition) bool {
	switch c.Op {
	case OpEq:
		return have == toUint(c.Value)
	case OpNe:
		return have != toUint(c.Value)
	case OpLt:
		return have < toUint(c.Value)
	case OpLte:
		return have <= toUint(c.Value)
	case OpGt:
		return have > toUint(c.Value)
	case OpGte:
		return have >= toUint(c.Value)
	case OpIn:
		for _, v := range toSlice(c.Value) {
			if have == toUint(v) {
				return true
			}
		}
	}
	return false
}

func matchUintArray(have []uint32, c Condition) bool {
	switch c.Op {
	case OpHas:
		want := uint32(toUint(c.Value))
		for _, v := range have {
			if v == want {
				return true
			}
		}
	case OpIn:
		for _, want := range toSlice(c.Value) {
			w := uint32(toUint(want))
			for _, v := range have {
				if v == w {
					return true
				}
			}
		}
	}
	return false
}

func matchStringArray(have []string, c Condition) bool {
	switch c.Op {
	case OpHas:
		return contains(have, toString(c.Value))
	case OpIn:
		for _, want := range toSlice(c.Value) {
			if contains(have, toString(want)) {
				return true
			}
		}
	}
	return false
}

func matchIP(have netip.Addr, c Condition) bool {
	switch c.Op {
	case OpEq, OpNe:
		want, err := netip.ParseAddr(toString(c.Value))
		equal := err == nil && have == want.Unmap()
		if c.Op == OpNe {
			return !equal
		}
		return equal
	case OpCIDR:
		prefix, err := netip.ParsePrefix(toString(c.Value))
		return err == nil && prefix.Contains(have)
	case OpIn:
		for _, v := range toSlice(c.Value) {
			if want, err := netip.ParseAddr(toString(v)); err == nil && have == want.Unmap() {
				return true
			}
		}
	}
	return false
}

// SortValue returns the value of a sortable field for an event, so a cursor can
// be built for the next page. It mirrors the column the query orders by.
func SortValue(field string, e *event.Event) any {
	col, ok := sortable(field)
	if !ok {
		return nil
	}
	switch col.kind {
	case kUInt:
		return uintField(e, col.name)
	case kBool:
		if boolField(e, col.name) {
			return 1
		}
		return 0
	case kIP:
		return ipField(e, col.name).String()
	case kDateTime:
		return e.TS
	default:
		return stringField(e, col.name)
	}
}

// Field accessors keep the matcher aligned with the SQL column names.

func stringField(e *event.Event, col string) string {
	switch col {
	case "id":
		return e.ID
	case "app_id":
		return e.AppID
	case "country":
		return e.Country
	case "as_org":
		return e.ASOrg
	case "ja3":
		return e.JA3
	case "ja4":
		return e.JA4
	case "method":
		return e.Method
	case "scheme":
		return e.Scheme
	case "host":
		return e.Host
	case "path":
		return e.Path
	case "query":
		return e.Query
	case "http_version":
		return e.HTTPVersion
	case "user_agent":
		return e.UserAgent
	case "req_body_inline":
		return e.ReqBody
	case "resp_content_type":
		return e.RespContentType
	case "upstream":
		return e.Upstream
	case "error":
		return e.Error
	}
	return ""
}

func uintField(e *event.Event, col string) uint64 {
	switch col {
	case "asn":
		return uint64(e.ASN)
	case "req_body_size":
		return e.ReqBodySize
	case "status":
		return uint64(e.Status)
	case "resp_size":
		return e.RespSize
	case "duration_ms":
		return uint64(e.DurationMS)
	case "upstream_ms":
		return uint64(e.UpstreamMS)
	case "waf_ms":
		return uint64(e.WAFMS)
	case "anomaly_score":
		return uint64(e.AnomalyScore)
	case "rule_severity":
		return uint64(e.RuleSeverity)
	case "paranoia_max":
		return uint64(e.ParanoiaMax)
	}
	return 0
}

func boolField(e *event.Event, col string) bool {
	switch col {
	case "would_block":
		return e.WouldBlock
	case "req_truncated":
		return e.ReqTruncated
	case "is_websocket":
		return e.IsWebsocket
	}
	return false
}

func ipField(e *event.Event, col string) netip.Addr {
	if col == "client_ip_claimed" {
		return e.ClientIPClaimed
	}
	return e.ClientIP
}

func mapField(e *event.Event, col string) map[string]string {
	if col == "resp_headers" {
		return e.RespHeaders
	}
	return e.ReqHeaders
}

func contains(haystack []string, needle string) bool {
	for _, v := range haystack {
		if v == needle {
			return true
		}
	}
	return false
}

func toString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case nil:
		return ""
	default:
		return fmt.Sprint(t)
	}
}

func toUint(v any) uint64 {
	switch t := v.(type) {
	case float64:
		if t < 0 {
			return 0
		}
		return uint64(t)
	case int:
		if t < 0 {
			return 0
		}
		return uint64(t)
	case uint64:
		return t
	case string:
		var n uint64
		_, _ = fmt.Sscanf(t, "%d", &n)
		return n
	}
	return 0
}

func toSlice(v any) []any {
	if s, ok := v.([]any); ok {
		return s
	}
	return []any{v}
}
