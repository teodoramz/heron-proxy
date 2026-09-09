// Package query turns traffic filters into parameterized ClickHouse SQL.
//
// Column and operator names come from a fixed allowlist; every value supplied by
// a caller is bound as a parameter and never concatenated into the statement.
package query

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Op is a comparison operator.
type Op string

// Supported operators.
const (
	OpEq       Op = "eq"
	OpNe       Op = "ne"
	OpLt       Op = "lt"
	OpLte      Op = "lte"
	OpGt       Op = "gt"
	OpGte      Op = "gte"
	OpIn       Op = "in"
	OpContains Op = "contains"
	OpPrefix   Op = "prefix"
	OpSuffix   Op = "suffix"
	OpRegex    Op = "regex"
	OpCIDR     Op = "cidr"
	OpHas      Op = "has"
	OpExists   Op = "exists"
)

// kind classifies a column so operators can be validated against it.
type kind int

const (
	kString kind = iota
	kLowCard
	kUInt
	kIP
	kBool
	kDateTime
	kArrUInt32
	kArrString
	kMap
)

type column struct {
	name string
	kind kind
}

// columns is the complete set of filterable fields.
var columns = map[string]column{
	"id":                {"id", kString},
	"ts":                {"ts", kDateTime},
	"app_id":            {"app_id", kLowCard},
	"client_ip":         {"client_ip", kIP},
	"client_ip_claimed": {"client_ip_claimed", kIP},
	"country":           {"country", kLowCard},
	"asn":               {"asn", kUInt},
	"as_org":            {"as_org", kString},
	"ja3":               {"ja3", kString},
	"ja4":               {"ja4", kString},
	"method":            {"method", kLowCard},
	"scheme":            {"scheme", kLowCard},
	"host":              {"host", kString},
	"path":              {"path", kString},
	"query":             {"query", kString},
	"http_version":      {"http_version", kLowCard},
	"user_agent":        {"user_agent", kString},
	"body":              {"req_body_inline", kString},
	"req_body_size":     {"req_body_size", kUInt},
	"req_truncated":     {"req_truncated", kBool},
	"status":            {"status", kUInt},
	"resp_size":         {"resp_size", kUInt},
	"resp_content_type": {"resp_content_type", kLowCard},
	"duration_ms":       {"duration_ms", kUInt},
	"upstream_ms":       {"upstream_ms", kUInt},
	"waf_ms":            {"waf_ms", kUInt},
	"anomaly_score":     {"anomaly_score", kUInt},
	"rule_id":           {"rule_ids", kArrUInt32},
	"rule_tag":          {"rule_tags", kArrString},
	"rule_severity":     {"rule_severity", kUInt},
	"paranoia_max":      {"paranoia_max", kUInt},
	"would_block":       {"would_block", kBool},
	"upstream":          {"upstream", kString},
	"error":             {"error", kString},
	"is_websocket":      {"is_websocket", kBool},
	"req_header":        {"req_headers", kMap},
	"resp_header":       {"resp_headers", kMap},
}

// allowedOps lists the operators each kind accepts.
var allowedOps = map[kind]map[Op]bool{
	kString:    {OpEq: true, OpNe: true, OpContains: true, OpPrefix: true, OpSuffix: true, OpRegex: true, OpIn: true, OpExists: true},
	kLowCard:   {OpEq: true, OpNe: true, OpIn: true, OpContains: true, OpPrefix: true, OpExists: true},
	kUInt:      {OpEq: true, OpNe: true, OpLt: true, OpLte: true, OpGt: true, OpGte: true, OpIn: true},
	kIP:        {OpEq: true, OpNe: true, OpCIDR: true, OpIn: true},
	kBool:      {OpEq: true},
	kDateTime:  {OpLt: true, OpLte: true, OpGt: true, OpGte: true},
	kArrUInt32: {OpHas: true, OpIn: true},
	kArrString: {OpHas: true, OpIn: true},
	kMap:       {OpEq: true, OpContains: true, OpExists: true},
}

// Condition is a single comparison. Key names the entry for map fields.
type Condition struct {
	Field string `json:"field"`
	Op    Op     `json:"op"`
	Value any    `json:"value,omitempty"`
	Key   string `json:"key,omitempty"`
}

// Group combines conditions and nested groups with AND or OR, optionally negated.
type Group struct {
	Op         string      `json:"op"`
	Not        bool        `json:"not,omitempty"`
	Conditions []Condition `json:"conditions,omitempty"`
	Groups     []Group     `json:"groups,omitempty"`
}

// Filter is a complete traffic query.
type Filter struct {
	From   time.Time `json:"from"`
	To     time.Time `json:"to"`
	Apps   []string  `json:"apps,omitempty"`
	Root   Group     `json:"root"`
	Limit  int       `json:"limit,omitempty"`
	Cursor string    `json:"cursor,omitempty"`
	Order  string    `json:"order,omitempty"`
}

// MaxLimit caps a single page.
const MaxLimit = 500

// DefaultLimit is the page size when none is given.
const DefaultLimit = 100

// maxRegexLen bounds a user-supplied regular expression.
const maxRegexLen = 256

// Normalize applies defaults and caps.
func (f *Filter) Normalize() {
	if f.Limit <= 0 {
		f.Limit = DefaultLimit
	}
	if f.Limit > MaxLimit {
		f.Limit = MaxLimit
	}
	if f.Root.Op == "" {
		f.Root.Op = "and"
	}
	if !strings.EqualFold(f.Order, "asc") {
		f.Order = "desc"
	}
	if f.To.IsZero() {
		f.To = time.Now().UTC().Add(time.Minute)
	}
	if f.From.IsZero() {
		f.From = f.To.Add(-24 * time.Hour)
	}
}

// ParseFilter decodes a filter from JSON and validates it.
func ParseFilter(data []byte) (Filter, error) {
	var f Filter
	if err := json.Unmarshal(data, &f); err != nil {
		return Filter{}, fmt.Errorf("query: parse filter: %w", err)
	}
	f.Normalize()
	if err := f.Root.validate(0); err != nil {
		return Filter{}, err
	}
	return f, nil
}

// maxDepth bounds nesting so a hostile filter cannot blow the stack.
const maxDepth = 8

func (g Group) validate(depth int) error {
	if depth > maxDepth {
		return fmt.Errorf("query: filter nested deeper than %d", maxDepth)
	}
	if op := strings.ToLower(g.Op); op != "" && op != "and" && op != "or" {
		return fmt.Errorf("query: unknown group operator %q", g.Op)
	}
	for _, c := range g.Conditions {
		if err := c.validate(); err != nil {
			return err
		}
	}
	for _, sub := range g.Groups {
		if err := sub.validate(depth + 1); err != nil {
			return err
		}
	}
	return nil
}

func (c Condition) validate() error {
	col, ok := columns[c.Field]
	if !ok {
		return fmt.Errorf("query: unknown field %q", c.Field)
	}
	if !allowedOps[col.kind][c.Op] {
		return fmt.Errorf("query: operator %q not allowed on field %q", c.Op, c.Field)
	}
	if col.kind == kMap && c.Key == "" {
		return fmt.Errorf("query: field %q requires a key", c.Field)
	}
	if c.Op == OpRegex {
		s, ok := c.Value.(string)
		if !ok {
			return fmt.Errorf("query: regex on %q needs a string value", c.Field)
		}
		if len(s) > maxRegexLen {
			return fmt.Errorf("query: regex longer than %d characters", maxRegexLen)
		}
	}
	return nil
}

// Fields returns every filterable field name.
func Fields() []string {
	out := make([]string, 0, len(columns))
	for name := range columns {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// FieldSchema describes one filterable field for the UI.
type FieldSchema struct {
	Field     string `json:"field"`
	Kind      string `json:"kind"`
	Operators []Op   `json:"operators"`
	NeedsKey  bool   `json:"needs_key,omitempty"`
}

var kindNames = map[kind]string{
	kString:    "string",
	kLowCard:   "enum",
	kUInt:      "number",
	kIP:        "ip",
	kBool:      "boolean",
	kDateTime:  "datetime",
	kArrUInt32: "number_array",
	kArrString: "string_array",
	kMap:       "map",
}

// Schema lists every field with the operators it accepts.
func Schema() []FieldSchema {
	out := make([]FieldSchema, 0, len(columns))
	for name, col := range columns {
		ops := make([]Op, 0, len(allowedOps[col.kind]))
		for op := range allowedOps[col.kind] {
			ops = append(ops, op)
		}
		sort.Slice(ops, func(i, j int) bool { return ops[i] < ops[j] })
		out = append(out, FieldSchema{
			Field:     name,
			Kind:      kindNames[col.kind],
			Operators: ops,
			NeedsKey:  col.kind == kMap,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Field < out[j].Field })
	return out
}
