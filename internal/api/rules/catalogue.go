// Package rules builds a searchable catalogue of the OWASP Core Rule Set, so an
// analyst can look up what a rule ID means without reading the .conf files.
package rules

import (
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
)

// Rule is one CRS rule as published in the rule files.
type Rule struct {
	ID       uint32   `json:"id"`
	Message  string   `json:"message"`
	Tags     []string `json:"tags"`
	Severity string   `json:"severity"`
	Paranoia int      `json:"paranoia"`
	Phase    int      `json:"phase"`
	File     string   `json:"file"`
	Category string   `json:"category"`
	Source   string   `json:"source"`
}

// Catalogue is the parsed rule set, ready to search.
type Catalogue struct {
	rules []Rule
	byID  map[uint32]Rule
}

var (
	once    sync.Once
	loaded  *Catalogue
	loadErr error
)

// Load parses the embedded rule files once and caches the result.
func Load() (*Catalogue, error) {
	once.Do(func() {
		loaded, loadErr = parse(coreruleset.FS)
	})
	return loaded, loadErr
}

var (
	idRe       = regexp.MustCompile(`\bid:(\d+)`)
	msgRe      = regexp.MustCompile(`\bmsg:'((?:[^'\\]|\\.)*)'`)
	tagRe      = regexp.MustCompile(`\btag:'((?:[^'\\]|\\.)*)'`)
	severityRe = regexp.MustCompile(`\bseverity:'?([A-Za-z]+)'?`)
	phaseRe    = regexp.MustCompile(`\bphase:(\d)`)
	paranoiaRe = regexp.MustCompile(`^paranoia-level/(\d)$`)
)

func parse(fsys fs.FS) (*Catalogue, error) {
	entries, err := fs.ReadDir(fsys, "@owasp_crs")
	if err != nil {
		return nil, fmt.Errorf("rules: read rule directory: %w", err)
	}
	c := &Catalogue{byID: make(map[uint32]Rule)}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".conf") {
			continue
		}
		body, err := fs.ReadFile(fsys, path.Join("@owasp_crs", entry.Name()))
		if err != nil {
			return nil, fmt.Errorf("rules: read %s: %w", entry.Name(), err)
		}
		for _, directive := range directives(string(body)) {
			rule, ok := parseDirective(directive, entry.Name())
			if !ok {
				continue
			}
			if _, seen := c.byID[rule.ID]; seen {
				continue
			}
			c.byID[rule.ID] = rule
			c.rules = append(c.rules, rule)
		}
	}
	sort.Slice(c.rules, func(i, j int) bool { return c.rules[i].ID < c.rules[j].ID })
	return c, nil
}

// directives splits a rule file into logical directives, joining the backslash
// continuations CRS uses to spread one rule across many lines.
func directives(body string) []string {
	var out []string
	var current strings.Builder

	for _, line := range strings.Split(body, "\n") {
		trimmed := strings.TrimSpace(line)
		if current.Len() == 0 && (trimmed == "" || strings.HasPrefix(trimmed, "#")) {
			continue
		}
		if continued := strings.HasSuffix(trimmed, `\`); continued {
			current.WriteString(strings.TrimSuffix(trimmed, `\`))
			current.WriteByte(' ')
			continue
		}
		current.WriteString(trimmed)
		out = append(out, current.String())
		current.Reset()
	}
	if current.Len() > 0 {
		out = append(out, current.String())
	}
	return out
}

func parseDirective(directive, file string) (Rule, bool) {
	if !strings.HasPrefix(directive, "SecRule") && !strings.HasPrefix(directive, "SecAction") {
		return Rule{}, false
	}
	m := idRe.FindStringSubmatch(directive)
	if m == nil {
		return Rule{}, false
	}
	id, err := strconv.ParseUint(m[1], 10, 32)
	if err != nil {
		return Rule{}, false
	}

	rule := Rule{
		ID:       uint32(id),
		File:     file,
		Category: category(file),
		Source:   directive,
	}
	if m := msgRe.FindStringSubmatch(directive); m != nil {
		rule.Message = m[1]
	}
	if m := severityRe.FindStringSubmatch(directive); m != nil {
		rule.Severity = strings.ToUpper(m[1])
	}
	if m := phaseRe.FindStringSubmatch(directive); m != nil {
		rule.Phase, _ = strconv.Atoi(m[1])
	}
	for _, t := range tagRe.FindAllStringSubmatch(directive, -1) {
		rule.Tags = append(rule.Tags, t[1])
		if p := paranoiaRe.FindStringSubmatch(t[1]); p != nil {
			rule.Paranoia, _ = strconv.Atoi(p[1])
		}
	}
	return rule, true
}

// category turns a file name such as REQUEST-942-APPLICATION-ATTACK-SQLI.conf
// into "Application attack sqli".
func category(file string) string {
	name := strings.TrimSuffix(file, ".conf")
	parts := strings.Split(name, "-")
	if len(parts) > 2 {
		parts = parts[2:]
	}
	joined := strings.ToLower(strings.Join(parts, " "))
	if joined == "" {
		return name
	}
	return strings.ToUpper(joined[:1]) + joined[1:]
}

// Query narrows the catalogue.
type Query struct {
	Text     string
	Tag      string
	Severity string
	Paranoia int
	Category string
	Limit    int
	Offset   int
}

// Result is one page of matching rules.
type Result struct {
	Rules  []Rule `json:"rules"`
	Total  int    `json:"total"`
	Offset int    `json:"offset"`
	Limit  int    `json:"limit"`
}

// Search returns the rules matching a query, in ID order.
func (c *Catalogue) Search(q Query) Result {
	if q.Limit <= 0 || q.Limit > 500 {
		q.Limit = 100
	}
	text := strings.ToLower(strings.TrimSpace(q.Text))

	matched := make([]Rule, 0, 64)
	for _, r := range c.rules {
		if !r.matches(text, q) {
			continue
		}
		matched = append(matched, r)
	}

	total := len(matched)
	if q.Offset > total {
		q.Offset = total
	}
	end := min(q.Offset+q.Limit, total)
	return Result{Rules: matched[q.Offset:end], Total: total, Offset: q.Offset, Limit: q.Limit}
}

func (r Rule) matches(text string, q Query) bool {
	if q.Tag != "" && !hasTag(r.Tags, q.Tag) {
		return false
	}
	if q.Severity != "" && !strings.EqualFold(r.Severity, q.Severity) {
		return false
	}
	if q.Paranoia > 0 && r.Paranoia != q.Paranoia {
		return false
	}
	if q.Category != "" && !strings.EqualFold(r.Category, q.Category) {
		return false
	}
	if text == "" {
		return true
	}
	// A bare number is treated as an ID prefix, which is how people search here.
	if strings.HasPrefix(strconv.FormatUint(uint64(r.ID), 10), text) {
		return true
	}
	if strings.Contains(strings.ToLower(r.Message), text) {
		return true
	}
	if strings.Contains(strings.ToLower(r.Category), text) {
		return true
	}
	for _, t := range r.Tags {
		if strings.Contains(strings.ToLower(t), text) {
			return true
		}
	}
	return false
}

func hasTag(tags []string, want string) bool {
	for _, t := range tags {
		if strings.EqualFold(t, want) {
			return true
		}
	}
	return false
}

// Get returns one rule by ID.
func (c *Catalogue) Get(id uint32) (Rule, bool) {
	r, ok := c.byID[id]
	return r, ok
}

// Len reports how many rules were parsed.
func (c *Catalogue) Len() int { return len(c.rules) }

// Facets lists the distinct values available for filtering.
func (c *Catalogue) Facets() map[string][]string {
	tags := map[string]bool{}
	categories := map[string]bool{}
	severities := map[string]bool{}
	for _, r := range c.rules {
		if r.Category != "" {
			categories[r.Category] = true
		}
		if r.Severity != "" {
			severities[r.Severity] = true
		}
		for _, t := range r.Tags {
			// Only the attack categories are useful as a filter; the rest are
			// bookkeeping such as OWASP_CRS or language markers.
			if strings.HasPrefix(t, "attack-") {
				tags[t] = true
			}
		}
	}
	return map[string][]string{
		"tags":       sortedKeys(tags),
		"categories": sortedKeys(categories),
		"severities": sortedKeys(severities),
	}
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
