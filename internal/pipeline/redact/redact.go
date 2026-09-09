// Package redact masks credentials in a captured event before it is written to disk.
package redact

import (
	"encoding/json"
	"strings"

	"github.com/amzteodor/heron/internal/config"
	"github.com/amzteodor/heron/internal/pipeline/event"
)

// Redactor applies one app's redaction policy.
type Redactor struct {
	headers map[string]struct{}
	fields  []string
	mask    string
	enabled bool
}

// New builds a Redactor from a policy. Header and field names are matched
// case-insensitively; fields match as substrings, so "api_key" also masks
// "user_api_key".
func New(p config.RedactionPolicy) *Redactor {
	r := &Redactor{
		headers: make(map[string]struct{}, len(p.Headers)),
		fields:  make([]string, 0, len(p.Fields)),
		mask:    p.Mask,
		enabled: p.Enabled,
	}
	if r.mask == "" {
		r.mask = "[REDACTED]"
	}
	for _, h := range p.Headers {
		r.headers[strings.ToLower(strings.TrimSpace(h))] = struct{}{}
	}
	for _, f := range p.Fields {
		if f = strings.ToLower(strings.TrimSpace(f)); f != "" {
			r.fields = append(r.fields, f)
		}
	}
	return r
}

// Apply masks the event in place.
func (r *Redactor) Apply(e *event.Event) {
	if !r.enabled {
		return
	}
	r.maskHeaders(e.ReqHeaders)
	r.maskHeaders(e.RespHeaders)
	e.Query = r.MaskQuery(e.Query)
	if e.ReqBody != "" {
		e.ReqBody = r.MaskBody(e.ReqBody, e.ReqHeaders["content-type"])
	}
}

func (r *Redactor) maskHeaders(h map[string]string) {
	for k := range h {
		if _, ok := r.headers[strings.ToLower(k)]; ok {
			h[k] = r.mask
		}
	}
}

// MaskQuery masks sensitive parameters in a raw query string, preserving order.
func (r *Redactor) MaskQuery(q string) string {
	if q == "" {
		return q
	}
	pairs := strings.Split(q, "&")
	for i, pair := range pairs {
		name, _, found := strings.Cut(pair, "=")
		if found && r.sensitive(name) {
			pairs[i] = name + "=" + r.mask
		}
	}
	return strings.Join(pairs, "&")
}

// MaskBody masks sensitive fields in a request body. JSON and form-encoded
// bodies are handled structurally; anything else is returned unchanged.
func (r *Redactor) MaskBody(body, contentType string) string {
	ct := strings.ToLower(contentType)
	switch {
	case strings.Contains(ct, "json"):
		return r.maskJSON(body)
	case strings.Contains(ct, "x-www-form-urlencoded"):
		return r.MaskQuery(body)
	default:
		return body
	}
}

func (r *Redactor) maskJSON(body string) string {
	var v any
	if err := json.Unmarshal([]byte(body), &v); err != nil {
		return body
	}
	out, err := json.Marshal(r.walk(v))
	if err != nil {
		return body
	}
	return string(out)
}

func (r *Redactor) walk(v any) any {
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			if r.sensitive(k) {
				t[k] = r.mask
			} else {
				t[k] = r.walk(val)
			}
		}
		return t
	case []any:
		for i, val := range t {
			t[i] = r.walk(val)
		}
		return t
	default:
		return v
	}
}

func (r *Redactor) sensitive(name string) bool {
	name = strings.ToLower(name)
	for _, f := range r.fields {
		if strings.Contains(name, f) {
			return true
		}
	}
	return false
}
