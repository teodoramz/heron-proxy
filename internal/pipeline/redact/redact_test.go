package redact

import (
	"strings"
	"testing"

	"github.com/amzteodor/heron/internal/config"
	"github.com/amzteodor/heron/internal/pipeline/event"
)

func newTestRedactor() *Redactor { return New(config.DefaultRedaction()) }

func TestMasksHeadersCaseInsensitively(t *testing.T) {
	r := newTestRedactor()
	e := &event.Event{ReqHeaders: map[string]string{
		"Authorization": "Bearer secret-value",
		"COOKIE":        "session=abc",
		"user-agent":    "curl/8",
	}}
	r.Apply(e)
	if e.ReqHeaders["Authorization"] != "[REDACTED]" {
		t.Errorf("Authorization = %q", e.ReqHeaders["Authorization"])
	}
	if e.ReqHeaders["COOKIE"] != "[REDACTED]" {
		t.Errorf("COOKIE = %q", e.ReqHeaders["COOKIE"])
	}
	if e.ReqHeaders["user-agent"] != "curl/8" {
		t.Errorf("user-agent was modified: %q", e.ReqHeaders["user-agent"])
	}
}

func TestMasksResponseHeaders(t *testing.T) {
	r := newTestRedactor()
	e := &event.Event{RespHeaders: map[string]string{"Set-Cookie": "sid=1; HttpOnly"}}
	r.Apply(e)
	if e.RespHeaders["Set-Cookie"] != "[REDACTED]" {
		t.Errorf("Set-Cookie = %q", e.RespHeaders["Set-Cookie"])
	}
}

func TestMasksQueryPreservingOrder(t *testing.T) {
	r := newTestRedactor()
	got := r.MaskQuery("user=bob&password=hunter2&page=3&api_key=xyz")
	want := "user=bob&password=[REDACTED]&page=3&api_key=[REDACTED]"
	if got != want {
		t.Errorf("got  %q\nwant %q", got, want)
	}
}

func TestMasksFormBody(t *testing.T) {
	r := newTestRedactor()
	got := r.MaskBody("name=a&passwd=b", "application/x-www-form-urlencoded")
	if got != "name=a&passwd=[REDACTED]" {
		t.Errorf("got %q", got)
	}
}

func TestMasksNestedJSON(t *testing.T) {
	r := newTestRedactor()
	got := r.MaskBody(`{"user":{"name":"a","password":"p"},"items":[{"token":"t"}]}`, "application/json")
	if strings.Contains(got, `"p"`) || strings.Contains(got, `"t"`) {
		t.Errorf("secret survived redaction: %s", got)
	}
	if !strings.Contains(got, `"name":"a"`) {
		t.Errorf("non-sensitive field lost: %s", got)
	}
}

func TestMasksSubstringFieldNames(t *testing.T) {
	r := newTestRedactor()
	got := r.MaskBody(`{"user_api_key":"k"}`, "application/json")
	if strings.Contains(got, `"k"`) {
		t.Errorf("substring match failed: %s", got)
	}
}

func TestInvalidJSONLeftIntact(t *testing.T) {
	r := newTestRedactor()
	body := `{"password": broken`
	if got := r.MaskBody(body, "application/json"); got != body {
		t.Errorf("got %q, want unchanged", got)
	}
}

func TestUnknownContentTypeLeftIntact(t *testing.T) {
	r := newTestRedactor()
	body := "password=secret"
	if got := r.MaskBody(body, "text/plain"); got != body {
		t.Errorf("got %q, want unchanged", got)
	}
}

func TestDisabledPolicyIsNoOp(t *testing.T) {
	p := config.DefaultRedaction()
	p.Enabled = false
	e := &event.Event{ReqHeaders: map[string]string{"Authorization": "keep"}}
	New(p).Apply(e)
	if e.ReqHeaders["Authorization"] != "keep" {
		t.Errorf("disabled policy modified the event")
	}
}

func TestCustomMask(t *testing.T) {
	p := config.DefaultRedaction()
	p.Mask = "***"
	if got := New(p).MaskQuery("token=a"); got != "token=***" {
		t.Errorf("got %q", got)
	}
}
