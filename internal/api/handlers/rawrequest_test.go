package handlers

import "testing"

func TestParseRawRequest(t *testing.T) {
	raw := "POST /api/items?page=2 HTTP/1.1\r\n" +
		"Host: shop.local\r\n" +
		"Content-Type: application/json\r\n" +
		"Authorization: Bearer token\r\n" +
		"\r\n" +
		`{"sku":"TL-4417"}`

	got, err := parseRawRequest(raw)
	if err != nil {
		t.Fatalf("parseRawRequest: %v", err)
	}
	if got.Method != "POST" || got.Target != "/api/items?page=2" {
		t.Errorf("request line wrong: %+v", got)
	}
	if got.Headers["Host"] != "shop.local" || got.Headers["Content-Type"] != "application/json" {
		t.Errorf("headers wrong: %v", got.Headers)
	}
	if got.Body != `{"sku":"TL-4417"}` {
		t.Errorf("body = %q", got.Body)
	}
}

func TestParseRawRequestAcceptsBareNewlines(t *testing.T) {
	got, err := parseRawRequest("GET /health HTTP/1.1\nHost: api.local\n\n")
	if err != nil {
		t.Fatalf("parseRawRequest: %v", err)
	}
	if got.Method != "GET" || got.Headers["Host"] != "api.local" {
		t.Errorf("got %+v", got)
	}
}

// TestParseRawRequestKeepsEditedBody is the reason this does not use
// http.ReadRequest: an edited body must not be truncated to a stale
// Content-Length.
func TestParseRawRequestKeepsEditedBody(t *testing.T) {
	raw := "POST /submit HTTP/1.1\nHost: shop.local\nContent-Length: 4\n\nthis body is much longer than four bytes"
	got, err := parseRawRequest(raw)
	if err != nil {
		t.Fatalf("parseRawRequest: %v", err)
	}
	if got.Body != "this body is much longer than four bytes" {
		t.Errorf("body truncated to Content-Length: %q", got.Body)
	}
}

func TestParseRawRequestWithoutBody(t *testing.T) {
	got, err := parseRawRequest("GET / HTTP/1.1\nHost: blog.local")
	if err != nil {
		t.Fatalf("parseRawRequest: %v", err)
	}
	if got.Body != "" || got.Target != "/" {
		t.Errorf("got %+v", got)
	}
}

func TestParseRawRequestErrors(t *testing.T) {
	for _, raw := range []string{
		"", "   ", "GET",
		"GET / HTTP/1.1\nbroken header line\n\n",
		"this is not an HTTP request",
		"get / HTTP/1.1",           // a method must be uppercase
		"GET / NOTHTTP/1.1",        // the version must look like one
		"GET / HTTP/1.1 extra bit", // too many fields on the request line
	} {
		if _, err := parseRawRequest(raw); err == nil {
			t.Errorf("parseRawRequest(%q) returned no error", raw)
		}
	}
}

func TestSplitTarget(t *testing.T) {
	path, query := splitTarget("/a/b?x=1&y=2")
	if path != "/a/b" || query != "x=1&y=2" {
		t.Errorf("got %q %q", path, query)
	}
	if p, q := splitTarget(""); p != "/" || q != "" {
		t.Errorf("got %q %q", p, q)
	}
}
