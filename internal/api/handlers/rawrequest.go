package handlers

import (
	"errors"
	"fmt"
	"strings"
)

// rawRequest is an HTTP request as typed by an analyst.
type rawRequest struct {
	Method  string
	Target  string // path with query, as written on the request line
	Headers map[string]string
	Body    string
}

// parseRawRequest reads a request the way a repeater should: forgivingly.
//
// It deliberately does not use http.ReadRequest, which honours Content-Length
// and so would truncate the body whenever someone edits it without correcting
// the header. Everything after the blank line is the body, and Content-Length is
// recalculated when the request is sent.
func parseRawRequest(raw string) (rawRequest, error) {
	text := strings.ReplaceAll(raw, "\r\n", "\n")
	head, body, found := strings.Cut(text, "\n\n")
	if !found {
		head = strings.TrimRight(text, "\n")
	}

	lines := strings.Split(head, "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) == "" {
		return rawRequest{}, errors.New("the request is empty")
	}

	fields := strings.Fields(strings.TrimSpace(lines[0]))
	if len(fields) < 2 || len(fields) > 3 {
		return rawRequest{}, fmt.Errorf(
			"cannot read the request line %q; expected something like 'GET /path HTTP/1.1'", lines[0])
	}
	if !isMethod(fields[0]) {
		return rawRequest{}, fmt.Errorf("%q is not an HTTP method", fields[0])
	}
	// A third field must be the version, which is what separates a real request
	// line from a sentence that happens to have three words.
	if len(fields) == 3 && !strings.HasPrefix(strings.ToUpper(fields[2]), "HTTP/") {
		return rawRequest{}, fmt.Errorf(
			"expected an HTTP version after the path, got %q", fields[2])
	}
	req := rawRequest{
		Method:  fields[0],
		Target:  fields[1],
		Headers: make(map[string]string, len(lines)),
		Body:    body,
	}
	if !strings.HasPrefix(req.Target, "/") && !strings.Contains(req.Target, "://") {
		req.Target = "/" + req.Target
	}

	for _, line := range lines[1:] {
		if strings.TrimSpace(line) == "" {
			continue
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			return rawRequest{}, fmt.Errorf("cannot read the header line %q; expected 'Name: value'", line)
		}
		name = strings.TrimSpace(name)
		if name == "" {
			return rawRequest{}, fmt.Errorf("a header on line %q has no name", line)
		}
		req.Headers[name] = strings.TrimSpace(value)
	}
	return req, nil
}

// isMethod reports whether s is a plausible HTTP method token.
func isMethod(s string) bool {
	if s == "" || len(s) > 20 {
		return false
	}
	for _, r := range s {
		if r < 'A' || r > 'Z' {
			return false
		}
	}
	return true
}

// splitTarget separates the path from the query string.
func splitTarget(target string) (path, query string) {
	path, query, _ = strings.Cut(target, "?")
	if path == "" {
		path = "/"
	}
	return path, query
}
