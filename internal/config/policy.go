package config

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

// CapturePolicy controls how much of a request is recorded.
type CapturePolicy struct {
	Enabled        bool     `json:"enabled"`
	BodyCapBytes   int64    `json:"body_cap_bytes"`
	InlineMaxBytes int64    `json:"inline_max_bytes"`
	SkipPaths      []string `json:"skip_paths"`
	BinaryTypes    []string `json:"binary_types"`
}

// RedactionPolicy lists what is masked before an event is written to disk.
type RedactionPolicy struct {
	Enabled bool     `json:"enabled"`
	Headers []string `json:"headers"`
	Fields  []string `json:"fields"`
	Mask    string   `json:"mask"`
}

// Blocking modes.
const (
	// ModeDetect records what would have happened and forwards everything.
	ModeDetect = "detect"
	// ModeBlock rejects a request once its anomaly score reaches the threshold.
	ModeBlock = "block"
)

// WAFPolicy configures Coraza for one app.
//
// The rule engine itself is always detection-only. Whether a request is
// actually rejected is decided here, from the same anomaly score the simulator
// reports, so enforcing does exactly what the simulation said it would.
type WAFPolicy struct {
	Enabled       bool     `json:"enabled"`
	Mode          string   `json:"mode"`
	ParanoiaLevel int      `json:"paranoia_level"`
	Threshold     int      `json:"threshold"`
	ExtraRules    []string `json:"extra_rules"`
}

// Blocks reports whether this policy rejects requests rather than only
// recording them.
func (p WAFPolicy) Blocks() bool { return p.Enabled && p.Mode == ModeBlock }

// ValidMode reports whether a mode is one this proxy understands.
func ValidMode(mode string) bool {
	return mode == ModeDetect || mode == ModeBlock
}

// Header is one header the proxy adds to the upstream request. A slice rather
// than a map, so the order the operator wrote them in is kept.
type Header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// reservedHeaders are never taken from configuration: Host has its own
// setting, and the rest frame the connection.
var reservedHeaders = map[string]bool{
	"host": true, "connection": true, "keep-alive": true, "proxy-authenticate": true,
	"proxy-connection": true, "te": true, "trailer": true, "transfer-encoding": true,
	"upgrade": true, "content-length": true,
}

// ValidHeaderName reports whether a name can be set from configuration.
func ValidHeaderName(name string) error {
	if name == "" {
		return errors.New("a header needs a name")
	}
	if reservedHeaders[strings.ToLower(name)] {
		return fmt.Errorf("%s is set by the proxy and cannot be overridden here", name)
	}
	for _, r := range name {
		// RFC 9110 token characters.
		if r <= ' ' || r >= 0x7f || strings.ContainsRune(`"(),/:;<=>?@[\]{}`, r) {
			return fmt.Errorf("%q is not a valid header name", name)
		}
	}
	return nil
}

// ValidHeaderValue rejects a value that would split the request.
func ValidHeaderValue(value string) error {
	if strings.ContainsAny(value, "\r\n") {
		return errors.New("a header value cannot contain a line break")
	}
	return nil
}

// App is one proxied application.
type App struct {
	ID                string   `json:"id"`
	Name              string   `json:"name"`
	Hostnames         []string `json:"hostnames"`
	UpstreamURL       string   `json:"upstream_url"`
	UpstreamTLSVerify bool     `json:"upstream_tls_verify"`
	PreserveHost      bool     `json:"preserve_host"`
	// RootRedirect, when set, answers a request for "/" with a 302 to this
	// path instead of forwarding it, for an application that lives under a
	// prefix such as /geoserver/web/.
	RootRedirect string `json:"root_redirect"`
	// ExtraHeaders are added to the upstream request, after the forwarding
	// headers, so an application that needs its own can have them.
	ExtraHeaders []Header `json:"extra_headers"`
	// NoLog proxies and inspects this application's traffic but records none
	// of it: no event, no body, nothing on disk. Enforcement still applies.
	NoLog bool `json:"no_log"`
	// HTTPOnly serves this application over plain HTTP only. The proxy
	// presents no certificate for its hostnames and mints none, so a client
	// reaching for TLS is refused rather than handed a certificate for a site
	// that was never meant to have one.
	HTTPOnly       bool            `json:"http_only"`
	TrustedCIDRs   []string        `json:"trusted_cidrs"`
	ClientIPHeader string          `json:"client_ip_header"`
	RetentionDays  int             `json:"retention_days"`
	Capture        CapturePolicy   `json:"capture"`
	Redaction      RedactionPolicy `json:"redaction"`
	WAF            WAFPolicy       `json:"waf"`
	Enabled        bool            `json:"enabled"`
	CreatedAt      time.Time       `json:"created_at"`
	UpdatedAt      time.Time       `json:"updated_at"`

	// trusted is the parsed form of TrustedCIDRs, precomputed when the app is
	// loaded so the request path does no parsing.
	trusted []netip.Prefix
}

// SetTrusted stores the parsed trusted-proxy prefixes.
func (a *App) SetTrusted(p []netip.Prefix) { a.trusted = p }

// TrustedPrefixes returns the parsed trusted-proxy prefixes.
func (a *App) TrustedPrefixes() []netip.Prefix { return a.trusted }

// DefaultCapture returns the capture policy applied to a new app.
func DefaultCapture() CapturePolicy {
	return CapturePolicy{
		Enabled:        true,
		BodyCapBytes:   256 << 10,
		InlineMaxBytes: 16 << 10,
		BinaryTypes: []string{
			"image/", "video/", "audio/", "font/",
			"application/octet-stream", "application/pdf", "application/zip",
		},
	}
}

// DefaultRedaction returns the redaction policy applied to a new app.
func DefaultRedaction() RedactionPolicy {
	return RedactionPolicy{
		Enabled: true,
		Headers: []string{"authorization", "cookie", "set-cookie", "proxy-authorization", "x-api-key"},
		Fields:  []string{"password", "passwd", "token", "secret", "api_key", "apikey", "card", "ssn"},
		Mask:    "[REDACTED]",
	}
}

// DefaultWAF returns the WAF policy applied to a new app.
func DefaultWAF() WAFPolicy {
	// New applications record rather than reject. Enforcing is something you
	// turn on after reading what it would have cost.
	return WAFPolicy{Enabled: true, Mode: ModeDetect, ParanoiaLevel: 1, Threshold: 5}
}

// ApplyDefaults fills unset fields on an app loaded from storage and normalizes
// nil slices to empty ones, which the array columns require.
func (a *App) ApplyDefaults() {
	if a.Hostnames == nil {
		a.Hostnames = []string{}
	}
	if a.TrustedCIDRs == nil {
		a.TrustedCIDRs = []string{}
	}
	if a.Capture.SkipPaths == nil {
		a.Capture.SkipPaths = []string{}
	}
	if a.Redaction.Headers == nil {
		a.Redaction.Headers = []string{}
	}
	if a.Redaction.Fields == nil {
		a.Redaction.Fields = []string{}
	}
	if a.WAF.ExtraRules == nil {
		a.WAF.ExtraRules = []string{}
	}
	if a.ExtraHeaders == nil {
		a.ExtraHeaders = []Header{}
	}
	if a.ClientIPHeader == "" {
		a.ClientIPHeader = "X-Real-IP"
	}
	if a.RetentionDays == 0 {
		a.RetentionDays = 90
	}
	if a.Capture.BodyCapBytes == 0 {
		a.Capture.BodyCapBytes = DefaultCapture().BodyCapBytes
	}
	if a.Capture.InlineMaxBytes == 0 {
		a.Capture.InlineMaxBytes = DefaultCapture().InlineMaxBytes
	}
	if len(a.Capture.BinaryTypes) == 0 {
		a.Capture.BinaryTypes = DefaultCapture().BinaryTypes
	}
	if a.Redaction.Mask == "" {
		a.Redaction.Mask = DefaultRedaction().Mask
	}
	if !ValidMode(a.WAF.Mode) {
		a.WAF.Mode = ModeDetect
	}
	if a.WAF.ParanoiaLevel == 0 {
		a.WAF.ParanoiaLevel = 1
	}
	if a.WAF.Threshold == 0 {
		a.WAF.Threshold = 5
	}
}
