package config

import (
	"net/netip"
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

// App is one proxied application.
type App struct {
	ID                string          `json:"id"`
	Name              string          `json:"name"`
	Hostnames         []string        `json:"hostnames"`
	UpstreamURL       string          `json:"upstream_url"`
	UpstreamTLSVerify bool            `json:"upstream_tls_verify"`
	PreserveHost      bool            `json:"preserve_host"`
	TrustedCIDRs      []string        `json:"trusted_cidrs"`
	ClientIPHeader    string          `json:"client_ip_header"`
	RetentionDays     int             `json:"retention_days"`
	Capture           CapturePolicy   `json:"capture"`
	Redaction         RedactionPolicy `json:"redaction"`
	WAF               WAFPolicy       `json:"waf"`
	Enabled           bool            `json:"enabled"`
	CreatedAt         time.Time       `json:"created_at"`
	UpdatedAt         time.Time       `json:"updated_at"`

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
