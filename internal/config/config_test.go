package config

import (
	"errors"
	"testing"
	"time"
)

func TestLoadDefaults(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Proxy.HTTPSAddr != ":443" {
		t.Errorf("HTTPSAddr = %q, want :443", c.Proxy.HTTPSAddr)
	}
	if c.Pipeline.QueueSize != 50000 {
		t.Errorf("QueueSize = %d, want 50000", c.Pipeline.QueueSize)
	}
}

func TestLoadRejectsShortEncryptionKey(t *testing.T) {
	t.Setenv("ENCRYPTION_KEY", "tooshort")
	if _, err := Load(); err == nil {
		t.Fatal("expected error for 8-byte ENCRYPTION_KEY")
	}
}

func TestLoadAcceptsExactEncryptionKey(t *testing.T) {
	t.Setenv("ENCRYPTION_KEY", "0123456789abcdef0123456789abcdef")
	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(c.API.EncryptionKey) != 32 {
		t.Errorf("key length = %d, want 32", len(c.API.EncryptionKey))
	}
}

func TestValidateRejectsSpoolSmallerThanSegment(t *testing.T) {
	c := &Config{Pipeline: PipelineConfig{
		QueueSize: 1, BatchSize: 1, BatchInterval: time.Second,
		SpoolSegBytes: 100, SpoolMaxBytes: 10,
	}}
	if err := c.Validate(); err == nil {
		t.Fatal("expected error when SPOOL_MAX_BYTES < SPOOL_SEGMENT_BYTES")
	}
}

func TestRequireStorage(t *testing.T) {
	c := &Config{}
	if err := c.RequireStorage(); !errors.Is(err, ErrMissing) {
		t.Fatalf("err = %v, want ErrMissing", err)
	}
}

func TestApplyDefaults(t *testing.T) {
	a := &App{}
	a.ApplyDefaults()
	if a.ClientIPHeader != "X-Real-IP" {
		t.Errorf("ClientIPHeader = %q", a.ClientIPHeader)
	}
	if a.RetentionDays != 90 {
		t.Errorf("RetentionDays = %d, want 90", a.RetentionDays)
	}
	if a.Capture.BodyCapBytes != 256<<10 {
		t.Errorf("BodyCapBytes = %d", a.Capture.BodyCapBytes)
	}
}

func TestEnvListTrims(t *testing.T) {
	t.Setenv("API_ALLOWED_ORIGINS", "https://a.example, https://b.example ,")
	got := envList("API_ALLOWED_ORIGINS", nil)
	if len(got) != 2 || got[1] != "https://b.example" {
		t.Errorf("envList = %#v", got)
	}
}
