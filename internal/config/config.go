// Package config loads process configuration from the environment and defines
// the per-app policy types shared by the proxy and the API.
package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config is the full process configuration. Each service reads the sections it needs.
type Config struct {
	Proxy    ProxyConfig
	API      APIConfig
	Storage  StorageConfig
	Pipeline PipelineConfig
}

// ProxyConfig configures the TLS-terminating reverse proxy.
type ProxyConfig struct {
	HTTPAddr     string
	HTTPSAddr    string
	AdminAddr    string
	RulesDir     string
	GeoIPCityDB  string
	GeoIPASNDB   string
	PollInterval time.Duration
	StreamToken  string
}

// APIConfig configures the query and administration API.
type APIConfig struct {
	ListenAddr     string
	SessionTTL     time.Duration
	AllowedOrigins []string
	ProxyStreamURL string
	StreamToken    string
	EncryptionKey  []byte
}

// StorageConfig holds the data store connection settings.
type StorageConfig struct {
	ClickHouseDSN string
	PostgresDSN   string
	BlobDir       string
	SpoolDir      string
}

// PipelineConfig tunes the ingestion path.
type PipelineConfig struct {
	QueueSize     int
	BatchSize     int
	BatchInterval time.Duration
	SpoolMaxBytes int64
	SpoolSegBytes int64
	BlockOnFull   bool
}

// ErrMissing reports a required variable that was not set.
var ErrMissing = errors.New("missing required configuration")

// Load reads configuration from the environment and validates it.
func Load() (*Config, error) {
	c := &Config{
		Proxy: ProxyConfig{
			HTTPAddr:     env("PROXY_HTTP_ADDR", ":80"),
			HTTPSAddr:    env("PROXY_HTTPS_ADDR", ":443"),
			AdminAddr:    env("PROXY_ADMIN_ADDR", ":9090"),
			RulesDir:     env("PROXY_RULES_DIR", "/rules"),
			GeoIPCityDB:  env("GEOIP_CITY_DB", ""),
			GeoIPASNDB:   env("GEOIP_ASN_DB", ""),
			PollInterval: envDuration("PROXY_POLL_INTERVAL", 5*time.Second),
			StreamToken:  env("INTERNAL_STREAM_TOKEN", ""),
		},
		API: APIConfig{
			ListenAddr:     env("API_LISTEN_ADDR", ":8080"),
			SessionTTL:     envDuration("API_SESSION_TTL", 12*time.Hour),
			AllowedOrigins: envList("API_ALLOWED_ORIGINS", nil),
			ProxyStreamURL: env("API_PROXY_STREAM_URL", "ws://proxy:9090/internal/stream"),
			StreamToken:    env("INTERNAL_STREAM_TOKEN", ""),
		},
		Storage: StorageConfig{
			ClickHouseDSN: env("CLICKHOUSE_DSN", ""),
			PostgresDSN:   env("POSTGRES_DSN", ""),
			BlobDir:       env("BLOB_DIR", "/data/blobs"),
			SpoolDir:      env("SPOOL_DIR", "/data/spool"),
		},
		Pipeline: PipelineConfig{
			QueueSize:     envInt("PIPELINE_QUEUE_SIZE", 50000),
			BatchSize:     envInt("PIPELINE_BATCH_SIZE", 5000),
			BatchInterval: envDuration("PIPELINE_BATCH_INTERVAL", 500*time.Millisecond),
			SpoolMaxBytes: envInt64("SPOOL_MAX_BYTES", 10<<30),
			SpoolSegBytes: envInt64("SPOOL_SEGMENT_BYTES", 64<<20),
			BlockOnFull:   envBool("PIPELINE_BLOCK_ON_FULL", false),
		},
	}

	if key := os.Getenv("ENCRYPTION_KEY"); key != "" {
		if len(key) != 32 {
			return nil, fmt.Errorf("ENCRYPTION_KEY must be exactly 32 bytes, got %d", len(key))
		}
		c.API.EncryptionKey = []byte(key)
	}

	return c, c.Validate()
}

// Validate reports the first configuration error found.
func (c *Config) Validate() error {
	if c.Pipeline.QueueSize < 1 {
		return fmt.Errorf("PIPELINE_QUEUE_SIZE must be positive, got %d", c.Pipeline.QueueSize)
	}
	if c.Pipeline.BatchSize < 1 {
		return fmt.Errorf("PIPELINE_BATCH_SIZE must be positive, got %d", c.Pipeline.BatchSize)
	}
	if c.Pipeline.SpoolSegBytes < 1 {
		return fmt.Errorf("SPOOL_SEGMENT_BYTES must be positive, got %d", c.Pipeline.SpoolSegBytes)
	}
	if c.Pipeline.SpoolMaxBytes < c.Pipeline.SpoolSegBytes {
		return fmt.Errorf("SPOOL_MAX_BYTES (%d) must be at least SPOOL_SEGMENT_BYTES (%d)",
			c.Pipeline.SpoolMaxBytes, c.Pipeline.SpoolSegBytes)
	}
	if c.Pipeline.BatchInterval <= 0 {
		return fmt.Errorf("PIPELINE_BATCH_INTERVAL must be positive, got %s", c.Pipeline.BatchInterval)
	}
	return nil
}

// RequireStorage reports an error if the data store DSNs are unset.
func (c *Config) RequireStorage() error {
	if c.Storage.ClickHouseDSN == "" {
		return fmt.Errorf("%w: CLICKHOUSE_DSN", ErrMissing)
	}
	if c.Storage.PostgresDSN == "" {
		return fmt.Errorf("%w: POSTGRES_DSN", ErrMissing)
	}
	return nil
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envList(key string, def []string) []string {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func envInt(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

func envInt64(key string, def int64) int64 {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return def
	}
	return n
}

func envBool(key string, def bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}

func envDuration(key string, def time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return def
	}
	return d
}
