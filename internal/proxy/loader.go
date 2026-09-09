package proxy

import (
	"context"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/amzteodor/proxy-waf/internal/config"
	"github.com/amzteodor/proxy-waf/internal/proxy/router"
	"github.com/amzteodor/proxy-waf/internal/proxy/tlsx"
	"github.com/amzteodor/proxy-waf/internal/proxy/waf"
	"github.com/amzteodor/proxy-waf/internal/store"
)

// ConfigSource supplies the proxy's live configuration.
type ConfigSource interface {
	ConfigVersion(ctx context.Context) (int64, error)
	ListApps(ctx context.Context) ([]config.App, error)
	ExclusionRules(ctx context.Context, appID string) ([]string, error)
	LoadTLSCertificates(ctx context.Context) ([]tlsx.Cert, error)
}

// Loader keeps the router, certificate store and WAF engine in step with the
// configuration store. It polls a version counter, so an unchanged
// configuration costs one cheap query per interval.
type Loader struct {
	src    ConfigSource
	router *router.Router
	certs  *tlsx.CertStore
	waf    *waf.Engine
	log    *slog.Logger

	version atomic.Int64
	loaded  atomic.Bool
}

// NewLoader builds a Loader.
func NewLoader(src ConfigSource, r *router.Router, c *tlsx.CertStore, w *waf.Engine, log *slog.Logger) *Loader {
	if log == nil {
		log = slog.Default()
	}
	return &Loader{src: src, router: r, certs: c, waf: w, log: log}
}

// Load reads the configuration and installs it.
func (l *Loader) Load(ctx context.Context) error {
	version, err := l.src.ConfigVersion(ctx)
	if err != nil {
		return err
	}
	apps, err := l.src.ListApps(ctx)
	if err != nil {
		return err
	}
	for i := range apps {
		rules, err := l.src.ExclusionRules(ctx, apps[i].ID)
		if err != nil {
			return fmt.Errorf("proxy: exclusions for %s: %w", apps[i].ID, err)
		}
		apps[i].WAF.ExtraRules = rules
	}
	certs, err := l.src.LoadTLSCertificates(ctx)
	if err != nil {
		return err
	}

	l.router.Replace(apps)
	l.certs.Replace(certs)
	l.waf.Reload()
	l.version.Store(version)
	l.loaded.Store(true)

	l.log.Info("configuration loaded", "version", version, "apps", len(apps), "certificates", len(certs))
	return nil
}

// Version returns the configuration version currently installed.
func (l *Loader) Version() int64 { return l.version.Load() }

// Ready reports whether a configuration has been loaded at least once.
func (l *Loader) Ready() bool { return l.loaded.Load() }

// Watch polls for configuration changes until the context is cancelled.
func (l *Loader) Watch(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 5 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			version, err := l.src.ConfigVersion(ctx)
			if err != nil {
				l.log.Error("config version check failed", "err", err)
				continue
			}
			if version == l.version.Load() {
				continue
			}
			if err := l.Load(ctx); err != nil {
				l.log.Error("config reload failed", "err", err)
			}
		}
	}
}

// StoreSource adapts the Postgres store to ConfigSource.
type StoreSource struct{ *store.Store }
