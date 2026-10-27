package proxy

import (
	"context"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/amzteodor/heron/internal/config"
	"github.com/amzteodor/heron/internal/proxy/router"
	"github.com/amzteodor/heron/internal/proxy/tlsx"
	"github.com/amzteodor/heron/internal/proxy/waf"
	"github.com/amzteodor/heron/internal/store"
)

// ConfigSource supplies the proxy's live configuration.
type ConfigSource interface {
	ConfigVersion(ctx context.Context) (int64, error)
	ListApps(ctx context.Context) ([]config.App, error)
	ExclusionRules(ctx context.Context, appID string) ([]string, error)
	LoadTLSCertificates(ctx context.Context) ([]tlsx.Cert, error)
	EnsureCA(ctx context.Context, name string) (*tlsx.CA, error)
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
	// The authority signs for hosts with no uploaded certificate, so a new
	// application works before anyone prepares one. It is read on every
	// reload, since regenerating it bumps the configuration version too; the
	// one in use, with its minted certificates, is kept unless it changed.
	if ca, err := l.src.EnsureCA(ctx, "heron"); err != nil {
		if l.certs.CA() == nil {
			l.log.Warn("certificate authority unavailable; hosts without an uploaded certificate will fail", "err", err)
		} else {
			l.log.Warn("certificate authority could not be re-read; keeping the one in use", "err", err)
		}
	} else if cur := l.certs.CA(); cur == nil || cur.Fingerprint() != ca.Fingerprint() {
		l.certs.SetCA(ca)
		l.log.Info("certificate authority ready", "fingerprint", ca.Fingerprint()[:16])
	}

	var plain []string
	for _, a := range apps {
		if a.HTTPOnly {
			plain = append(plain, a.Hostnames...)
		}
	}

	l.router.Replace(apps)
	l.certs.Replace(certs)
	l.certs.SetPlainHosts(plain)
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
