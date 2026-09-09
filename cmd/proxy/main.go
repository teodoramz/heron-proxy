// Command proxy runs the TLS-terminating reverse proxy that records traffic.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/amzteodor/proxy-waf/internal/config"
	"github.com/amzteodor/proxy-waf/internal/pipeline"
	"github.com/amzteodor/proxy-waf/internal/pipeline/blob"
	"github.com/amzteodor/proxy-waf/internal/pipeline/chsink"
	"github.com/amzteodor/proxy-waf/internal/pipeline/enrich"
	"github.com/amzteodor/proxy-waf/internal/pipeline/event"
	"github.com/amzteodor/proxy-waf/internal/pipeline/spool"
	"github.com/amzteodor/proxy-waf/internal/proxy"
	"github.com/amzteodor/proxy-waf/internal/proxy/router"
	"github.com/amzteodor/proxy-waf/internal/proxy/tlsx"
	"github.com/amzteodor/proxy-waf/internal/proxy/waf"
	"github.com/amzteodor/proxy-waf/internal/store"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(log)

	if err := run(log); err != nil {
		log.Error("proxy exited", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	if err := cfg.RequireStorage(); err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	db, err := store.Open(ctx, cfg.Storage.PostgresDSN, cfg.API.EncryptionKey)
	if err != nil {
		return err
	}
	defer db.Close()

	ch, err := chsink.Open(cfg.Storage.ClickHouseDSN)
	if err != nil {
		return err
	}
	defer ch.Close()

	sp, err := spool.Open(cfg.Storage.SpoolDir, spool.Options{
		SegmentBytes: cfg.Pipeline.SpoolSegBytes,
		MaxBytes:     cfg.Pipeline.SpoolMaxBytes,
	})
	if err != nil {
		return err
	}
	defer sp.Close()

	pipe := pipeline.New(sp, &clickhouseSink{ch}, pipeline.Options{
		QueueSize:     cfg.Pipeline.QueueSize,
		BatchSize:     cfg.Pipeline.BatchSize,
		BatchInterval: cfg.Pipeline.BatchInterval,
		BlockOnFull:   cfg.Pipeline.BlockOnFull,
		Logger:        log,
	})
	pipe.Start(ctx)
	defer pipe.Close()

	rt := router.New()
	certs := tlsx.NewCertStore()
	engine := waf.NewEngine(cfg.Proxy.RulesDir)

	loader := proxy.NewLoader(db, rt, certs, engine, log)
	if err := loader.Load(ctx); err != nil {
		return err
	}
	go loader.Watch(ctx, cfg.Proxy.PollInterval)

	enricher, err := enrich.New(cfg.Proxy.GeoIPCityDB, cfg.Proxy.GeoIPASNDB)
	if err != nil {
		log.Warn("geoip disabled", "err", err)
	}

	srv := proxy.New(proxy.Options{
		Router:   rt,
		WAF:      engine,
		Sink:     pipe,
		Blobs:    blob.New(cfg.Storage.BlobDir),
		Enricher: enricher,
		Logger:   log,
	})

	admin := &proxy.Admin{Pipeline: pipe, Loader: loader, Token: cfg.Proxy.StreamToken, Logger: log}

	servers := []*http.Server{
		{Addr: cfg.Proxy.AdminAddr, Handler: admin.Handler()},
		{
			Addr:              cfg.Proxy.HTTPAddr,
			Handler:           srv,
			ReadHeaderTimeout: 15 * time.Second,
			IdleTimeout:       90 * time.Second,
			ConnContext:       tlsx.ConnContext,
		},
	}
	errc := make(chan error, 3)

	go func() { errc <- ignoreClosed(servers[0].ListenAndServe()) }()
	go func() {
		ln, err := net.Listen("tcp", cfg.Proxy.HTTPAddr)
		if err != nil {
			errc <- err
			return
		}
		log.Info("http listener started", "addr", cfg.Proxy.HTTPAddr)
		errc <- ignoreClosed(servers[1].Serve(tlsx.NewListener(ln)))
	}()

	httpsSrv := &http.Server{
		Addr:              cfg.Proxy.HTTPSAddr,
		Handler:           srv,
		ReadHeaderTimeout: 15 * time.Second,
		IdleTimeout:       90 * time.Second,
		ConnContext:       tlsx.ConnContext,
		TLSConfig: &tls.Config{
			GetCertificate: certs.GetCertificate,
			MinVersion:     tls.VersionTLS12,
			NextProtos:     []string{"h2", "http/1.1"},
		},
	}
	servers = append(servers, httpsSrv)
	go func() {
		ln, err := net.Listen("tcp", cfg.Proxy.HTTPSAddr)
		if err != nil {
			errc <- err
			return
		}
		log.Info("https listener started", "addr", cfg.Proxy.HTTPSAddr)
		errc <- ignoreClosed(httpsSrv.Serve(tls.NewListener(tlsx.NewListener(ln), httpsSrv.TLSConfig)))
	}()

	select {
	case <-ctx.Done():
		log.Info("shutting down")
	case err := <-errc:
		if err != nil {
			return err
		}
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	for _, s := range servers {
		_ = s.Shutdown(shutdownCtx)
	}
	return nil
}

// clickhouseSink adapts the ClickHouse writer to the pipeline's Sink interface.
type clickhouseSink struct{ w *chsink.Writer }

func (c *clickhouseSink) WriteBatch(ctx context.Context, events []event.Event) error {
	return c.w.WriteBatch(ctx, events)
}

func ignoreClosed(err error) error {
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
