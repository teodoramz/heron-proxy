// Command api serves the traffic query API, configuration endpoints and the
// live event stream.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/amzteodor/proxy-waf/internal/api"
	"github.com/amzteodor/proxy-waf/internal/api/alerts"
	"github.com/amzteodor/proxy-waf/internal/api/auth"
	"github.com/amzteodor/proxy-waf/internal/api/handlers"
	"github.com/amzteodor/proxy-waf/internal/api/reader"
	"github.com/amzteodor/proxy-waf/internal/api/tail"
	"github.com/amzteodor/proxy-waf/internal/config"
	"github.com/amzteodor/proxy-waf/internal/pipeline/blob"
	"github.com/amzteodor/proxy-waf/internal/pipeline/chsink"
	"github.com/amzteodor/proxy-waf/internal/store"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(log)

	if err := run(log); err != nil {
		log.Error("api exited", "err", err)
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

	// The API owns schema migration for both stores so the proxy can start
	// against a database that is already prepared.
	if err := db.Migrate(ctx); err != nil {
		return err
	}
	ch, err := chsink.Open(cfg.Storage.ClickHouseDSN)
	if err != nil {
		return err
	}
	defer ch.Close()

	if err := ch.Migrate(ctx); err != nil {
		return err
	}
	if err := bootstrapAdmin(ctx, db, log); err != nil {
		return err
	}

	signer, err := auth.NewSigner(sessionKey(), cfg.API.SessionTTL)
	if err != nil {
		return err
	}
	middleware := &auth.Middleware{
		Signer: signer,
		Store:  db,
		Secure: os.Getenv("API_SECURE_COOKIES") == "true",
		Logger: log,
	}

	hub := tail.New(cfg.API.ProxyStreamURL, cfg.API.StreamToken, log)
	go hub.Run(ctx)
	go alerts.New(hub, db, log).Run(ctx)

	handler := &handlers.Handler{
		Reader:         reader.New(ch.Conn()),
		Store:          db,
		Blobs:          blob.New(cfg.Storage.BlobDir),
		Auth:           middleware,
		Tail:           hub,
		Logger:         log,
		AllowedOrigins: cfg.API.AllowedOrigins,
	}
	srv := &http.Server{
		Addr:              cfg.API.ListenAddr,
		Handler:           api.NewRouter(api.Options{Handler: handler, Auth: middleware, AllowedOrigins: cfg.API.AllowedOrigins}),
		ReadHeaderTimeout: 15 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	errc := make(chan error, 1)
	go func() {
		log.Info("api listening", "addr", cfg.API.ListenAddr)
		err := srv.ListenAndServe()
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		errc <- err
	}()

	select {
	case <-ctx.Done():
		log.Info("shutting down")
	case err := <-errc:
		if err != nil {
			return err
		}
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}

// sessionKey returns the configured session signing key. When unset, sessions
// are signed with a per-process random key, which logs everyone out on restart.
func sessionKey() []byte {
	if v := os.Getenv("SESSION_KEY"); v != "" {
		return []byte(v)
	}
	return nil
}

// bootstrapAdmin creates the first administrator from the environment when no
// user exists yet.
func bootstrapAdmin(ctx context.Context, db *store.Store, log *slog.Logger) error {
	users, err := db.ListUsers(ctx)
	if err != nil {
		return err
	}
	if len(users) > 0 {
		return nil
	}
	username := strings.TrimSpace(os.Getenv("ADMIN_USERNAME"))
	password := os.Getenv("ADMIN_PASSWORD")
	if username == "" || password == "" {
		log.Warn("no users exist and ADMIN_USERNAME/ADMIN_PASSWORD are unset; create an administrator before signing in")
		return nil
	}
	if err := store.ValidUsername(username); err != nil {
		return fmt.Errorf("ADMIN_USERNAME: %w", err)
	}
	if len(password) < 12 {
		return errors.New("ADMIN_PASSWORD must be at least 12 characters")
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		return err
	}
	user, err := db.CreateUser(ctx, username, hash, store.RoleAdmin)
	if err != nil {
		return err
	}
	log.Info("bootstrapped the first administrator", "username", user.Username)
	return nil
}
