// Package store holds configuration state in Postgres: apps, certificates,
// users, saved filters, rule exclusions, alerts and the audit log.
package store

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"embed"
	"errors"
	"fmt"
	"path"
	"sort"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed all:migrations
var migrations embed.FS

// ErrNotFound reports a missing row.
var ErrNotFound = errors.New("store: not found")

// Store is a Postgres-backed configuration store.
type Store struct {
	pool *pgxpool.Pool
	aead cipher.AEAD
}

// Open connects to Postgres. encryptionKey must be 32 bytes and is used to
// encrypt certificate private keys at rest; an empty key disables encryption
// and rejects certificate writes.
func Open(ctx context.Context, dsn string, encryptionKey []byte) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("store: parse dsn: %w", err)
	}
	cfg.MaxConns = 16
	cfg.MaxConnLifetime = time.Hour

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("store: connect: %w", err)
	}
	s := &Store{pool: pool}
	if len(encryptionKey) > 0 {
		block, err := aes.NewCipher(encryptionKey)
		if err != nil {
			pool.Close()
			return nil, fmt.Errorf("store: cipher: %w", err)
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			pool.Close()
			return nil, fmt.Errorf("store: gcm: %w", err)
		}
		s.aead = aead
	}
	return s, nil
}

// Pool exposes the connection pool.
func (s *Store) Pool() *pgxpool.Pool { return s.pool }

// Ping verifies connectivity.
func (s *Store) Ping(ctx context.Context) error { return s.pool.Ping(ctx) }

// Close releases the pool.
func (s *Store) Close() { s.pool.Close() }

// Migrate applies every embedded schema file in name order.
func (s *Store) Migrate(ctx context.Context) error {
	entries, err := migrations.ReadDir("migrations")
	if err != nil {
		return fmt.Errorf("store: read migrations: %w", err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	for _, name := range names {
		stmt, err := migrations.ReadFile(path.Join("migrations", name))
		if err != nil {
			return fmt.Errorf("store: read %s: %w", name, err)
		}
		if _, err := s.pool.Exec(ctx, string(stmt)); err != nil {
			return fmt.Errorf("store: apply %s: %w", name, err)
		}
	}
	return nil
}

// ConfigVersion returns the counter that increments on any proxy-visible
// configuration change. The proxy polls it to decide whether to reload.
func (s *Store) ConfigVersion(ctx context.Context) (int64, error) {
	var v int64
	err := s.pool.QueryRow(ctx, `SELECT version FROM config_version WHERE id`).Scan(&v)
	if err != nil {
		return 0, fmt.Errorf("store: config version: %w", err)
	}
	return v, nil
}

// encrypt seals a private key with AES-GCM.
func (s *Store) encrypt(plain []byte) ([]byte, error) {
	if s.aead == nil {
		return nil, errors.New("store: no encryption key configured")
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("store: nonce: %w", err)
	}
	return s.aead.Seal(nonce, nonce, plain, nil), nil
}

// decrypt opens a sealed private key.
func (s *Store) decrypt(sealed []byte) ([]byte, error) {
	if s.aead == nil {
		return nil, errors.New("store: no encryption key configured")
	}
	n := s.aead.NonceSize()
	if len(sealed) < n {
		return nil, errors.New("store: ciphertext too short")
	}
	plain, err := s.aead.Open(nil, sealed[:n], sealed[n:], nil)
	if err != nil {
		return nil, fmt.Errorf("store: decrypt: %w", err)
	}
	return plain, nil
}
