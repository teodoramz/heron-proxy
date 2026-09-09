package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/amzteodor/proxy-waf/internal/proxy/tlsx"
)

// CAInfo describes the proxy's certificate authority without exposing its key.
type CAInfo struct {
	CertPEM     string    `json:"cert_pem"`
	Fingerprint string    `json:"fingerprint"`
	NotAfter    time.Time `json:"not_after"`
	CreatedAt   time.Time `json:"created_at"`
}

// EnsureCA returns the stored authority, generating one on first use.
//
// The authority signs certificates for hostnames with none uploaded, so an
// application can be proxied without preparing anything. Its key is encrypted
// at rest with the same key as uploaded certificates.
func (s *Store) EnsureCA(ctx context.Context, name string) (*tlsx.CA, error) {
	ca, err := s.LoadCA(ctx)
	if err == nil {
		return ca, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return nil, err
	}

	fresh, err := tlsx.NewCA(name)
	if err != nil {
		return nil, err
	}
	keyPEM, err := fresh.KeyPEM()
	if err != nil {
		return nil, err
	}
	sealed, err := s.encrypt(keyPEM)
	if err != nil {
		return nil, err
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO certificate_authority (id, cert_pem, key_encrypted, fingerprint, not_after)
		VALUES (TRUE, $1, $2, $3, $4)
		ON CONFLICT (id) DO NOTHING`,
		fresh.CertPEM(), sealed, fresh.Fingerprint(), fresh.NotAfter())
	if err != nil {
		return nil, fmt.Errorf("store: save authority: %w", err)
	}
	// Another process may have inserted first; read back so every instance
	// signs with the same authority.
	return s.LoadCA(ctx)
}

// LoadCA returns the stored authority.
func (s *Store) LoadCA(ctx context.Context) (*tlsx.CA, error) {
	var (
		certPEM string
		sealed  []byte
	)
	err := s.pool.QueryRow(ctx,
		`SELECT cert_pem, key_encrypted FROM certificate_authority WHERE id`).Scan(&certPEM, &sealed)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: load authority: %w", err)
	}
	keyPEM, err := s.decrypt(sealed)
	if err != nil {
		return nil, err
	}
	return tlsx.LoadCA(certPEM, keyPEM)
}

// CAInfo returns the authority's public details.
func (s *Store) CAInfo(ctx context.Context) (CAInfo, error) {
	var info CAInfo
	err := s.pool.QueryRow(ctx, `
		SELECT cert_pem, fingerprint, not_after, created_at
		FROM certificate_authority WHERE id`).
		Scan(&info.CertPEM, &info.Fingerprint, &info.NotAfter, &info.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return CAInfo{}, ErrNotFound
	}
	if err != nil {
		return CAInfo{}, fmt.Errorf("store: authority info: %w", err)
	}
	return info, nil
}

// RegenerateCA replaces the authority. Every client trusting the old one must
// install the new certificate, so this is deliberately a separate action.
func (s *Store) RegenerateCA(ctx context.Context, name string) (*tlsx.CA, error) {
	if _, err := s.pool.Exec(ctx, `DELETE FROM certificate_authority WHERE id`); err != nil {
		return nil, fmt.Errorf("store: clear authority: %w", err)
	}
	return s.EnsureCA(ctx, name)
}
