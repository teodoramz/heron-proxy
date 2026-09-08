package store

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/amzteodor/proxy-waf/internal/proxy/tlsx"
)

// Certificate is a stored TLS certificate. PrivateKeyPEM is only populated when
// a certificate is created; it is never returned by a read.
type Certificate struct {
	ID            string    `json:"id"`
	AppID         string    `json:"app_id"`
	SNINames      []string  `json:"sni_names"`
	CertPEM       string    `json:"cert_pem"`
	PrivateKeyPEM string    `json:"private_key_pem,omitempty"`
	Fingerprint   string    `json:"fingerprint"`
	NotBefore     time.Time `json:"not_before"`
	NotAfter      time.Time `json:"not_after"`
	IsDefault     bool      `json:"is_default"`
	CreatedAt     time.Time `json:"created_at"`
}

// ExpiresIn returns the time until the certificate expires.
func (c Certificate) ExpiresIn() time.Duration { return time.Until(c.NotAfter) }

// SaveCertificate validates a key pair, encrypts the private key, and stores it.
// SNI names default to the certificate's own subject and SAN entries.
func (s *Store) SaveCertificate(ctx context.Context, c Certificate) (Certificate, error) {
	pair, err := tls.X509KeyPair([]byte(c.CertPEM), []byte(c.PrivateKeyPEM))
	if err != nil {
		return Certificate{}, fmt.Errorf("store: invalid key pair: %w", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return Certificate{}, fmt.Errorf("store: parse certificate: %w", err)
	}
	sum := sha256.Sum256(pair.Certificate[0])
	c.Fingerprint = hex.EncodeToString(sum[:])
	c.NotBefore, c.NotAfter = leaf.NotBefore, leaf.NotAfter
	if len(c.SNINames) == 0 {
		c.SNINames = certNames(leaf)
	}

	sealed, err := s.encrypt([]byte(c.PrivateKeyPEM))
	if err != nil {
		return Certificate{}, err
	}
	err = s.pool.QueryRow(ctx, `
		INSERT INTO certificates (app_id, sni_names, cert_pem, key_encrypted, fingerprint,
			not_before, not_after, is_default)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		RETURNING id, created_at`,
		nullable(c.AppID), c.SNINames, c.CertPEM, sealed, c.Fingerprint,
		c.NotBefore, c.NotAfter, c.IsDefault).Scan(&c.ID, &c.CreatedAt)
	if err != nil {
		return Certificate{}, fmt.Errorf("store: save certificate: %w", err)
	}
	c.PrivateKeyPEM = ""
	return c, nil
}

// ListCertificates returns certificate metadata without private keys.
func (s *Store) ListCertificates(ctx context.Context) ([]Certificate, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, COALESCE(app_id, ''), sni_names, cert_pem, fingerprint,
		       not_before, not_after, is_default, created_at
		FROM certificates ORDER BY not_after`)
	if err != nil {
		return nil, fmt.Errorf("store: list certificates: %w", err)
	}
	defer rows.Close()

	var out []Certificate
	for rows.Next() {
		var c Certificate
		if err := rows.Scan(&c.ID, &c.AppID, &c.SNINames, &c.CertPEM, &c.Fingerprint,
			&c.NotBefore, &c.NotAfter, &c.IsDefault, &c.CreatedAt); err != nil {
			return nil, fmt.Errorf("store: scan certificate: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// DeleteCertificate removes a certificate.
func (s *Store) DeleteCertificate(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM certificates WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("store: delete certificate: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// LoadTLSCertificates decrypts every stored key pair for the proxy's cert store.
func (s *Store) LoadTLSCertificates(ctx context.Context) ([]tlsx.Cert, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT sni_names, cert_pem, key_encrypted, is_default FROM certificates`)
	if err != nil {
		return nil, fmt.Errorf("store: load certificates: %w", err)
	}
	defer rows.Close()

	var out []tlsx.Cert
	for rows.Next() {
		var (
			names     []string
			certPEM   string
			sealed    []byte
			isDefault bool
		)
		if err := rows.Scan(&names, &certPEM, &sealed, &isDefault); err != nil {
			return nil, fmt.Errorf("store: scan certificate: %w", err)
		}
		keyPEM, err := s.decrypt(sealed)
		if err != nil {
			return nil, err
		}
		pair, err := tls.X509KeyPair([]byte(certPEM), keyPEM)
		if err != nil {
			return nil, fmt.Errorf("store: rebuild key pair: %w", err)
		}
		if leaf, err := x509.ParseCertificate(pair.Certificate[0]); err == nil {
			pair.Leaf = leaf
			if len(names) == 0 {
				names = certNames(leaf)
			}
		}
		out = append(out, tlsx.Cert{Names: names, Default: isDefault, Cert: &pair})
	}
	return out, rows.Err()
}

func certNames(leaf *x509.Certificate) []string {
	names := append([]string(nil), leaf.DNSNames...)
	if leaf.Subject.CommonName != "" {
		names = append(names, leaf.Subject.CommonName)
	}
	return names
}

// ValidatePEM reports whether a block is a parseable certificate chain.
func ValidatePEM(certPEM string) error {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return fmt.Errorf("store: no PEM block found")
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		return fmt.Errorf("store: parse certificate: %w", err)
	}
	return nil
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}
