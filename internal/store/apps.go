package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/amzteodor/heron/internal/config"
)

const appColumns = `id, name, hostnames, upstream_url, upstream_tls_verify, preserve_host, http_only,
	trusted_cidrs, client_ip_header, retention_days, capture, redaction, waf, extra_headers, enabled,
	created_at, updated_at`

// ListApps returns every configured app.
func (s *Store) ListApps(ctx context.Context) ([]config.App, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+appColumns+` FROM apps ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("store: list apps: %w", err)
	}
	defer rows.Close()

	var out []config.App
	for rows.Next() {
		app, err := scanApp(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, app)
	}
	return out, rows.Err()
}

// GetApp returns one app by ID.
func (s *Store) GetApp(ctx context.Context, id string) (config.App, error) {
	row := s.pool.QueryRow(ctx, `SELECT `+appColumns+` FROM apps WHERE id = $1`, id)
	app, err := scanApp(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return config.App{}, ErrNotFound
	}
	return app, err
}

// SaveApp inserts or updates an app.
func (s *Store) SaveApp(ctx context.Context, app config.App) error {
	app.ApplyDefaults()
	headers, _ := json.Marshal(app.ExtraHeaders)
	capture, _ := json.Marshal(app.Capture)
	redaction, _ := json.Marshal(app.Redaction)
	wafPolicy, _ := json.Marshal(app.WAF)

	_, err := s.pool.Exec(ctx, `
		INSERT INTO apps (id, name, hostnames, upstream_url, upstream_tls_verify, preserve_host, http_only,
			trusted_cidrs, client_ip_header, retention_days, capture, redaction, waf, extra_headers, enabled, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15, now())
		ON CONFLICT (id) DO UPDATE SET
			name = EXCLUDED.name,
			hostnames = EXCLUDED.hostnames,
			upstream_url = EXCLUDED.upstream_url,
			upstream_tls_verify = EXCLUDED.upstream_tls_verify,
			preserve_host = EXCLUDED.preserve_host,
			http_only = EXCLUDED.http_only,
			trusted_cidrs = EXCLUDED.trusted_cidrs,
			client_ip_header = EXCLUDED.client_ip_header,
			retention_days = EXCLUDED.retention_days,
			capture = EXCLUDED.capture,
			redaction = EXCLUDED.redaction,
			waf = EXCLUDED.waf,
			extra_headers = EXCLUDED.extra_headers,
			enabled = EXCLUDED.enabled,
			updated_at = now()`,
		app.ID, app.Name, app.Hostnames, app.UpstreamURL, app.UpstreamTLSVerify, app.PreserveHost, app.HTTPOnly,
		app.TrustedCIDRs, app.ClientIPHeader, app.RetentionDays, capture, redaction, wafPolicy, headers, app.Enabled)
	if err != nil {
		return fmt.Errorf("store: save app %s: %w", app.ID, err)
	}
	return nil
}

// DeleteApp removes an app and everything that references it.
func (s *Store) DeleteApp(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM apps WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("store: delete app %s: %w", id, err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

type scanner interface {
	Scan(dest ...any) error
}

func scanApp(row scanner) (config.App, error) {
	var (
		app                                    config.App
		capture, redaction, wafPolicy, headers []byte
	)
	err := row.Scan(&app.ID, &app.Name, &app.Hostnames, &app.UpstreamURL, &app.UpstreamTLSVerify,
		&app.PreserveHost, &app.HTTPOnly, &app.TrustedCIDRs, &app.ClientIPHeader, &app.RetentionDays,
		&capture, &redaction, &wafPolicy, &headers, &app.Enabled, &app.CreatedAt, &app.UpdatedAt)
	if err != nil {
		return config.App{}, err
	}
	_ = json.Unmarshal(capture, &app.Capture)
	_ = json.Unmarshal(redaction, &app.Redaction)
	_ = json.Unmarshal(wafPolicy, &app.WAF)
	_ = json.Unmarshal(headers, &app.ExtraHeaders)
	app.ApplyDefaults()
	return app, nil
}
