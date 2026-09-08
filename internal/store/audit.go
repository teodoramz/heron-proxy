package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// AuditEntry records one configuration change or replay.
type AuditEntry struct {
	ID     int64           `json:"id"`
	UserID string          `json:"user_id,omitempty"`
	Action string          `json:"action"`
	Detail json.RawMessage `json:"detail"`
	TS     time.Time       `json:"ts"`
}

// Audit appends an audit entry. Failures are returned but are never fatal to
// the caller's operation.
func (s *Store) Audit(ctx context.Context, userID, action string, detail any) error {
	body, err := json.Marshal(detail)
	if err != nil {
		body = []byte(`{}`)
	}
	_, err = s.pool.Exec(ctx,
		`INSERT INTO audit_log (user_id, action, detail) VALUES ($1,$2,$3)`,
		nullable(userID), action, body)
	if err != nil {
		return fmt.Errorf("store: audit: %w", err)
	}
	return nil
}

// ListAudit returns the most recent audit entries.
func (s *Store) ListAudit(ctx context.Context, limit int) ([]AuditEntry, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, COALESCE(user_id::text,''), action, detail, ts
		FROM audit_log ORDER BY ts DESC LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("store: list audit: %w", err)
	}
	defer rows.Close()

	var out []AuditEntry
	for rows.Next() {
		var a AuditEntry
		var detail []byte
		if err := rows.Scan(&a.ID, &a.UserID, &a.Action, &detail, &a.TS); err != nil {
			return nil, err
		}
		a.Detail = json.RawMessage(detail)
		out = append(out, a)
	}
	return out, rows.Err()
}
