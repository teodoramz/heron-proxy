package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// SavedFilter is a named traffic query.
type SavedFilter struct {
	ID        string          `json:"id"`
	UserID    string          `json:"user_id"`
	Name      string          `json:"name"`
	Query     json.RawMessage `json:"query"`
	Shared    bool            `json:"shared"`
	CreatedAt time.Time       `json:"created_at"`
}

// SaveFilter stores a named filter.
func (s *Store) SaveFilter(ctx context.Context, f SavedFilter) (SavedFilter, error) {
	err := s.pool.QueryRow(ctx, `
		INSERT INTO saved_filters (user_id, name, query, shared)
		VALUES ($1,$2,$3,$4) RETURNING id, created_at`,
		f.UserID, f.Name, []byte(f.Query), f.Shared).Scan(&f.ID, &f.CreatedAt)
	if err != nil {
		return SavedFilter{}, fmt.Errorf("store: save filter: %w", err)
	}
	return f, nil
}

// ListFilters returns a user's own filters plus every shared one.
func (s *Store) ListFilters(ctx context.Context, userID string) ([]SavedFilter, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, user_id::text, name, query, shared, created_at
		FROM saved_filters WHERE user_id = $1 OR shared ORDER BY name`, userID)
	if err != nil {
		return nil, fmt.Errorf("store: list filters: %w", err)
	}
	defer rows.Close()

	var out []SavedFilter
	for rows.Next() {
		var f SavedFilter
		var q []byte
		if err := rows.Scan(&f.ID, &f.UserID, &f.Name, &q, &f.Shared, &f.CreatedAt); err != nil {
			return nil, err
		}
		f.Query = json.RawMessage(q)
		out = append(out, f)
	}
	return out, rows.Err()
}

// DeleteFilter removes a filter the user owns.
func (s *Store) DeleteFilter(ctx context.Context, id, userID string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM saved_filters WHERE id = $1 AND user_id = $2`, id, userID)
	if err != nil {
		return fmt.Errorf("store: delete filter: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
