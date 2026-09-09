package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Role names the permission level of a user.
type Role string

// The three roles, in descending order of privilege.
const (
	RoleAdmin   Role = "admin"
	RoleAnalyst Role = "analyst"
	RoleViewer  Role = "viewer"
)

// Valid reports whether r is a known role.
func (r Role) Valid() bool {
	switch r {
	case RoleAdmin, RoleAnalyst, RoleViewer:
		return true
	}
	return false
}

// AtLeast reports whether r is at least as privileged as want.
func (r Role) AtLeast(want Role) bool {
	rank := map[Role]int{RoleViewer: 1, RoleAnalyst: 2, RoleAdmin: 3}
	return rank[r] >= rank[want]
}

// User is an account that can sign in to the API.
type User struct {
	ID           string     `json:"id"`
	Username     string     `json:"username"`
	PasswordHash string     `json:"-"`
	Role         Role       `json:"role"`
	Enabled      bool       `json:"enabled"`
	CreatedAt    time.Time  `json:"created_at"`
	LastLoginAt  *time.Time `json:"last_login_at,omitempty"`
}

// ErrUsernameTaken reports a username already in use.
var ErrUsernameTaken = errors.New("store: that username is already taken")

// ValidUsername reports whether a name is usable, and why not if it is not.
//
// Letters, digits and a few separators only: a username appears in the audit
// log and in the interface, so it should be readable and unambiguous.
func ValidUsername(name string) error {
	name = strings.TrimSpace(name)
	if len(name) < 2 || len(name) > 40 {
		return errors.New("a username must be between 2 and 40 characters")
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.' || r == '-' || r == '_':
		default:
			return fmt.Errorf("a username cannot contain %q; use letters, digits, dots, dashes or underscores", r)
		}
	}
	return nil
}

// CreateUser inserts a user and returns it.
func (s *Store) CreateUser(ctx context.Context, username, passwordHash string, role Role) (User, error) {
	if !role.Valid() {
		return User{}, fmt.Errorf("store: invalid role %q", role)
	}
	username = strings.TrimSpace(username)
	if err := ValidUsername(username); err != nil {
		return User{}, err
	}
	u := User{Username: username, Role: role, Enabled: true, PasswordHash: passwordHash}
	err := s.pool.QueryRow(ctx, `
		INSERT INTO users (username, password_hash, role) VALUES ($1,$2,$3)
		RETURNING id, created_at`, username, passwordHash, string(role)).Scan(&u.ID, &u.CreatedAt)
	if err != nil {
		if strings.Contains(err.Error(), "users_username_lower_idx") || strings.Contains(err.Error(), "duplicate key") {
			return User{}, ErrUsernameTaken
		}
		return User{}, fmt.Errorf("store: create user: %w", err)
	}
	return u, nil
}

// GetUserByUsername looks a user up for sign-in, ignoring case.
func (s *Store) GetUserByUsername(ctx context.Context, username string) (User, error) {
	return s.scanUser(s.pool.QueryRow(ctx, `
		SELECT id, username, password_hash, role, enabled, created_at, last_login_at
		FROM users WHERE lower(username) = lower($1)`, strings.TrimSpace(username)))
}

// GetUser looks a user up by ID.
func (s *Store) GetUser(ctx context.Context, id string) (User, error) {
	return s.scanUser(s.pool.QueryRow(ctx, `
		SELECT id, username, password_hash, role, enabled, created_at, last_login_at
		FROM users WHERE id = $1`, id))
}

// ListUsers returns every account.
func (s *Store) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, username, password_hash, role, enabled, created_at, last_login_at
		FROM users ORDER BY lower(username)`)
	if err != nil {
		return nil, fmt.Errorf("store: list users: %w", err)
	}
	defer rows.Close()

	var out []User
	for rows.Next() {
		u, err := s.scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// UpdateUser changes role and enabled state.
func (s *Store) UpdateUser(ctx context.Context, id string, role Role, enabled bool) error {
	if !role.Valid() {
		return fmt.Errorf("store: invalid role %q", role)
	}
	tag, err := s.pool.Exec(ctx, `UPDATE users SET role = $2, enabled = $3 WHERE id = $1`,
		id, string(role), enabled)
	if err != nil {
		return fmt.Errorf("store: update user: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// SetPassword replaces a user's password hash.
func (s *Store) SetPassword(ctx context.Context, id, passwordHash string) error {
	tag, err := s.pool.Exec(ctx, `UPDATE users SET password_hash = $2 WHERE id = $1`, id, passwordHash)
	if err != nil {
		return fmt.Errorf("store: set password: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// TouchLogin records a successful sign-in.
func (s *Store) TouchLogin(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `UPDATE users SET last_login_at = now() WHERE id = $1`, id)
	return err
}

// DeleteUser removes an account.
func (s *Store) DeleteUser(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("store: delete user: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// SetAppAccess replaces a user's per-app visibility list. An empty list means
// the user sees every app, subject to their role.
func (s *Store) SetAppAccess(ctx context.Context, userID string, appIDs []string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("store: begin: %w", err)
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `DELETE FROM app_access WHERE user_id = $1`, userID); err != nil {
		return fmt.Errorf("store: clear app access: %w", err)
	}
	for _, appID := range appIDs {
		if _, err := tx.Exec(ctx,
			`INSERT INTO app_access (user_id, app_id) VALUES ($1,$2) ON CONFLICT DO NOTHING`,
			userID, appID); err != nil {
			return fmt.Errorf("store: grant app access: %w", err)
		}
	}
	return tx.Commit(ctx)
}

// AppAccess returns the app IDs a user is scoped to, empty meaning all apps.
func (s *Store) AppAccess(ctx context.Context, userID string) ([]string, error) {
	rows, err := s.pool.Query(ctx, `SELECT app_id FROM app_access WHERE user_id = $1`, userID)
	if err != nil {
		return nil, fmt.Errorf("store: app access: %w", err)
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

func (s *Store) scanUser(row scanner) (User, error) {
	var u User
	var role string
	err := row.Scan(&u.ID, &u.Username, &u.PasswordHash, &role, &u.Enabled, &u.CreatedAt, &u.LastLoginAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("store: scan user: %w", err)
	}
	u.Role = Role(role)
	return u, nil
}
