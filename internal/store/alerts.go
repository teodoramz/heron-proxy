package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// AlertCondition describes when an alert fires. All set fields must hold.
type AlertCondition struct {
	RuleIDs       []uint32 `json:"rule_ids,omitempty"`
	RuleTags      []string `json:"rule_tags,omitempty"`
	MinAnomaly    uint16   `json:"min_anomaly,omitempty"`
	WouldBlock    bool     `json:"would_block,omitempty"`
	StatusAtLeast uint16   `json:"status_at_least,omitempty"`
	PathPrefix    string   `json:"path_prefix,omitempty"`
}

// AlertRule delivers a notification when its condition matches an event.
type AlertRule struct {
	ID        string         `json:"id"`
	Name      string         `json:"name"`
	AppID     string         `json:"app_id"`
	Condition AlertCondition `json:"condition"`
	Channel   string         `json:"channel"`
	TargetURL string         `json:"target_url"`
	// Template is the message body, rendered per event. Empty means the
	// channel's built-in wording.
	Template        string     `json:"template"`
	ThrottleSeconds int        `json:"throttle_seconds"`
	Enabled         bool       `json:"enabled"`
	LastFiredAt     *time.Time `json:"last_fired_at,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
}

// SaveAlertRule inserts or updates an alert rule.
func (s *Store) SaveAlertRule(ctx context.Context, r AlertRule) (AlertRule, error) {
	cond, err := json.Marshal(r.Condition)
	if err != nil {
		return AlertRule{}, fmt.Errorf("store: encode condition: %w", err)
	}
	if r.ID == "" {
		err = s.pool.QueryRow(ctx, `
			INSERT INTO alert_rules (name, app_id, condition, channel, target_url, throttle_seconds, enabled, template)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id, created_at`,
			r.Name, nullable(r.AppID), cond, r.Channel, r.TargetURL, r.ThrottleSeconds, r.Enabled, r.Template).
			Scan(&r.ID, &r.CreatedAt)
	} else {
		_, err = s.pool.Exec(ctx, `
			UPDATE alert_rules SET name=$2, app_id=$3, condition=$4, channel=$5,
				target_url=$6, throttle_seconds=$7, enabled=$8, template=$9 WHERE id=$1`,
			r.ID, r.Name, nullable(r.AppID), cond, r.Channel, r.TargetURL, r.ThrottleSeconds, r.Enabled, r.Template)
	}
	if err != nil {
		return AlertRule{}, fmt.Errorf("store: save alert rule: %w", err)
	}
	return r, nil
}

// ListAlertRules returns every alert rule.
func (s *Store) ListAlertRules(ctx context.Context) ([]AlertRule, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, name, COALESCE(app_id,''), condition, channel, target_url,
		       throttle_seconds, enabled, template, last_fired_at, created_at
		FROM alert_rules ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("store: list alert rules: %w", err)
	}
	defer rows.Close()

	var out []AlertRule
	for rows.Next() {
		var r AlertRule
		var cond []byte
		if err := rows.Scan(&r.ID, &r.Name, &r.AppID, &cond, &r.Channel, &r.TargetURL,
			&r.ThrottleSeconds, &r.Enabled, &r.Template, &r.LastFiredAt, &r.CreatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(cond, &r.Condition)
		out = append(out, r)
	}
	return out, rows.Err()
}

// TouchAlertFired records that a rule just fired, for throttling.
func (s *Store) TouchAlertFired(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `UPDATE alert_rules SET last_fired_at = now() WHERE id = $1`, id)
	return err
}

// DeleteAlertRule removes an alert rule.
func (s *Store) DeleteAlertRule(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM alert_rules WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("store: delete alert rule: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
