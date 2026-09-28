package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Exclusion is a generated CRS tuning directive for one app.
//
// An empty Target disables the rule outright; a Target such as ARGS:comment
// removes only that variable from the rule. A Path scopes the exclusion to
// requests whose URI starts with it, which requires a generated rule ID.
type Exclusion struct {
	ID        string    `json:"id"`
	AppID     string    `json:"app_id"`
	RuleID    int64     `json:"rule_id"`
	Target    string    `json:"target"`
	Path      string    `json:"path"`
	Reason    string    `json:"reason"`
	SecLang   string    `json:"seclang"`
	Enabled   bool      `json:"enabled"`
	CreatedBy string    `json:"created_by,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// exclusionRuleIDBase is where generated path-scoped rules start numbering, well
// clear of the CRS range.
const exclusionRuleIDBase = 10000000

// BuildSecLang renders the directive for an exclusion. genID is used only by
// path-scoped exclusions, which are expressed as a rule with a ctl action.
func BuildSecLang(e Exclusion, genID int) string {
	target := strings.TrimSpace(e.Target)
	path := strings.TrimSpace(e.Path)

	switch {
	case path != "" && target != "":
		return fmt.Sprintf(
			`SecRule REQUEST_URI "@beginsWith %s" "id:%d,phase:2,pass,nolog,ctl:ruleRemoveTargetById=%d;%s"`,
			path, genID, e.RuleID, target)
	case path != "":
		return fmt.Sprintf(
			`SecRule REQUEST_URI "@beginsWith %s" "id:%d,phase:1,pass,nolog,ctl:ruleRemoveById=%d"`,
			path, genID, e.RuleID)
	case target != "":
		return fmt.Sprintf(`SecRuleUpdateTargetById %d "!%s"`, e.RuleID, target)
	default:
		return fmt.Sprintf(`SecRuleRemoveById %d`, e.RuleID)
	}
}

// SaveExclusion stores an exclusion, rendering its directive.
func (s *Store) SaveExclusion(ctx context.Context, e Exclusion) (Exclusion, error) {
	e.SecLang = BuildSecLang(e, exclusionRuleIDBase)
	err := s.pool.QueryRow(ctx, `
		INSERT INTO rule_exclusions (app_id, rule_id, target, reason, seclang, enabled, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7)
		RETURNING id, created_at`,
		nullable(e.AppID), e.RuleID, exclusionTarget(e), e.Reason, e.SecLang, e.Enabled,
		nullable(e.CreatedBy)).Scan(&e.ID, &e.CreatedAt)
	if err != nil {
		return Exclusion{}, fmt.Errorf("store: save exclusion: %w", err)
	}
	return e, nil
}

// exclusionTarget packs Target and Path into the single stored target column.
func exclusionTarget(e Exclusion) string {
	if e.Path == "" {
		return e.Target
	}
	return e.Target + "\x1fpath=" + e.Path
}

func unpackTarget(stored string) (target, path string) {
	target, rest, found := strings.Cut(stored, "\x1f")
	if !found {
		return target, ""
	}
	return target, strings.TrimPrefix(rest, "path=")
}

// ListExclusions returns exclusions, optionally filtered to one app.
func (s *Store) ListExclusions(ctx context.Context, apps []string) ([]Exclusion, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, COALESCE(app_id, ''), rule_id, target, reason, seclang, enabled,
		       COALESCE(created_by::text, ''), created_at
		FROM rule_exclusions
		WHERE (coalesce(cardinality($1::text[]), 0) = 0 OR app_id = ANY($1))
		ORDER BY created_at DESC`, apps)
	if err != nil {
		return nil, fmt.Errorf("store: list exclusions: %w", err)
	}
	defer rows.Close()

	var out []Exclusion
	for rows.Next() {
		var e Exclusion
		var stored string
		if err := rows.Scan(&e.ID, &e.AppID, &e.RuleID, &stored, &e.Reason, &e.SecLang,
			&e.Enabled, &e.CreatedBy, &e.CreatedAt); err != nil {
			return nil, fmt.Errorf("store: scan exclusion: %w", err)
		}
		e.Target, e.Path = unpackTarget(stored)
		out = append(out, e)
	}
	return out, rows.Err()
}

// ExclusionRules renders every enabled exclusion for an app as SecLang, with
// unique IDs assigned to the path-scoped ones.
func (s *Store) ExclusionRules(ctx context.Context, appID string) ([]string, error) {
	exclusions, err := s.ListExclusions(ctx, []string{appID})
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(exclusions))
	genID := exclusionRuleIDBase
	for _, e := range exclusions {
		if !e.Enabled {
			continue
		}
		out = append(out, BuildSecLang(e, genID))
		genID++
	}
	return out, nil
}

// ExclusionApp returns the app an exclusion belongs to, so a caller can be
// checked against it before changing it.
func (s *Store) ExclusionApp(ctx context.Context, id string) (string, error) {
	var appID string
	err := s.pool.QueryRow(ctx,
		`SELECT COALESCE(app_id, '') FROM rule_exclusions WHERE id = $1`, id).Scan(&appID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("store: exclusion app: %w", err)
	}
	return appID, nil
}

// SetExclusionEnabled toggles an exclusion.
func (s *Store) SetExclusionEnabled(ctx context.Context, id string, enabled bool) error {
	tag, err := s.pool.Exec(ctx, `UPDATE rule_exclusions SET enabled = $2 WHERE id = $1`, id, enabled)
	if err != nil {
		return fmt.Errorf("store: toggle exclusion: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteExclusion removes an exclusion.
func (s *Store) DeleteExclusion(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM rule_exclusions WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("store: delete exclusion: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// FPMark records an analyst's verdict on one rule match.
type FPMark struct {
	ID        string    `json:"id"`
	EventID   string    `json:"event_id"`
	AppID     string    `json:"app_id"`
	RuleID    int64     `json:"rule_id"`
	Verdict   string    `json:"verdict"`
	Note      string    `json:"note"`
	UserID    string    `json:"user_id,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// SaveFPMark records or replaces a verdict.
func (s *Store) SaveFPMark(ctx context.Context, m FPMark) (FPMark, error) {
	err := s.pool.QueryRow(ctx, `
		INSERT INTO fp_marks (event_id, app_id, rule_id, verdict, note, user_id)
		VALUES ($1,$2,$3,$4,$5,$6)
		ON CONFLICT (event_id, rule_id) DO UPDATE SET
			verdict = EXCLUDED.verdict, note = EXCLUDED.note, user_id = EXCLUDED.user_id
		RETURNING id, created_at`,
		m.EventID, m.AppID, m.RuleID, m.Verdict, m.Note, nullable(m.UserID)).Scan(&m.ID, &m.CreatedAt)
	if err != nil {
		return FPMark{}, fmt.Errorf("store: save fp mark: %w", err)
	}
	return m, nil
}

// FPSummary counts verdicts for one rule in one app.
type FPSummary struct {
	AppID         string `json:"app_id"`
	RuleID        int64  `json:"rule_id"`
	FalsePositive int    `json:"false_positive"`
	TruePositive  int    `json:"true_positive"`
	Unsure        int    `json:"unsure"`
}

// FPSummaries aggregates verdicts per rule, most false positives first.
func (s *Store) FPSummaries(ctx context.Context, apps []string) ([]FPSummary, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT app_id, rule_id,
			count(*) FILTER (WHERE verdict = 'false_positive'),
			count(*) FILTER (WHERE verdict = 'true_positive'),
			count(*) FILTER (WHERE verdict = 'unsure')
		FROM fp_marks
		WHERE (coalesce(cardinality($1::text[]), 0) = 0 OR app_id = ANY($1))
		GROUP BY app_id, rule_id
		ORDER BY 3 DESC`, apps)
	if err != nil {
		return nil, fmt.Errorf("store: fp summaries: %w", err)
	}
	defer rows.Close()

	var out []FPSummary
	for rows.Next() {
		var f FPSummary
		if err := rows.Scan(&f.AppID, &f.RuleID, &f.FalsePositive, &f.TruePositive, &f.Unsure); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// FPMarksForEvents returns verdicts for a set of events, keyed by event ID.
func (s *Store) FPMarksForEvents(ctx context.Context, eventIDs []string) (map[string][]FPMark, error) {
	if len(eventIDs) == 0 {
		return map[string][]FPMark{}, nil
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, event_id::text, app_id, rule_id, verdict, note, COALESCE(user_id::text,''), created_at
		FROM fp_marks WHERE event_id = ANY($1::uuid[])`, eventIDs)
	if err != nil {
		return nil, fmt.Errorf("store: fp marks: %w", err)
	}
	defer rows.Close()

	out := make(map[string][]FPMark)
	for rows.Next() {
		var m FPMark
		if err := rows.Scan(&m.ID, &m.EventID, &m.AppID, &m.RuleID, &m.Verdict, &m.Note,
			&m.UserID, &m.CreatedAt); err != nil {
			return nil, err
		}
		out[m.EventID] = append(out[m.EventID], m)
	}
	return out, rows.Err()
}

// Annotation is a user's tags, note and bookmark on one event.
type Annotation struct {
	EventID    string    `json:"event_id"`
	AppID      string    `json:"app_id"`
	Tags       []string  `json:"tags"`
	Note       string    `json:"note"`
	Bookmarked bool      `json:"bookmarked"`
	UserID     string    `json:"user_id,omitempty"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// SaveAnnotation stores or replaces an annotation.
func (s *Store) SaveAnnotation(ctx context.Context, a Annotation) error {
	if a.Tags == nil {
		a.Tags = []string{}
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO event_annotations (event_id, app_id, tags, note, bookmarked, user_id, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6, now())
		ON CONFLICT (event_id) DO UPDATE SET
			tags = EXCLUDED.tags, note = EXCLUDED.note,
			bookmarked = EXCLUDED.bookmarked, user_id = EXCLUDED.user_id, updated_at = now()`,
		a.EventID, a.AppID, a.Tags, a.Note, a.Bookmarked, nullable(a.UserID))
	if err != nil {
		return fmt.Errorf("store: save annotation: %w", err)
	}
	return nil
}

// AnnotationsForEvents returns annotations keyed by event ID.
func (s *Store) AnnotationsForEvents(ctx context.Context, eventIDs []string) (map[string]Annotation, error) {
	if len(eventIDs) == 0 {
		return map[string]Annotation{}, nil
	}
	rows, err := s.pool.Query(ctx, `
		SELECT event_id::text, app_id, tags, note, bookmarked, COALESCE(user_id::text,''), updated_at
		FROM event_annotations WHERE event_id = ANY($1::uuid[])`, eventIDs)
	if err != nil {
		return nil, fmt.Errorf("store: annotations: %w", err)
	}
	defer rows.Close()

	out := make(map[string]Annotation)
	for rows.Next() {
		var a Annotation
		if err := rows.Scan(&a.EventID, &a.AppID, &a.Tags, &a.Note, &a.Bookmarked,
			&a.UserID, &a.UpdatedAt); err != nil {
			return nil, err
		}
		out[a.EventID] = a
	}
	return out, rows.Err()
}

// BookmarkedEventIDs returns the events flagged for follow-up.
func (s *Store) BookmarkedEventIDs(ctx context.Context, apps []string, limit int) ([]string, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT event_id::text FROM event_annotations
		WHERE bookmarked AND (coalesce(cardinality($1::text[]), 0) = 0 OR app_id = ANY($1))
		ORDER BY updated_at DESC LIMIT $2`, apps, limit)
	if err != nil {
		return nil, fmt.Errorf("store: bookmarks: %w", err)
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
