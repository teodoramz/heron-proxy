package reader

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/amzteodor/heron/internal/api/query"
)

// Summary is the headline set of numbers for a filtered range.
type Summary struct {
	Requests     uint64  `json:"requests"`
	Clients      uint64  `json:"clients"`
	WouldBlock   uint64  `json:"would_block"`
	Blocked      uint64  `json:"blocked"`
	Errors       uint64  `json:"errors"`
	Bytes        uint64  `json:"bytes"`
	P50Duration  float64 `json:"p50_duration_ms"`
	P95Duration  float64 `json:"p95_duration_ms"`
	P99Duration  float64 `json:"p99_duration_ms"`
	AvgAnomaly   float64 `json:"avg_anomaly"`
	WebsocketNum uint64  `json:"websockets"`
}

// Summary aggregates the filtered range.
func (r *Reader) Summary(ctx context.Context, f query.Filter) (Summary, error) {
	where, args, err := query.Where(f)
	if err != nil {
		return Summary{}, err
	}
	sql := `SELECT
		count(),
		uniq(client_ip),
		countIf(would_block = 1),
		countIf(blocked = 1),
		countIf(status >= 400),
		sum(resp_size),
		quantile(0.5)(duration_ms),
		quantile(0.95)(duration_ms),
		quantile(0.99)(duration_ms),
		avg(anomaly_score),
		countIf(is_websocket = 1)
	FROM traffic WHERE ` + where

	var s Summary
	err = r.conn.QueryRow(ctx, sql, args...).Scan(&s.Requests, &s.Clients, &s.WouldBlock,
		&s.Blocked, &s.Errors, &s.Bytes, &s.P50Duration, &s.P95Duration, &s.P99Duration,
		&s.AvgAnomaly, &s.WebsocketNum)
	if err != nil {
		return Summary{}, fmt.Errorf("reader: summary: %w", err)
	}
	return s, nil
}

// Point is one bucket of the traffic time series.
type Point struct {
	Bucket     time.Time `json:"bucket"`
	Requests   uint64    `json:"requests"`
	S2xx       uint64    `json:"s2xx"`
	S3xx       uint64    `json:"s3xx"`
	S4xx       uint64    `json:"s4xx"`
	S5xx       uint64    `json:"s5xx"`
	WouldBlock uint64    `json:"would_block"`
	P50        float64   `json:"p50_duration_ms"`
	P95        float64   `json:"p95_duration_ms"`
	P99        float64   `json:"p99_duration_ms"`
}

// TimeSeries buckets the filtered range.
func (r *Reader) TimeSeries(ctx context.Context, f query.Filter, bucket time.Duration) ([]Point, error) {
	where, args, err := query.Where(f)
	if err != nil {
		return nil, err
	}
	expr := bucketExpr(bucket)
	sql := fmt.Sprintf(`SELECT
		%s AS bucket,
		count(),
		countIf(status >= 200 AND status < 300),
		countIf(status >= 300 AND status < 400),
		countIf(status >= 400 AND status < 500),
		countIf(status >= 500),
		countIf(would_block = 1),
		quantile(0.5)(duration_ms),
		quantile(0.95)(duration_ms),
		quantile(0.99)(duration_ms)
	FROM traffic WHERE %s GROUP BY bucket ORDER BY bucket`, expr, where)

	rows, err := r.conn.Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("reader: time series: %w", err)
	}
	defer rows.Close()

	var out []Point
	for rows.Next() {
		var p Point
		if err := rows.Scan(&p.Bucket, &p.Requests, &p.S2xx, &p.S3xx, &p.S4xx, &p.S5xx,
			&p.WouldBlock, &p.P50, &p.P95, &p.P99); err != nil {
			return nil, fmt.Errorf("reader: scan point: %w", err)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// RuleStat counts hits for one CRS rule.
//
// There is no per-rule tag list: an event stores the union of tags across every
// rule that matched, so tags cannot be attributed back to a single rule.
type RuleStat struct {
	RuleID  uint32 `json:"rule_id"`
	Hits    uint64 `json:"hits"`
	Clients uint64 `json:"clients"`
	Message string `json:"message,omitempty"`
}

// TopRules ranks the rules that fired most, with a sample message for each.
func (r *Reader) TopRules(ctx context.Context, f query.Filter, limit int) ([]RuleStat, error) {
	where, args, err := query.Where(f)
	if err != nil {
		return nil, err
	}
	// Joining both arrays keeps each message paired with its own rule.
	// arrayResize guards the length mismatch that would fail the whole query.
	sql := fmt.Sprintf(`SELECT rule_id, count() AS hits, uniq(client_ip) AS clients, any(rule_msg)
		FROM traffic
		ARRAY JOIN rule_ids AS rule_id, arrayResize(rule_msgs, length(rule_ids), '') AS rule_msg
		WHERE %s GROUP BY rule_id ORDER BY hits DESC LIMIT %d`, where, clampLimit(limit))

	rows, err := r.conn.Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("reader: top rules: %w", err)
	}
	defer rows.Close()

	var out []RuleStat
	for rows.Next() {
		var s RuleStat
		if err := rows.Scan(&s.RuleID, &s.Hits, &s.Clients, &s.Message); err != nil {
			return nil, fmt.Errorf("reader: scan rule stat: %w", err)
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// IPStat summarizes one source address.
type IPStat struct {
	ClientIP   string    `json:"client_ip"`
	Country    string    `json:"country"`
	ASN        uint32    `json:"asn"`
	ASOrg      string    `json:"as_org"`
	Requests   uint64    `json:"requests"`
	Paths      uint64    `json:"paths"`
	Anomaly    uint64    `json:"anomaly"`
	WouldBlock uint64    `json:"would_block"`
	Errors     uint64    `json:"errors"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
}

// TopIPs ranks source addresses by anomaly then volume.
func (r *Reader) TopIPs(ctx context.Context, f query.Filter, limit int) ([]IPStat, error) {
	where, args, err := query.Where(f)
	if err != nil {
		return nil, err
	}
	sql := fmt.Sprintf(`SELECT client_ip, any(country), any(asn), any(as_org),
			count() AS requests, uniq(path) AS paths, sum(anomaly_score) AS anomaly,
			countIf(would_block = 1), countIf(status >= 400), min(ts), max(ts)
		FROM traffic WHERE %s GROUP BY client_ip
		ORDER BY anomaly DESC, requests DESC LIMIT %d`, where, clampLimit(limit))

	rows, err := r.conn.Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("reader: top ips: %w", err)
	}
	defer rows.Close()

	var out []IPStat
	for rows.Next() {
		var s IPStat
		var ip net.IP
		if err := rows.Scan(&ip, &s.Country, &s.ASN, &s.ASOrg, &s.Requests, &s.Paths,
			&s.Anomaly, &s.WouldBlock, &s.Errors, &s.FirstSeen, &s.LastSeen); err != nil {
			return nil, fmt.Errorf("reader: scan ip stat: %w", err)
		}
		s.ClientIP = toAddr(ip).String()
		out = append(out, s)
	}
	return out, rows.Err()
}

// GroupStat is a generic top-N row.
type GroupStat struct {
	Key        string `json:"key"`
	Requests   uint64 `json:"requests"`
	Errors     uint64 `json:"errors"`
	WouldBlock uint64 `json:"would_block"`
}

// TopBy ranks by one of a fixed set of groupable columns.
func (r *Reader) TopBy(ctx context.Context, f query.Filter, field string, limit int) ([]GroupStat, error) {
	column, ok := groupable[field]
	if !ok {
		return nil, fmt.Errorf("reader: %q is not groupable", field)
	}
	where, args, err := query.Where(f)
	if err != nil {
		return nil, err
	}
	sql := fmt.Sprintf(`SELECT %s AS k, count() AS requests,
			countIf(status >= 400), countIf(would_block = 1)
		FROM traffic WHERE %s GROUP BY k ORDER BY requests DESC LIMIT %d`,
		column, where, clampLimit(limit))

	rows, err := r.conn.Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("reader: top %s: %w", field, err)
	}
	defer rows.Close()

	var out []GroupStat
	for rows.Next() {
		var s GroupStat
		if err := rows.Scan(&s.Key, &s.Requests, &s.Errors, &s.WouldBlock); err != nil {
			return nil, fmt.Errorf("reader: scan group stat: %w", err)
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// groupable restricts GROUP BY to a known set of columns.
var groupable = map[string]string{
	"path":         "path",
	"host":         "host",
	"country":      "country",
	"method":       "method",
	"status":       "toString(status)",
	"user_agent":   "user_agent",
	"ja3":          "ja3",
	"ja4":          "ja4",
	"app_id":       "app_id",
	"content_type": "resp_content_type",
	"as_org":       "as_org",
}

// GroupableFields lists the columns TopBy accepts.
func GroupableFields() []string {
	out := make([]string, 0, len(groupable))
	for k := range groupable {
		out = append(out, k)
	}
	return out
}

// Simulation reports what a blocking threshold would have done.
type Simulation struct {
	Threshold  uint16  `json:"threshold"`
	Total      uint64  `json:"total"`
	WouldBlock uint64  `json:"would_block"`
	Percent    float64 `json:"percent"`
}

// Simulate counts requests whose anomaly score reaches a threshold.
func (r *Reader) Simulate(ctx context.Context, f query.Filter, threshold uint16) (Simulation, error) {
	where, args, err := query.Where(f)
	if err != nil {
		return Simulation{}, err
	}
	sql := "SELECT count(), countIf(anomaly_score >= ?) FROM traffic WHERE " + where
	args = append([]any{threshold}, args...)

	s := Simulation{Threshold: threshold}
	if err := r.conn.QueryRow(ctx, sql, args...).Scan(&s.Total, &s.WouldBlock); err != nil {
		return Simulation{}, fmt.Errorf("reader: simulate: %w", err)
	}
	if s.Total > 0 {
		s.Percent = float64(s.WouldBlock) / float64(s.Total) * 100
	}
	return s, nil
}

// IPProfile is everything known about one source address in a time range.
type IPProfile struct {
	ClientIP     string      `json:"client_ip"`
	Stat         IPStat      `json:"stat"`
	Fingerprints []GroupStat `json:"fingerprints"`
	TopPaths     []GroupStat `json:"top_paths"`
	TopRules     []RuleStat  `json:"top_rules"`
}

// IPProfile builds the per-address view.
func (r *Reader) IPProfile(ctx context.Context, f query.Filter, ip string, limit int) (IPProfile, error) {
	scoped := f
	scoped.Root.Conditions = append(append([]query.Condition(nil), f.Root.Conditions...),
		query.Condition{Field: "client_ip", Op: query.OpEq, Value: ip})

	stats, err := r.TopIPs(ctx, scoped, 1)
	if err != nil {
		return IPProfile{}, err
	}
	profile := IPProfile{ClientIP: ip}
	if len(stats) > 0 {
		profile.Stat = stats[0]
	}
	if profile.Fingerprints, err = r.TopBy(ctx, scoped, "ja4", limit); err != nil {
		return IPProfile{}, err
	}
	if profile.TopPaths, err = r.TopBy(ctx, scoped, "path", limit); err != nil {
		return IPProfile{}, err
	}
	if profile.TopRules, err = r.TopRules(ctx, scoped, limit); err != nil {
		return IPProfile{}, err
	}
	// Empty lists, never null: an address that tripped no rule is the common
	// case, and the UI maps over every list.
	if profile.Fingerprints == nil {
		profile.Fingerprints = []GroupStat{}
	}
	if profile.TopPaths == nil {
		profile.TopPaths = []GroupStat{}
	}
	if profile.TopRules == nil {
		profile.TopRules = []RuleStat{}
	}
	profile.Stat.ClientIP = ip
	return profile, nil
}

func clampLimit(n int) int {
	if n <= 0 {
		return 20
	}
	if n > 500 {
		return 500
	}
	return n
}
