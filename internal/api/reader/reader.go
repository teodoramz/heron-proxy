// Package reader runs traffic queries against ClickHouse.
package reader

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/google/uuid"

	"github.com/amzteodor/proxy-waf/internal/api/query"
	"github.com/amzteodor/proxy-waf/internal/pipeline/event"
)

// CountCap bounds an exact count; above it the UI shows "N+".
const CountCap = 10000

// Reader queries the traffic table.
type Reader struct{ conn driver.Conn }

// New wraps a ClickHouse connection.
func New(conn driver.Conn) *Reader { return &Reader{conn: conn} }

// Page is one keyset page of events.
type Page struct {
	Events     []event.Event `json:"events"`
	NextCursor string        `json:"next_cursor,omitempty"`
	HasMore    bool          `json:"has_more"`
}

// List returns one page of events plus a cursor for the next.
func (r *Reader) List(ctx context.Context, f query.Filter) (Page, error) {
	f.Normalize()
	sql, args, err := query.List(f)
	if err != nil {
		return Page{}, err
	}
	rows, err := r.conn.Query(ctx, sql, args...)
	if err != nil {
		return Page{}, fmt.Errorf("reader: list: %w", err)
	}
	defer rows.Close()

	page := Page{Events: make([]event.Event, 0, f.Limit)}
	for rows.Next() {
		e, err := scanList(rows)
		if err != nil {
			return Page{}, err
		}
		page.Events = append(page.Events, e)
	}
	if err := rows.Err(); err != nil {
		return Page{}, fmt.Errorf("reader: list rows: %w", err)
	}

	// One extra row was requested to detect a following page.
	if len(page.Events) > f.Limit {
		page.Events = page.Events[:f.Limit]
		page.HasMore = true
	}
	if len(page.Events) > 0 {
		last := page.Events[len(page.Events)-1]
		page.NextCursor = query.EncodeCursor(query.Cursor{TS: last.TS, ID: last.ID})
	}
	return page, nil
}

// Get returns one event in full.
func (r *Reader) Get(ctx context.Context, id string) (event.Event, error) {
	sql := "SELECT " + query.DetailColumns + " FROM traffic WHERE id = ? LIMIT 1"
	rows, err := r.conn.Query(ctx, sql, id)
	if err != nil {
		return event.Event{}, fmt.Errorf("reader: get: %w", err)
	}
	defer rows.Close()

	if !rows.Next() {
		return event.Event{}, ErrNotFound
	}
	return scanDetail(rows)
}

// Count returns an exact count up to CountCap, and whether the cap was reached.
func (r *Reader) Count(ctx context.Context, f query.Filter) (uint64, bool, error) {
	sql, args, err := query.Count(f, CountCap)
	if err != nil {
		return 0, false, err
	}
	var n uint64
	if err := r.conn.QueryRow(ctx, sql, args...).Scan(&n); err != nil {
		return 0, false, fmt.Errorf("reader: count: %w", err)
	}
	return n, n >= CountCap, nil
}

// ErrNotFound reports a missing event.
var ErrNotFound = notFoundError{}

type notFoundError struct{}

func (notFoundError) Error() string { return "reader: event not found" }

func scanList(rows driver.Rows) (event.Event, error) {
	var (
		e                         event.Event
		id                        uuid.UUID
		clientIP, clientIPClaimed net.IP
		truncated, wouldBlock, ws uint8
	)
	err := rows.Scan(&id, &e.TS, &e.AppID, &clientIP, &clientIPClaimed, &e.Country, &e.ASN,
		&e.JA3, &e.JA4, &e.Method, &e.Scheme, &e.Host, &e.Path, &e.Query, &e.HTTPVersion,
		&e.ReqBodySize, &truncated, &e.UserAgent, &e.Status, &e.RespSize, &e.RespContentType,
		&e.DurationMS, &e.UpstreamMS, &e.WAFMS, &e.AnomalyScore, &e.RuleIDs, &e.RuleTags,
		&e.RuleSeverity, &e.ParanoiaMax, &wouldBlock, &e.Upstream, &e.Error, &ws)
	if err != nil {
		return event.Event{}, fmt.Errorf("reader: scan: %w", err)
	}
	e.ID = id.String()
	e.ClientIP = toAddr(clientIP)
	e.ClientIPClaimed = toAddr(clientIPClaimed)
	e.ReqTruncated = truncated == 1
	e.WouldBlock = wouldBlock == 1
	e.IsWebsocket = ws == 1
	return e, nil
}

func scanDetail(rows driver.Rows) (event.Event, error) {
	var (
		e                         event.Event
		id                        uuid.UUID
		clientIP, clientIPClaimed net.IP
		truncated, wouldBlock, ws uint8
	)
	err := rows.Scan(&id, &e.TS, &e.AppID, &clientIP, &clientIPClaimed, &e.Country, &e.ASN,
		&e.JA3, &e.JA4, &e.Method, &e.Scheme, &e.Host, &e.Path, &e.Query, &e.HTTPVersion,
		&e.ReqBodySize, &truncated, &e.UserAgent, &e.Status, &e.RespSize, &e.RespContentType,
		&e.DurationMS, &e.UpstreamMS, &e.WAFMS, &e.AnomalyScore, &e.RuleIDs, &e.RuleTags,
		&e.RuleSeverity, &e.ParanoiaMax, &wouldBlock, &e.Upstream, &e.Error, &ws,
		&e.ReqHeaders, &e.RespHeaders, &e.ReqBody, &e.ReqBodySHA, &e.ReqBodyBlob,
		&e.RuleMsgs, &e.ClientPort, &e.ASOrg, &e.RetentionDays)
	if err != nil {
		return event.Event{}, fmt.Errorf("reader: scan detail: %w", err)
	}
	e.ID = id.String()
	e.ClientIP = toAddr(clientIP)
	e.ClientIPClaimed = toAddr(clientIPClaimed)
	e.ReqTruncated = truncated == 1
	e.WouldBlock = wouldBlock == 1
	e.IsWebsocket = ws == 1
	return e, nil
}

// toAddr converts a ClickHouse IPv6 value, unmapping IPv4 for readability.
func toAddr(ip net.IP) netip.Addr {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Addr{}
	}
	return addr.Unmap()
}

func bucketExpr(bucket time.Duration) string {
	switch {
	case bucket <= time.Minute:
		return "toStartOfMinute(ts)"
	case bucket <= 5*time.Minute:
		return "toStartOfFiveMinutes(ts)"
	case bucket <= 15*time.Minute:
		return "toStartOfFifteenMinutes(ts)"
	case bucket <= time.Hour:
		return "toStartOfHour(ts)"
	default:
		return "toStartOfDay(ts)"
	}
}
