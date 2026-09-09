// Package chsink writes traffic events to ClickHouse and applies its schema.
package chsink

import (
	"context"
	"embed"
	"fmt"
	"net"
	"net/netip"
	"path"
	"sort"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/amzteodor/heron/internal/pipeline/event"
)

//go:embed all:migrations
var migrations embed.FS

const insertStmt = `INSERT INTO traffic (
	ts, id, app_id, retention_days,
	client_ip, client_ip_claimed, client_port, country, asn, as_org, ja3, ja4,
	method, scheme, host, path, query, http_version, req_headers,
	req_body_size, req_body_inline, req_body_sha256, req_body_blob, req_truncated, user_agent,
	status, resp_headers, resp_size, resp_content_type,
	duration_ms, upstream_ms, waf_ms,
	anomaly_score, rule_ids, rule_msgs, rule_tags, rule_severity, paranoia_max, would_block, blocked,
	upstream, error, is_websocket
)`

// Writer inserts batches of events into ClickHouse.
type Writer struct {
	conn driver.Conn
}

// Open connects to ClickHouse using a DSN such as
// clickhouse://user:pass@host:9000/proxywaf.
func Open(dsn string) (*Writer, error) {
	opts, err := clickhouse.ParseDSN(dsn)
	if err != nil {
		return nil, fmt.Errorf("chsink: parse dsn: %w", err)
	}
	opts.Compression = &clickhouse.Compression{Method: clickhouse.CompressionLZ4}
	opts.MaxOpenConns = 8
	opts.DialTimeout = 5 * time.Second

	conn, err := clickhouse.Open(opts)
	if err != nil {
		return nil, fmt.Errorf("chsink: open: %w", err)
	}
	return &Writer{conn: conn}, nil
}

// Conn exposes the underlying connection for queries.
func (w *Writer) Conn() driver.Conn { return w.conn }

// Ping verifies connectivity.
func (w *Writer) Ping(ctx context.Context) error { return w.conn.Ping(ctx) }

// Close releases the connection.
func (w *Writer) Close() error { return w.conn.Close() }

// Migrate applies every embedded schema file in name order.
func (w *Writer) Migrate(ctx context.Context) error {
	entries, err := migrations.ReadDir("migrations")
	if err != nil {
		return fmt.Errorf("chsink: read migrations: %w", err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	for _, name := range names {
		stmt, err := migrations.ReadFile(path.Join("migrations", name))
		if err != nil {
			return fmt.Errorf("chsink: read %s: %w", name, err)
		}
		if err := w.conn.Exec(ctx, string(stmt)); err != nil {
			return fmt.Errorf("chsink: apply %s: %w", name, err)
		}
	}
	return nil
}

// WriteBatch inserts events in a single batch.
func (w *Writer) WriteBatch(ctx context.Context, events []event.Event) error {
	if len(events) == 0 {
		return nil
	}
	batch, err := w.conn.PrepareBatch(ctx, insertStmt)
	if err != nil {
		return fmt.Errorf("chsink: prepare batch: %w", err)
	}
	for i := range events {
		e := &events[i]
		err := batch.Append(
			e.TS, e.ID, e.AppID, retention(e.RetentionDays),
			ip(e.ClientIP), ip(e.ClientIPClaimed), e.ClientPort, e.Country, e.ASN, e.ASOrg, e.JA3, e.JA4,
			e.Method, e.Scheme, e.Host, e.Path, e.Query, e.HTTPVersion, e.ReqHeaders,
			e.ReqBodySize, e.ReqBody, e.ReqBodySHA, e.ReqBodyBlob, b8(e.ReqTruncated), e.UserAgent,
			e.Status, e.RespHeaders, e.RespSize, e.RespContentType,
			e.DurationMS, e.UpstreamMS, e.WAFMS,
			e.AnomalyScore, e.RuleIDs, e.RuleMsgs, e.RuleTags, e.RuleSeverity, e.ParanoiaMax,
			b8(e.WouldBlock), b8(e.Blocked),
			e.Upstream, e.Error, b8(e.IsWebsocket),
		)
		if err != nil {
			return fmt.Errorf("chsink: append row %d: %w", i, err)
		}
	}
	if err := batch.Send(); err != nil {
		return fmt.Errorf("chsink: send batch: %w", err)
	}
	return nil
}

// ip converts an address to the 16-byte form the IPv6 columns expect.
func ip(a netip.Addr) net.IP {
	if !a.IsValid() {
		return net.IPv6zero
	}
	v := a.As16()
	return net.IP(v[:])
}

func b8(v bool) uint8 {
	if v {
		return 1
	}
	return 0
}

func retention(days uint16) uint16 {
	if days == 0 {
		return 90
	}
	return days
}
