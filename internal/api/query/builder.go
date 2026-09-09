package query

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// ListColumns is the projection for the traffic table, excluding large bodies.
const ListColumns = `id, ts, app_id, client_ip, client_ip_claimed, country, asn, ja3, ja4,
	method, scheme, host, path, query, http_version, req_body_size, req_truncated, user_agent,
	status, resp_size, resp_content_type, duration_ms, upstream_ms, waf_ms,
	anomaly_score, rule_ids, rule_tags, rule_severity, paranoia_max, would_block, blocked,
	upstream, error, is_websocket,
	substring(req_body_inline, 1, 200) AS req_body_preview`

// DetailColumns is the full projection for a single event.
const DetailColumns = ListColumns + `, req_headers, resp_headers, req_body_inline,
	req_body_sha256, req_body_blob, rule_msgs, client_port, as_org, retention_days`

// Where renders the filter as a WHERE clause with bound arguments. The clause
// omits the keyset cursor so it can be reused for aggregates.
func Where(f Filter) (string, []any, error) {
	f.Normalize()
	if err := f.Root.validate(0); err != nil {
		return "", nil, err
	}
	var (
		parts []string
		args  []any
	)
	parts = append(parts, "ts >= ? AND ts <= ?")
	args = append(args, f.From, f.To)

	if len(f.Apps) > 0 {
		parts = append(parts, "app_id IN (?)")
		args = append(args, f.Apps)
	}
	clause, groupArgs, err := renderGroup(f.Root)
	if err != nil {
		return "", nil, err
	}
	if clause != "" {
		parts = append(parts, clause)
		args = append(args, groupArgs...)
	}
	return strings.Join(parts, " AND "), args, nil
}

// List renders the paginated traffic query.
//
// Ordering is always by the sort column then the timestamp and id. Those last
// two are unique together, so the order is total and the keyset predicate can
// never skip or repeat a row, whatever the sort column contains.
func List(f Filter) (string, []any, error) {
	f.Normalize()
	where, args, err := Where(f)
	if err != nil {
		return "", nil, err
	}
	col, ok := sortable(f.Sort)
	if !ok {
		return "", nil, fmt.Errorf("query: cannot sort by %q", f.Sort)
	}
	direction := "DESC"
	compare := "<"
	if f.Order == "asc" {
		direction, compare = "ASC", ">"
	}

	byTime := col.name == "ts"
	order := fmt.Sprintf("ts %s, id %s", direction, direction)
	if !byTime {
		order = fmt.Sprintf("%s %s, %s", col.name, direction, order)
	}

	if f.Cursor != "" {
		c, err := DecodeCursor(f.Cursor)
		if err != nil {
			return "", nil, err
		}
		if byTime {
			where += fmt.Sprintf(" AND (ts, id) %s (?, ?)", compare)
			args = append(args, c.TS, c.ID)
		} else {
			value, err := castCursorValue(col, c.Sort)
			if err != nil {
				return "", nil, err
			}
			where += fmt.Sprintf(" AND (%s, ts, id) %s (%s, ?, ?)", col.name, compare, placeholderFor(col))
			args = append(args, value, c.TS, c.ID)
		}
	}

	sql := fmt.Sprintf("SELECT %s FROM traffic WHERE %s ORDER BY %s LIMIT %d",
		ListColumns, where, order, f.Limit+1)
	return sql, args, nil
}

// placeholderFor wraps the bound sort value so its type matches the column.
func placeholderFor(col column) string {
	if col.kind == kIP {
		return "toIPv6(?)"
	}
	return "?"
}

// castCursorValue converts a value that has been through JSON back into
// something the column can be compared with.
func castCursorValue(col column, v any) (any, error) {
	if v == nil {
		return nil, fmt.Errorf("query: cursor is missing its sort value")
	}
	switch col.kind {
	case kUInt:
		switch n := v.(type) {
		case float64:
			return uint64(n), nil
		case string:
			parsed, err := strconv.ParseUint(n, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("query: invalid cursor value")
			}
			return parsed, nil
		}
		return nil, fmt.Errorf("query: invalid cursor value")
	case kBool:
		return boolToUint8(v), nil
	default:
		s, ok := v.(string)
		if !ok {
			return fmt.Sprint(v), nil
		}
		return s, nil
	}
}

// Count renders an exact count, capped so a wide filter cannot scan everything.
func Count(f Filter, cap int) (string, []any, error) {
	where, args, err := Where(f)
	if err != nil {
		return "", nil, err
	}
	sql := fmt.Sprintf(
		"SELECT count() FROM (SELECT id FROM traffic WHERE %s LIMIT %d)", where, cap)
	return sql, args, nil
}

func renderGroup(g Group) (string, []any, error) {
	joiner := " AND "
	if strings.EqualFold(g.Op, "or") {
		joiner = " OR "
	}
	var (
		parts []string
		args  []any
	)
	for _, c := range g.Conditions {
		clause, condArgs, err := renderCondition(c)
		if err != nil {
			return "", nil, err
		}
		parts = append(parts, clause)
		args = append(args, condArgs...)
	}
	for _, sub := range g.Groups {
		clause, subArgs, err := renderGroup(sub)
		if err != nil {
			return "", nil, err
		}
		if clause == "" {
			continue
		}
		parts = append(parts, clause)
		args = append(args, subArgs...)
	}
	if len(parts) == 0 {
		return "", nil, nil
	}
	clause := "(" + strings.Join(parts, joiner) + ")"
	if g.Not {
		clause = "NOT " + clause
	}
	return clause, args, nil
}

func renderCondition(c Condition) (string, []any, error) {
	if err := c.validate(); err != nil {
		return "", nil, err
	}
	col := columns[c.Field]

	switch col.kind {
	case kMap:
		return renderMap(col.name, c)
	case kArrUInt32, kArrString:
		return renderArray(col.name, c)
	case kIP:
		return renderIP(col.name, c)
	case kBool:
		return fmt.Sprintf("%s = ?", col.name), []any{boolToUint8(c.Value)}, nil
	}

	switch c.Op {
	case OpEq:
		return fmt.Sprintf("%s = ?", col.name), []any{c.Value}, nil
	case OpNe:
		return fmt.Sprintf("%s != ?", col.name), []any{c.Value}, nil
	case OpLt:
		return fmt.Sprintf("%s < ?", col.name), []any{c.Value}, nil
	case OpLte:
		return fmt.Sprintf("%s <= ?", col.name), []any{c.Value}, nil
	case OpGt:
		return fmt.Sprintf("%s > ?", col.name), []any{c.Value}, nil
	case OpGte:
		return fmt.Sprintf("%s >= ?", col.name), []any{c.Value}, nil
	case OpIn:
		return fmt.Sprintf("%s IN (?)", col.name), []any{c.Value}, nil
	case OpContains:
		return fmt.Sprintf("positionCaseInsensitive(%s, ?) > 0", col.name), []any{c.Value}, nil
	case OpPrefix:
		return fmt.Sprintf("startsWith(%s, ?)", col.name), []any{c.Value}, nil
	case OpSuffix:
		return fmt.Sprintf("endsWith(%s, ?)", col.name), []any{c.Value}, nil
	case OpRegex:
		return fmt.Sprintf("match(%s, ?)", col.name), []any{c.Value}, nil
	case OpExists:
		return fmt.Sprintf("%s != ''", col.name), nil, nil
	}
	return "", nil, fmt.Errorf("query: unhandled operator %q", c.Op)
}

func renderMap(name string, c Condition) (string, []any, error) {
	switch c.Op {
	case OpExists:
		return fmt.Sprintf("mapContains(%s, ?)", name), []any{strings.ToLower(c.Key)}, nil
	case OpEq:
		return fmt.Sprintf("%s[?] = ?", name), []any{strings.ToLower(c.Key), c.Value}, nil
	case OpContains:
		return fmt.Sprintf("positionCaseInsensitive(%s[?], ?) > 0", name),
			[]any{strings.ToLower(c.Key), c.Value}, nil
	}
	return "", nil, fmt.Errorf("query: unhandled map operator %q", c.Op)
}

func renderArray(name string, c Condition) (string, []any, error) {
	switch c.Op {
	case OpHas:
		return fmt.Sprintf("has(%s, ?)", name), []any{c.Value}, nil
	case OpIn:
		return fmt.Sprintf("hasAny(%s, ?)", name), []any{c.Value}, nil
	}
	return "", nil, fmt.Errorf("query: unhandled array operator %q", c.Op)
}

func renderIP(name string, c Condition) (string, []any, error) {
	switch c.Op {
	case OpEq:
		return fmt.Sprintf("%s = toIPv6(?)", name), []any{c.Value}, nil
	case OpNe:
		return fmt.Sprintf("%s != toIPv6(?)", name), []any{c.Value}, nil
	case OpIn:
		return fmt.Sprintf("%s IN (SELECT toIPv6(arrayJoin(?)))", name), []any{c.Value}, nil
	case OpCIDR:
		prefix, err := normalizeCIDR(toStringValue(c.Value))
		if err != nil {
			return "", nil, err
		}
		return fmt.Sprintf("isIPAddressInRange(IPv6NumToString(%s), ?)", name), []any{prefix}, nil
	}
	return "", nil, fmt.Errorf("query: unhandled ip operator %q", c.Op)
}

// normalizeCIDR renders a prefix in the IPv6 form the stored column uses, so an
// IPv4 prefix still matches addresses held as IPv4-mapped IPv6.
func normalizeCIDR(value string) (string, error) {
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		return "", fmt.Errorf("query: invalid CIDR %q: %w", value, err)
	}
	if prefix.Addr().Is4() {
		return netip.PrefixFrom(netip.AddrFrom16(prefix.Addr().As16()), prefix.Bits()+96).String(), nil
	}
	return prefix.String(), nil
}

func toStringValue(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprint(v)
}

func boolToUint8(v any) uint8 {
	switch t := v.(type) {
	case bool:
		if t {
			return 1
		}
	case float64:
		if t != 0 {
			return 1
		}
	case string:
		if t == "true" || t == "1" {
			return 1
		}
	}
	return 0
}
