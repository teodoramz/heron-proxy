# proxy-waf — Design

> Written before the project was named. It was renamed to Heron Proxy;
> the module path is now `github.com/amzteodor/heron`.

Status: approved
Date: 2026-09-08

## 1. Overview

A persistent MITM proxy and WAF traffic analyzer. It terminates TLS for one or
more web applications, evaluates every request against the OWASP Core Rule Set
in detection-only mode, records the transaction, and forwards to an upstream
that may live on any reachable host.

A web UI browses the recorded traffic with keyset pagination, composable
filters, live tail, and request replay.

Non-goals for v1: blocking traffic, response body capture, WebSocket frame
capture, distributed deployment across multiple proxy nodes.

## 2. Architecture

```
                    ┌──────────────────────────────────────┐
  client ──TLS──▶   │ proxy (Go)                           │  ──▶ upstream app
                    │  peek ClientHello → JA3/JA4          │      (any host)
                    │  SNI cert select                     │
                    │  Coraza + CRS (DetectionOnly)        │
                    │  capture · redact · inject X-Real-IP │
                    └──────┬────────────────────┬──────────┘
                           │                    │
                    disk spool (fsync)    live-tail fan-out
                           │                    │
                  ClickHouse (batched)          │
                           │                    │
                    ┌──────┴────────────────────┴──────────┐
                    │ api (Go) — REST + WebSocket          │
                    │  Postgres: apps, certs, users, rules │
                    └──────────────────┬───────────────────┘
                                       │
                              web (React SPA)
```

| Container | Responsibility |
| --- | --- |
| `proxy` | TLS termination, WAF evaluation, capture, reverse proxying |
| `api` | Query API, config CRUD, auth, replay, alerts, live tail |
| `clickhouse` | Traffic events |
| `postgres` | Apps, certificates, users, filters, exclusions, alerts, audit |
| `web` | nginx serving the built SPA |

Volumes: `spool/` (durability WAL), `blobs/` (large request bodies),
`rules/` (CRS plus generated exclusions).

Two stores is deliberate. ClickHouse handles high-volume append-only analytics;
Postgres handles low-volume mutable configuration. Neither does the other's job
well.

## 3. Request path

1. Peeking listener reads the raw ClientHello, computes JA3/JA4, replays the
   bytes into `tls.Server`. Go's stdlib does not expose extension ordering, so
   the peek is required.
2. `GetCertificate` resolves SNI against an in-memory certificate map,
   hot-reloaded on config version change.
3. Route by `Host` to an app. Unknown hosts return 421.
4. Coraza phases 1–3 (request headers, request body, response headers). Phase 4
   is disabled — response bodies are never buffered. Disruptive actions are
   recorded as `would_block`, never enforced.
5. Request body is teed into a capped buffer (default 256 KB) while streaming to
   the upstream.
6. Headers injected: `X-Real-IP`, `X-Forwarded-For`, `X-Forwarded-Proto`,
   `X-Forwarded-Host`, `X-Request-Id` (the event UUID, for log correlation).
   Hop-by-hop headers are stripped.
7. Response is relayed with `io.Copy`. No buffering, no body inspection.
8. Event is redacted, then handed to the pipeline. The request path never
   touches a database.

### Client IP trust

The proxy records both the true TCP peer (`client_ip`) and any inbound
`X-Forwarded-For` value (`client_ip_claimed`). The claimed value is used for
attribution only when the peer is in the app's `trusted_cidrs` list, so a direct
client cannot spoof its own source address.

The outbound header name is configurable per app (default `X-Real-IP`).

## 4. Ingestion pipeline

```
event ──▶ bounded channel (50k) ──▶ spool writer ──▶ shipper ──▶ ClickHouse
                                    (append + fsync)   (batch 5k / 500ms)
```

- An event is durable once appended to the segmented, length-prefixed spool. The
  shipper advances a checkpoint after each successful insert, so `SIGKILL` under
  load loses nothing.
- If ClickHouse is unavailable the spool grows until `spool_max_bytes`
  (default 10 GB), then drops oldest segments and increments `events_dropped`,
  which raises an alert. A config flag switches this to blocking instead of
  dropping.
- ClickHouse writes use `async_insert` with batching.
- The sink is an interface. The default is spool→ClickHouse; a broker-backed sink
  (NATS/Kafka) can replace it without changes to the request path.

### Body storage

| Size | Location |
| --- | --- |
| ≤ 16 KB | inline in ClickHouse |
| > 16 KB, ≤ cap | SHA-256 content-addressed file in `blobs/` |
| > cap | truncated to cap, `req_truncated = 1`, true size retained |

Binary and media content types store hash and size only.

### Redaction

Applied in the proxy before the event reaches disk. Defaults mask the
`Authorization`, `Cookie`, and `Set-Cookie` headers, and body or query fields
matching `password|passwd|token|secret|api_key|card|ssn`. Configurable globally
and per app.

## 5. Data model

### ClickHouse `traffic`

`ENGINE = MergeTree`, `PARTITION BY toYYYYMMDD(ts)`,
`ORDER BY (app_id, ts, id)`, `TTL ts + INTERVAL 90 DAY` (per-app override).

| Group | Columns |
| --- | --- |
| Identity | `ts DateTime64(3)`, `id UUID`, `app_id LowCardinality(String)` |
| Client | `client_ip IPv6`, `client_ip_claimed IPv6`, `client_port UInt16`, `country LowCardinality(String)`, `asn UInt32`, `as_org String`, `ja3 String`, `ja4 String` |
| Request | `method`, `scheme`, `host`, `path`, `query`, `http_version`, `req_headers Map(String,String)`, `req_body_size UInt64`, `req_body_inline String`, `req_body_sha256 String`, `req_body_blob String`, `req_truncated UInt8`, `user_agent String` |
| Response | `status UInt16`, `resp_headers Map(String,String)`, `resp_size UInt64`, `resp_content_type LowCardinality(String)` |
| Timing | `duration_ms UInt32`, `upstream_ms UInt32`, `waf_ms UInt32` |
| WAF | `anomaly_score UInt16`, `rule_ids Array(UInt32)`, `rule_msgs Array(String)`, `rule_tags Array(LowCardinality(String))`, `rule_severity UInt8`, `paranoia_max UInt8`, `would_block UInt8` |
| Ops | `upstream String`, `error String`, `is_websocket UInt8` |

Skip indexes: bloom filter on `client_ip` and `rule_ids`; `tokenbf_v1` on
`path`, `user_agent`, and `req_body_inline` (body search); minmax on `status`.

Materialized views, so dashboards never scan raw rows:

| View | Key | Aggregates |
| --- | --- | --- |
| `traffic_stats_1m` | app, minute | count, status class counts, `quantileState(duration)`, `uniqState(client_ip)` |
| `rule_hits_1h` | app, rule_id, hour | count, `uniqState(client_ip)` |
| `ip_stats_1h` | app, client_ip, hour | count, distinct paths, anomaly sum, 4xx/5xx counts |

### Postgres

`apps`, `certificates`, `users`, `app_access`, `saved_filters`,
`rule_exclusions`, `fp_marks`, `event_annotations`, `alert_rules`, `audit_log`.

`apps` carries hostnames, upstream URL, TLS verification flag, host preservation,
trusted CIDRs, client IP header name, and the capture, redaction and WAF policy
as JSONB. Certificate private keys are encrypted at rest.

## 6. Pagination and filtering

Pagination is keyset on `(ts, id)` ordered descending. There is no `OFFSET`; page
10,000 costs what page 1 costs. The cursor is an opaque base64 of the last row's
sort key. Counts are exact when the filtered set is under 10,000 rows and rendered as
`10,000+` otherwise.

Filterable fields:

time range, app, method, status (exact / class / range), host, path
(contains / prefix / regex), query, header key and value, request body contains,
client IP (exact or CIDR), country, ASN, JA3, JA4, user agent, rule ID, rule tag,
severity, anomaly score, `would_block`, duration, response size, content type,
`is_websocket`, has body, truncated, bookmarked, false-positive marked.

Filters compose with AND/OR groups and NOT, serialize into the URL so any view is
a shareable link, and can be saved per user or shared.

Translation to SQL runs through a parameterized builder with an allowlist of
columns and operators. No user-supplied string is concatenated into a query.

## 7. Features

**Replay.** Load any captured request into an editor, modify method, URL, headers
or body, send it to the original upstream or an arbitrary target, and diff the
result against the recorded transaction. Every replay is written to the audit log.

**Rule tuning.** Each event lists the rules that matched, with ID, message,
severity, paranoia level, tags, and the matched data. Marking a match as a false
positive generates the corresponding `SecRuleRemoveById` or
`SecRuleUpdateTargetById` directive, which is stored, applied, and hot-reloaded
into the proxy.

**Threshold simulation.** For a given app, anomaly threshold and time range,
report how many recorded requests would have been blocked, with the sample set.
This is the evidence needed before enabling blocking mode.

**Live tail.** WebSocket stream of events with filters applied server-side.
Auto-pauses on scroll.

**Dashboards.** Requests per second, status distribution, latency p50/p95/p99,
top rules, top source IPs, top paths, `would_block` trend over time.

**Alerts.** Conditions on rule matches, anomaly thresholds, or request rate,
delivered to a webhook, Slack, or Discord, with per-rule throttling.

**IP intelligence.** MaxMind GeoIP and ASN enrichment, JA3/JA4 fingerprints, and
a per-IP profile page correlating every request, rule match, and fingerprint from
one source across the retention window.

## 8. API

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/api/traffic` | Keyset-paginated, filtered list |
| GET | `/api/traffic/:id` | Full event including body blob |
| GET | `/api/traffic/:id/export` | Raw HTTP, HAR, or curl |
| WS | `/api/stream` | Live tail with filters |
| POST | `/api/replay` | Replay with overrides, returns response and diff |
| GET | `/api/stats/*` | Dashboard aggregates |
| GET | `/api/ip/:ip` | IP profile |
| GET | `/api/simulate` | Would-block counts for a threshold |
| CRUD | `/api/apps`, `/api/certificates` | App and certificate management |
| CRUD | `/api/users`, `/api/filters`, `/api/alerts`, `/api/exclusions` | Configuration |
| POST | `/api/auth/login`, `/api/auth/logout` | Session |

## 9. Authentication

Three roles:

| Role | Capability |
| --- | --- |
| `admin` | Everything, including users, apps, and certificates |
| `analyst` | View traffic, replay, triage false positives, manage filters |
| `viewer` | Read-only; request bodies hidden unless granted |

Visibility is scoped per app via `app_access`. Argon2id password hashing,
HttpOnly session cookies, CSRF tokens on mutations, and an audit log entry for
every configuration change and every replay.

## 10. Frontend

React, TypeScript, Vite, Tailwind.

- **Traffic** — virtualized table, dense rows, colored by status and anomaly
  score; sticky filter bar; live-tail toggle.
- **Detail drawer** — Overview, Request (pretty / raw / hex), Response headers,
  WAF (matched rules, expandable, with a mark-false-positive action), Timing,
  Client (geo, ASN, fingerprints, other requests from this IP), Replay.
- **Dashboard** — the aggregates in §7.
- **Apps** — CRUD, certificate upload with expiry warnings, per-app policy.
- **Tuning** — rule hits by volume, false-positive queue, generated exclusions.
- **Settings** — users, roles, alerts, retention, redaction defaults.

## 11. Deployment

`docker compose` on a single host is the primary target. Kubernetes manifests
(Deployment, Service, Ingress, PVC) are produced from the same images.

The proxy listens on `:80` and `:443`, supports HTTP/2 and HTTP/1.1 inbound, and
speaks HTTP/1.1 to upstreams. WebSocket upgrades are evaluated at the handshake,
then relayed bidirectionally and recorded as a single event with byte counts and
duration on close.

## 12. Testing

| Level | Coverage |
| --- | --- |
| Unit | Redaction, XFF trust, cursor encode/decode, filter→SQL builder including injection cases, spool round-trip |
| Integration | Compose stack with a stub upstream; known SQLi, XSS and traversal payloads must produce the expected CRS rule IDs in ClickHouse |
| Durability | `SIGKILL` the proxy under load; assert zero event loss after restart |
| Load | k6 at target rate; assert p99 added latency budget and zero dropped events |

## 13. Repository layout

```
cmd/proxy/            proxy entrypoint
cmd/api/              api entrypoint
internal/proxy/       tls, ja3, router, waf, capture, websocket
internal/pipeline/    event, redact, spool, sink, clickhouse, blob
internal/api/         handlers, query, auth, replay, alerts, stats
internal/config/      loading, validation, hot reload
migrations/           postgres/, clickhouse/
rules/                CRS and generated exclusions
web/                  React SPA
deploy/               compose/, k8s/
docs/
```

## 14. Build order

| Phase | Deliverable |
| --- | --- |
| 1 | Proxy: TLS, routing, Coraza, capture, spool, ClickHouse writer |
| 2 | API and SPA: traffic table, filters, keyset pagination, detail drawer |
| 3 | Auth and roles, app and certificate CRUD, hot reload |
| 4 | Live tail, dashboards, alerts |
| 5 | Replay, false-positive triage, exclusion generation, simulation |
| 6 | GeoIP, ASN, JA3/JA4 enrichment, IP profile |
| 7 | Kubernetes manifests, load and durability test suite |

## 15. Known limitations

- Response bodies are never captured. Use replay to obtain a response.
- WebSocket frames are not captured; only the handshake and byte counts.
- JA3/JA4 requires the ClientHello peeking listener.
- Single proxy node. Multi-node requires the broker-backed sink.
