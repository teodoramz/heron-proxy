# Configuration

Process settings come from the environment. Per-application policy lives in
Postgres and is edited in the UI.

## Environment

### Shared

| Variable | Default | Purpose |
| --- | --- | --- |
| `POSTGRES_DSN` | — | Required. Configuration store. |
| `CLICKHOUSE_DSN` | — | Required. Traffic store. |
| `ENCRYPTION_KEY` | — | Exactly 32 bytes. Encrypts certificate private keys at rest. |
| `INTERNAL_STREAM_TOKEN` | — | Shared secret for the proxy's internal event stream. |
| `BLOB_DIR` | `/data/blobs` | Content-addressed store for large request bodies. |

### Proxy

| Variable | Default | Purpose |
| --- | --- | --- |
| `PROXY_HTTP_ADDR` | `:80` | Plain HTTP listener. |
| `PROXY_HTTPS_ADDR` | `:443` | TLS listener. HTTP/2 and HTTP/1.1. |
| `PROXY_ADMIN_ADDR` | `:9090` | Health, metrics and the internal stream. Keep private. |
| `PROXY_RULES_DIR` | `/rules` | Extra `.conf` files appended to CRS. |
| `PROXY_POLL_INTERVAL` | `5s` | How often configuration changes are picked up. |
| `SPOOL_DIR` | `/data/spool` | Write-ahead log. |
| `GEOIP_CITY_DB` | — | MaxMind City database for country lookup. |
| `GEOIP_ASN_DB` | — | MaxMind ASN database for network lookup. |

### Ingestion

| Variable | Default | Purpose |
| --- | --- | --- |
| `PIPELINE_QUEUE_SIZE` | `50000` | In-memory queue between the request path and the spool. |
| `PIPELINE_BATCH_SIZE` | `5000` | Rows per ClickHouse insert. |
| `PIPELINE_BATCH_INTERVAL` | `500ms` | Maximum wait before flushing a partial batch. |
| `PIPELINE_BLOCK_ON_FULL` | `false` | `true` stalls requests instead of dropping events. |
| `SPOOL_SEGMENT_BYTES` | `64MiB` | Spool segment size. |
| `SPOOL_MAX_BYTES` | `10GiB` | Watermark. Beyond it the oldest segments are dropped. |

### API

| Variable | Default | Purpose |
| --- | --- | --- |
| `API_LISTEN_ADDR` | `:8080` | HTTP listener. |
| `API_SESSION_TTL` | `12h` | Session lifetime. |
| `API_SECURE_COOKIES` | `false` | Set `true` when the UI is served over HTTPS. |
| `API_ALLOWED_ORIGINS` | — | Comma-separated origins for cross-origin use, for both CORS and the live-tail websocket. Same-origin needs none. |
| `API_PROXY_STREAM_URL` | `ws://proxy:9090/internal/stream` | Where live tail reads from. |
| `SESSION_KEY` | random | Signs session cookies. Unset means everyone is signed out on restart. |
| `ADMIN_EMAIL`, `ADMIN_PASSWORD` | — | Creates the first administrator, on first start only. |

## Per-application policy

Set in the UI, stored in Postgres, applied by the proxy on its next poll.

### Routing

| Field | Purpose |
| --- | --- |
| `hostnames` | Exact names or one wildcard label, `*.example.com`. An exact match wins. |
| `upstream_url` | Absolute `http` or `https` URL. Any reachable host. |
| `upstream_tls_verify` | Verify the upstream certificate. Off for self-signed internal services. The scheme of `upstream_url` decides whether TLS is used at all. |
| `preserve_host` | Send the client's `Host` upstream instead of the upstream's own. |
| `client_ip_header` | Header carrying the real client address. Default `X-Real-IP`. |
| `trusted_cidrs` | Ranges whose `X-Forwarded-For` is believed. Empty means trust none. |
| `retention_days` | Overrides the 90-day default for this app's events. |

### Capture

| Field | Default | Purpose |
| --- | --- | --- |
| `enabled` | `true` | Turn off to record metadata only. |
| `body_cap_bytes` | 256 KiB | Beyond this the body is truncated, though the full body still reaches the upstream. |
| `inline_max_bytes` | 16 KiB | Above this the body goes to the blob store instead of ClickHouse. |
| `skip_paths` | — | Paths recorded without a body. Supports a trailing `*`. |
| `binary_types` | image, video, audio, font, octet-stream, pdf, zip | Stored as hash and size only. |

### Redaction

Applied in the proxy before anything reaches disk.

| Field | Default |
| --- | --- |
| `headers` | `authorization`, `cookie`, `set-cookie`, `proxy-authorization`, `x-api-key` |
| `fields` | `password`, `passwd`, `token`, `secret`, `api_key`, `apikey`, `card`, `ssn` |
| `mask` | `[REDACTED]` |

Field names match as substrings, so `api_key` also masks `user_api_key`. JSON and
form-encoded bodies are masked structurally; other content types are left alone.

### WAF

| Field | Default | Purpose |
| --- | --- | --- |
| `enabled` | `true` | Evaluate CRS for this app. |
| `paranoia_level` | `1` | 1–4. Higher catches more and produces more false positives. |
| `threshold` | `5` | Anomaly score at which an event is flagged `would_block`. |

The engine is always `DetectionOnly`. `threshold` changes only what is flagged.

## Custom rules

Any `.conf` file in `PROXY_RULES_DIR` is appended to CRS for every application.
Per-app exclusions are generated from the UI and stored in Postgres — do not put
them here.
