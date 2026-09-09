# proxy-waf

A persistent MITM proxy and WAF traffic analyzer. It terminates TLS for your
applications, evaluates every request against the OWASP Core Rule Set in
detection-only mode, records the transaction, and forwards it to an upstream on
any reachable host.

Nothing is ever blocked. The point is to see what a WAF *would* do before you
let it do anything.

```
                    ┌──────────────────────────────────────┐
  client ──TLS──▶   │ proxy                                │  ──▶ upstream app
                    │  peek ClientHello → JA3/JA4          │      (any host)
                    │  SNI certificate selection           │
                    │  Coraza + CRS (detection only)       │
                    │  capture · redact · inject X-Real-IP │
                    └──────┬────────────────────┬──────────┘
                           │                    │
                    disk spool (WAL)      live-tail fan-out
                           │                    │
                  ClickHouse (batched)          │
                           │                    │
                    ┌──────┴────────────────────┴──────────┐
                    │ api — REST + WebSocket               │
                    │  Postgres: apps, certs, users, rules │
                    └──────────────────┬───────────────────┘
                                       │
                                  web (React)
```

## What it does

- **Records every request** — method, path, query, all headers, and the request
  body up to a configurable cap. Response status, headers and size are kept;
  response bodies are never read.
- **Works before you prepare anything** — an application with no certificate is
  served one minted by the proxy's own authority, carrying the name the client
  asked for. Upload a real certificate whenever you have one.
- **Detects without blocking** — OWASP CRS 4 through [Coraza](https://coraza.io),
  always in `DetectionOnly`. Each event carries the rules that fired, the anomaly
  score, and whether CRS would have blocked it.
- **Attributes traffic honestly** — the true TCP peer and any claimed
  `X-Forwarded-For` are both stored, and the claimed value is believed only from
  a configured trusted proxy.
- **Fingerprints clients** — JA3 and JA4 from the raw ClientHello, so a scanner
  rotating IP addresses is still one actor.
- **Loses nothing** — events are appended to an on-disk write-ahead log before
  they are acknowledged. `SIGKILL` the proxy mid-load and every event is still
  shipped after restart.
- **Answers questions fast** — ClickHouse with keyset pagination, so page 10,000
  costs what page 1 costs.

## Quickstart

Requires Docker with Compose v2.

```bash
git clone <your-fork> proxy-waf && cd proxy-waf
cp deploy/compose/.env.example deploy/compose/.env
$EDITOR deploy/compose/.env     # every value needs changing
make up
```

The UI is on <http://localhost:8081>. Sign in with the `ADMIN_USERNAME` and
`ADMIN_PASSWORD` you set; that account is created on first start only.

Then, in the UI:

1. **Applications** — add an app: an identifier, the hostnames it answers on,
   and the upstream URL.
2. **Applications → Certificates** — upload the certificate and key for those
   hostnames. The proxy reloads within seconds; no restart.
3. Point DNS for those hostnames at the proxy. Traffic appears under **Traffic**.

`ENCRYPTION_KEY` must be exactly 32 bytes. It encrypts certificate private keys
at rest, and losing it makes stored certificates unreadable.

## Documentation

| Guide | Contents |
| --- | --- |
| [Configuration](docs/configuration.md) | Every environment variable and per-app policy |
| [Deployment](docs/deployment.md) | Compose, Kubernetes, TLS, sizing, backups |
| [Filters](docs/filters.md) | Every filterable field and operator |
| [Rule tuning](docs/tuning.md) | False positives, exclusions, and enabling blocking safely |
| [Design](docs/superpowers/specs/2026-09-08-proxy-waf-design.md) | Why it is built this way |

## Layout

```
cmd/proxy/            proxy entrypoint
cmd/api/              api entrypoint
internal/proxy/       tls peeking, ja3/ja4, routing, waf, capture, websocket
internal/pipeline/    event, redaction, spool, blob store, ClickHouse writer
internal/api/         query builder, reader, auth, handlers, alerts, live tail
internal/store/       Postgres configuration store and migrations
web/                  React UI
deploy/               compose and Kubernetes manifests
test/                 integration and load tests
rules/                custom SecLang rules appended to CRS
```

## Development

```bash
make build          # both binaries into bin/
make test           # unit tests, no databases needed
make lint           # gofmt and go vet
cd web && npm run dev
```

The full suite needs Postgres and ClickHouse:

```bash
docker run -d --name pw-pg -e POSTGRES_PASSWORD=test -e POSTGRES_DB=proxywaf -p 55432:5432 postgres:16-alpine
docker run -d --name pw-ch -e CLICKHOUSE_DB=proxywaf -e CLICKHOUSE_PASSWORD=test \
  -e CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT=1 -p 59000:9000 clickhouse/clickhouse-server:24.8-alpine
make test-all
```

## Limitations

- Response bodies are never recorded. Use Replay to fetch a current response.
- WebSocket frames are not captured; the handshake and byte counts are.
- One proxy node. Scaling out needs the broker-backed sink, which the pipeline
  is structured for but does not yet ship.
- Blocking mode is deliberately absent. Use the threshold simulator to decide
  what you would enable, then enforce it somewhere built to enforce.

## License

MIT
