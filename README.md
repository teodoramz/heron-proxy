# Heron Proxy

A persistent MITM proxy and WAF traffic analyser.

It terminates TLS for your applications, evaluates every request against the
OWASP Core Rule Set, records the transaction, and forwards it to an upstream on
any reachable host. Detection comes first: you read what the rules would have
done before deciding whether to enforce it.

> A heron stands in the current, watches everything pass, and strikes only when
> it has decided.

```
                    ┌──────────────────────────────────────┐
  client ──TLS──▶   │ proxy                                │  ──▶ upstream app
                    │  peek ClientHello → JA3/JA4          │      (any host)
                    │  certificate: uploaded, or minted    │
                    │  Coraza + CRS · detect or enforce    │
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

- **Records every request** — method, path, query, all headers, and the body up
  to a configurable cap. Response status, headers and size are kept; response
  bodies are never read.
- **Works before you prepare anything** — an application with no certificate is
  served one minted by the proxy's own authority, carrying the name the client
  asked for.
- **Detects, then optionally enforces** — OWASP CRS 4 through
  [Coraza](https://coraza.io). Per application: record what would have happened,
  or reject at the threshold. The enforcement rule is the same score the
  simulator reports.
- **Attributes traffic honestly** — the true TCP peer and any claimed
  `X-Forwarded-For` are both stored, and the claimed value is believed only from
  a configured trusted proxy.
- **Fingerprints clients** — JA3 and JA4 from the raw ClientHello, so a scanner
  rotating addresses is still one actor.
- **Loses nothing** — events are appended to an on-disk write-ahead log before
  being acknowledged. `SIGKILL` the proxy under load and every event still ships
  after restart.
- **Answers questions fast** — ClickHouse with keyset pagination, so page 10,000
  costs what page 1 costs.

## Quickstart

Requires Docker with Compose v2.

```bash
cp deploy/compose/.env.example deploy/compose/.env
$EDITOR deploy/compose/.env     # every value needs changing
make up
```

The UI is on <http://localhost:8081>. Sign in with the `ADMIN_USERNAME` and
`ADMIN_PASSWORD` you set; that account is created on first start only.

Then, in the UI:

1. **Applications** — add an app: an identifier, the hostnames it answers on,
   and the upstream URL. It works immediately over TLS, using a minted
   certificate.
2. Point DNS for those hostnames at the proxy. Traffic appears under **Traffic**.
3. Optionally upload a real certificate, and install the proxy's authority
   (**Applications → Certificate authority**) wherever you want no warnings.

`ENCRYPTION_KEY` must be exactly 32 bytes. It encrypts certificate private keys
at rest, and losing it makes stored certificates unreadable.

## Enforcing

Nothing is blocked until you say so, per application.

1. Run in detection long enough to see normal traffic.
2. **Rule tuning** ranks the rules that fired. Open the requests one matched,
   decide whether it caught an attack or your own users, and exclude the ones
   that are wrong.
3. The threshold ladder shows what each threshold would have rejected over the
   last week. Read the requests it names.
4. When you trust a threshold, set the application's mode to **Reject**.

## Documentation

| Guide | Contents |
| --- | --- |
| [Configuration](docs/configuration.md) | Every environment variable and per-app policy |
| [Deployment](docs/deployment.md) | Compose, Kubernetes, TLS, sizing, backups |
| [Filters](docs/filters.md) | Every filterable field and operator |
| [Rule tuning](docs/tuning.md) | False positives, exclusions, enabling enforcement |

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
test/                 integration, load and lab traffic generators
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
docker run -d --name heron-pg -e POSTGRES_PASSWORD=test -e POSTGRES_DB=heron -p 55432:5432 postgres:16-alpine
docker run -d --name heron-ch -e CLICKHOUSE_DB=heron -e CLICKHOUSE_PASSWORD=test \
  -e CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT=1 -p 59000:9000 clickhouse/clickhouse-server:24.8-alpine
make test-all
```

`test/lab/` holds traffic generators for a local lab: `crawler.py` for visitor
traffic, `attacker.py` for eight campaigns of attack payloads. Both refuse any
target that is not the local lab.

## Roles

| | analyst | admin |
| --- | :--: | :--: |
| Browse, search and filter traffic | ✓ | ✓ |
| Request bodies, replay, verdicts, exclusions | ✓ | ✓ |
| Applications, certificates, users, alerts | | ✓ |

## Limitations

- Response bodies are never recorded. Use Replay to fetch a current response.
- WebSocket frames are not captured; the handshake and byte counts are.
- One proxy node. Scaling out needs the broker-backed sink the pipeline is
  structured for but does not yet ship.

## License

MIT
