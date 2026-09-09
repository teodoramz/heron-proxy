# Deployment

## Docker Compose

The intended single-host deployment.

```bash
cp deploy/compose/.env.example deploy/compose/.env
$EDITOR deploy/compose/.env
make up
```

Six services: `proxy`, `api`, `web`, `postgres`, `clickhouse`, and four named
volumes for the spool, blobs, and both databases.

| Port | Service | Exposure |
| --- | --- | --- |
| 80, 443 | proxy | Public. This is where your applications' traffic arrives. |
| 8081 | web | Private or behind your own TLS. The UI. |
| 9090 | proxy admin | Never public. Health, metrics, internal event stream. |
| 8080 | api | Internal only. Reached through `web`. |

The API is not published to the host: `web` proxies `/api` to it. Do not expose
port 9090 — it streams every recorded event.

### Secrets

| Variable | Consequence of loss | Consequence of change |
| --- | --- | --- |
| `ENCRYPTION_KEY` | Stored certificates become unreadable | Same. Re-upload every certificate. |
| `SESSION_KEY` | — | Everyone is signed out. |
| `INTERNAL_STREAM_TOKEN` | — | Live tail stops until both services agree. |

`ENCRYPTION_KEY` must be exactly 32 bytes. Back it up separately from the
database; together they are equivalent to holding the private keys.

## TLS

The proxy terminates TLS itself using certificates you upload in the UI, matched
by SNI with wildcard support and a default fallback. Certificate changes apply
within one poll interval, without a restart.

Put nothing that terminates TLS in front of it. If a load balancer must sit in
front, run it in TCP passthrough mode — otherwise the ClientHello never reaches
the proxy and JA3/JA4 fingerprinting is lost.

If a trusted proxy does sit in front, add its address range to the app's
`trusted_cidrs`, or every request will be attributed to the load balancer.

The UI is a separate concern: serve `web` behind your own TLS and set
`API_SECURE_COOKIES=true`.

## Kubernetes

```bash
$EDITOR deploy/k8s/01-secrets.yaml     # replace every value
kubectl apply -f deploy/k8s/
```

Two constraints are structural, not incidental:

- **The proxy runs one replica.** The spool is a `ReadWriteOnce` volume and the
  design is single-node. Scaling out requires the broker-backed sink.
- **`blobs` must be `ReadWriteMany`.** The proxy writes request bodies and the
  API reads them.

Application traffic reaches the `proxy` Service directly, as a `LoadBalancer`.
The Ingress covers only the UI, because the proxy terminates TLS itself.

## Sizing

Per recorded request, roughly 1–2 KB before compression and considerably less
after; ClickHouse typically compresses this traffic five- to tenfold. Bodies
dominate, so `body_cap_bytes` is the strongest lever on storage.

| Rate | Retention | ClickHouse volume |
| --- | --- | --- |
| 50 req/s | 90 days | ~40 GB |
| 500 req/s | 90 days | ~400 GB |
| 2000 req/s | 30 days | ~500 GB |

Give ClickHouse at least 4 GB of memory and real disk. The spool needs
`SPOOL_MAX_BYTES` of headroom — 10 GB by default, which buys hours of outage at
moderate rates.

Reduce cost by lowering `retention_days` per app, lowering `body_cap_bytes`, or
adding `skip_paths` for static assets.

## Operations

Health and counters:

```bash
curl -s http://proxy:9090/healthz
curl -s http://proxy:9090/metrics
```

`/metrics` reports `submitted`, `dropped`, `spooled`, `shipped`, `sink_errors`,
`spool_bytes` and `spool_dropped_bytes`.

Two numbers matter. **`dropped`** counts events discarded because the in-memory
queue was full — the proxy chose to serve traffic rather than record it. Raise
`PIPELINE_QUEUE_SIZE`, or set `PIPELINE_BLOCK_ON_FULL=true` if you would rather
slow requests than lose records. **`spool_dropped_bytes`** counts segments
discarded at the watermark, which means ClickHouse was unavailable for longer
than the spool could cover.

### Backups

- **Postgres** holds every configuration: apps, encrypted certificates, users,
  exclusions. Small, and the thing to back up. `pg_dump` on a schedule.
- **ClickHouse** holds traffic, which is TTL'd anyway. Back it up if the history
  is evidence; otherwise accept the loss.
- **Blobs** hold large request bodies. Without them, oversized bodies show as
  missing; everything else still reads.

### Upgrades

Both binaries apply migrations that are additive and idempotent. Start the API
first — it owns schema migration for both stores — then the proxy.

Restarting the proxy is safe under load: in-flight requests drain, and the spool
carries anything not yet shipped across the restart.
