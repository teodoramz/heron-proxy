# Load testing

`k6.js` drives a steady arrival rate through the proxy with a mix of benign and
attack traffic.

```
k6 run -e TARGET=https://app.example -e HOST=app.example -e RATE=500 k6.js
```

Two things make a run pass:

1. The latency thresholds in the script — p95 under 100 ms and p99 under 250 ms
   against a stub upstream.
2. `events_dropped` and `spool_dropped_bytes` at `http://<proxy>:9090/metrics`
   must both be zero. A non-zero value means the ingestion path could not keep
   up and traffic was recorded incompletely.

Point the app at a stub upstream that returns immediately, otherwise you are
measuring the upstream rather than the proxy.
