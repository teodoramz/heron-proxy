// Load profile for the proxy. Run against a stack whose app routes to a stub
// upstream, then compare the reported drop counter against zero.
//
//   k6 run -e TARGET=https://app.example -e HOST=app.example test/load/k6.js
//
// The proxy's own counters are at http://<proxy>:9090/metrics; events_dropped
// and spool_dropped_bytes must both stay at zero for a clean run.

import http from 'k6/http'
import { check } from 'k6'
import { Trend } from 'k6/metrics'

const TARGET = __ENV.TARGET || 'http://localhost:8080'
const HOST = __ENV.HOST || 'app.example'
const RATE = Number(__ENV.RATE || 500)

const latency = new Trend('proxy_latency', true)

export const options = {
  scenarios: {
    steady: {
      executor: 'constant-arrival-rate',
      rate: RATE,
      timeUnit: '1s',
      duration: __ENV.DURATION || '60s',
      preAllocatedVUs: Math.max(50, RATE / 5),
      maxVUs: Math.max(200, RATE),
    },
  },
  thresholds: {
    // The proxy's own overhead budget, measured end to end against a stub upstream.
    'http_req_duration{expected_response:true}': ['p(99)<250', 'p(95)<100'],
    http_req_failed: ['rate<0.01'],
  },
  insecureSkipTLSVerify: true,
}

// A realistic mix: mostly benign traffic with a minority of attack payloads, so
// the WAF evaluation path is exercised without dominating the profile.
const PATHS = [
  { path: '/', weight: 40 },
  { path: '/api/v1/items?page=2', weight: 25 },
  { path: '/api/v1/users/42', weight: 15 },
  { path: '/static/app.js', weight: 10 },
  { path: "/search?q=1'%20OR%20'1'='1", weight: 5 },
  { path: '/q?s=%3Cscript%3Ealert(1)%3C/script%3E', weight: 3 },
  { path: '/file?name=../../../../etc/passwd', weight: 2 },
]

const TABLE = PATHS.flatMap((p) => Array(p.weight).fill(p.path))

export default function () {
  const path = TABLE[Math.floor(Math.random() * TABLE.length)]
  const res = http.get(`${TARGET}${path}`, {
    headers: { Host: HOST, 'User-Agent': 'k6-load/1.0' },
    tags: { name: 'proxied' },
  })
  latency.add(res.timings.duration)
  check(res, {
    'proxy responded': (r) => r.status !== 0,
    'not blocked': (r) => r.status !== 403,
  })
}

export function handleSummary(data) {
  const p99 = data.metrics.proxy_latency?.values['p(99)'] ?? 0
  const p95 = data.metrics.proxy_latency?.values['p(95)'] ?? 0
  return {
    stdout: `\nproxy latency  p95 ${p95.toFixed(1)} ms  p99 ${p99.toFixed(1)} ms\n` +
      `check the proxy's /metrics: events_dropped and spool_dropped_bytes must be 0\n\n`,
  }
}
