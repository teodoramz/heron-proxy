import { useEffect, useState } from 'react'
import { api } from '../api/client'
import { TrafficChart } from '../components/Chart'
import { count, duration } from '../components/format'
import type { Filter, GroupStat, IPStat, RuleStat, SeriesPoint, Summary } from '../api/types'

const WINDOWS = [
  { label: 'Last hour', minutes: 60, bucket: '1m' },
  { label: 'Last 6 hours', minutes: 360, bucket: '5m' },
  { label: 'Last day', minutes: 1440, bucket: '15m' },
  { label: 'Last week', minutes: 10080, bucket: '1h' },
]

export function Dashboard() {
  const [windowIndex, setWindowIndex] = useState(1)
  const [summary, setSummary] = useState<Summary>()
  const [points, setPoints] = useState<SeriesPoint[]>([])
  const [rules, setRules] = useState<RuleStat[]>([])
  const [ips, setIPs] = useState<IPStat[]>([])
  const [paths, setPaths] = useState<GroupStat[]>([])
  const [error, setError] = useState('')

  useEffect(() => {
    const w = WINDOWS[windowIndex]
    const to = new Date()
    const filter: Filter = {
      from: new Date(to.getTime() - w.minutes * 60_000).toISOString(),
      to: to.toISOString(),
      root: { op: 'and', conditions: [] },
    }
    setError('')
    Promise.all([
      api.summary(filter),
      api.series(filter, w.bucket),
      api.topRules(filter, 10),
      api.topIPs(filter, 10),
      api.topBy(filter, 'path', 10),
    ])
      .then(([s, series, r, i, p]) => {
        setSummary(s)
        setPoints(series.points ?? [])
        setRules(r.rules ?? [])
        setIPs(i.ips ?? [])
        setPaths(p.rows ?? [])
      })
      .catch((e) => setError(e.message))
  }, [windowIndex])

  return (
    <>
      <div className="page-head">
        <h1 className="page-title">Dashboard</h1>
        <span className="spacer" />
        <select
          className="select"
          style={{ width: 150 }}
          value={windowIndex}
          onChange={(e) => setWindowIndex(Number(e.target.value))}
          aria-label="Time window"
        >
          {WINDOWS.map((w, i) => (
            <option key={w.label} value={i}>
              {w.label}
            </option>
          ))}
        </select>
      </div>

      <div className="page-body">
        {error && <p className="error-msg">{error}</p>}

        <div className="stat-row">
          <Stat label="Requests" value={summary ? count(summary.requests) : '—'} />
          <Stat label="Sources" value={summary ? count(summary.clients) : '—'} />
          <Stat
            label="Suspicious"
            value={summary ? count(summary.would_block) : '—'}
            tone={summary && summary.would_block > 0 ? 'block' : undefined}
          />
          <Stat
            label="Rejected"
            value={summary ? count(summary.blocked) : '—'}
            tone={summary && summary.blocked > 0 ? 'blocked' : undefined}
          />
          <Stat label="4xx and 5xx" value={summary ? count(summary.errors) : '—'} />
          <Stat label="p95 latency" value={summary ? duration(Math.round(summary.p95_duration_ms)) : '—'} />
          <Stat label="p99 latency" value={summary ? duration(Math.round(summary.p99_duration_ms)) : '—'} />
        </div>

        <section className="panel">
          <div className="panel-head">
            <h2>Requests over time</h2>
          </div>
          <div className="panel-body">
            <TrafficChart points={points} />
          </div>
        </section>

        <div className="two-col">
          <section className="panel">
            <div className="panel-head">
              <h2>Rules triggered</h2>
            </div>
            <div className="panel-body">
              <RankTable
                head={['Rule', 'Message', 'Hits']}
                rows={rules.map((r) => [String(r.rule_id), r.message ?? '', count(r.hits)])}
                empty="No rules fired in this window."
              />
            </div>
          </section>

          <section className="panel">
            <div className="panel-head">
              <h2>Sources by anomaly</h2>
            </div>
            <div className="panel-body">
              <RankTable
                head={['Address', 'Requests', 'Anomaly']}
                rows={ips.map((i) => [i.client_ip, count(i.requests), count(i.anomaly)])}
                empty="No traffic in this window."
                link={(row) => `/ip/${encodeURIComponent(row[0])}`}
              />
            </div>
          </section>

          <section className="panel">
            <div className="panel-head">
              <h2>Busiest paths</h2>
            </div>
            <div className="panel-body">
              <RankTable
                head={['Path', 'Requests', 'Errors']}
                rows={paths.map((p) => [p.key, count(p.requests), count(p.errors)])}
                empty="No traffic in this window."
              />
            </div>
          </section>
        </div>
      </div>
    </>
  )
}

function Stat({ label, value, tone }: { label: string; value: string; tone?: 'block' | 'blocked' }) {
  const cls = tone === 'blocked' ? 'blocked-flag' : tone === 'block' ? 'block-flag' : ''
  return (
    <div className="stat">
      <dt>{label}</dt>
      <dd className={cls}>{value}</dd>
    </div>
  )
}

function RankTable({
  head,
  rows,
  empty,
  link,
}: {
  head: string[]
  rows: string[][]
  empty: string
  link?: (row: string[]) => string
}) {
  if (rows.length === 0) return <p className="muted">{empty}</p>
  return (
    <table className="data">
      <thead>
        <tr>
          {head.map((h, i) => (
            <th key={h} className={i > 0 ? 'num' : ''}>
              {h}
            </th>
          ))}
        </tr>
      </thead>
      <tbody>
        {rows.map((row, i) => (
          <tr key={i}>
            {row.map((cell, j) => (
              <td key={j} className={j > 0 ? 'num' : ''}>
                {j === 0 && link ? <a href={link(row)}>{cell}</a> : cell}
              </td>
            ))}
          </tr>
        ))}
      </tbody>
    </table>
  )
}
