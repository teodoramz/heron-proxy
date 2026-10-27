import { useEffect, useState } from 'react'
import { Link, useParams, useSearchParams } from 'react-router-dom'
import { api, rangeParams, type IPProfile as Profile } from '../api/client'
import type { TrafficEvent } from '../api/types'
import { DetailDrawer } from '../components/DetailDrawer'
import { count, duration, fullTime, statusClass } from '../components/format'
import { requestsLink } from '../components/sourceLinks'

const WINDOWS = [1, 7, 30, 90]
const RECENT = 50

export function IPProfileRoute() {
  const { ip = '' } = useParams()
  const [params, setParams] = useSearchParams()
  const days = Math.max(1, Number(params.get('days')) || 7)
  const [profile, setProfile] = useState<Profile>()
  const [recent, setRecent] = useState<TrafficEvent[]>()
  const [error, setError] = useState('')
  const [selected, setSelected] = useState<string>()

  useEffect(() => {
    const to = new Date()
    const from = new Date(to.getTime() - days * 24 * 60 * 60_000)
    setProfile(undefined)
    setRecent(undefined)
    setError('')
    api
      .ipProfile(ip, rangeParams(from, to))
      .then(setProfile)
      .catch((e) => setError(e.message))
    api
      .searchTraffic({
        from: from.toISOString(),
        to: to.toISOString(),
        root: { op: 'and', conditions: [{ field: 'client_ip', op: 'eq', value: ip }] },
        limit: RECENT,
        sort: 'ts',
        order: 'desc',
      })
      .then((page) => setRecent(page.events ?? []))
      .catch((e) => setError(e.message))
  }, [ip, days])

  const windows = WINDOWS.includes(days) ? WINDOWS : [...WINDOWS, days].sort((a, b) => a - b)

  return (
    <>
      <div className="page-head">
        <h1 className="page-title mono">{ip}</h1>
        {windows.map((d) => (
          <button
            key={d}
            type="button"
            className="btn btn-sm"
            aria-pressed={d === days}
            onClick={() => setParams({ days: String(d) })}
          >
            {d === 1 ? '24h' : `${d}d`}
          </button>
        ))}
        <span className="spacer" />
        <Link className="btn btn-sm" to={requestsLink(ip, days)}>
          Open in Traffic
        </Link>
      </div>
      <div className="page-body">
        {error && <p className="error-msg">{error}</p>}
        {!profile && !error && <p className="muted">Loading…</p>}
        {profile && (
          <>
            {profile.stat.requests === 0 && (
              <p className="muted">
                Nothing from this address in the last {days === 1 ? '24 hours' : `${days} days`}.
                Try a wider window.
              </p>
            )}
            <div className="stat-row">
              <Stat label="Requests" value={count(profile.stat.requests)} />
              <Stat label="Distinct paths" value={count(profile.stat.paths)} />
              <Stat label="Anomaly total" value={count(profile.stat.anomaly)} />
              <Stat label="Would block" value={count(profile.stat.would_block)} />
              <Stat label="Network" value={profile.stat.asn ? `AS${profile.stat.asn}` : '—'} />
              <Stat label="Country" value={profile.stat.country || '—'} />
            </div>

            <div className="two-col">
              <Panel title="Paths requested" rows={(profile.top_paths ?? []).map((p) => [p.key, count(p.requests)])} />
              <Panel
                title="TLS fingerprints"
                rows={(profile.fingerprints ?? []).map((f) => [f.key || '(none, plain HTTP)', count(f.requests)])}
              />
              <Panel
                title="Rules triggered"
                rows={(profile.top_rules ?? []).map((r) => [`${r.rule_id} ${r.message ?? ''}`, count(r.hits)])}
              />
            </div>
          </>
        )}

        {recent && recent.length > 0 && (
          <section className="panel">
            <div className="panel-head">
              <h2>Latest requests</h2>
              <span className="spacer" />
              {recent.length === RECENT && (
                <Link to={requestsLink(ip, days)}>See all in Traffic</Link>
              )}
            </div>
            <div className="panel-body">
              <table className="data">
                <thead>
                  <tr>
                    <th>Time</th>
                    <th>Method</th>
                    <th>Host</th>
                    <th>Path</th>
                    <th className="num">Status</th>
                    <th className="num">Score</th>
                    <th className="num">Took</th>
                  </tr>
                </thead>
                <tbody>
                  {recent.map((e) => (
                    <tr key={e.id} onClick={() => setSelected(e.id)} style={{ cursor: 'pointer' }}>
                      <td className="mono">{fullTime(e.ts)}</td>
                      <td>{e.method}</td>
                      <td className="clip">{e.host}</td>
                      <td className="clip-wide" title={e.path}>{e.path}</td>
                      <td className={`num ${statusClass(e.status)}`}>{e.status}</td>
                      <td className="num">{e.anomaly_score}</td>
                      <td className="num">{duration(e.duration_ms)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
        )}
      </div>
      {selected && <DetailDrawer id={selected} onClose={() => setSelected(undefined)} />}
    </>
  )
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className="stat">
      <dt>{label}</dt>
      <dd>{value}</dd>
    </div>
  )
}

function Panel({ title, rows }: { title: string; rows: string[][] }) {
  return (
    <section className="panel">
      <div className="panel-head">
        <h2>{title}</h2>
      </div>
      <div className="panel-body">
        {rows.length === 0 ? (
          <p className="muted">Nothing recorded.</p>
        ) : (
          <table className="data">
            <tbody>
              {rows.map((r, i) => (
                <tr key={i}>
                  <td>{r[0]}</td>
                  <td className="num">{r[1]}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </section>
  )
}
