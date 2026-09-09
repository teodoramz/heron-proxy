import { useEffect, useState } from 'react'
import { useParams } from 'react-router-dom'
import { api, rangeParams, type IPProfile as Profile } from '../api/client'
import { count } from '../components/format'

export function IPProfileRoute() {
  const { ip = '' } = useParams()
  const [profile, setProfile] = useState<Profile>()
  const [error, setError] = useState('')

  useEffect(() => {
    const to = new Date()
    const from = new Date(to.getTime() - 7 * 24 * 60 * 60_000)
    api
      .ipProfile(ip, rangeParams(from, to))
      .then(setProfile)
      .catch((e) => setError(e.message))
  }, [ip])

  return (
    <>
      <div className="page-head">
        <h1 className="page-title mono">{ip}</h1>
        <span className="muted">last 7 days</span>
      </div>
      <div className="page-body">
        {error && <p className="error-msg">{error}</p>}
        {!profile && !error && <p className="muted">Loading…</p>}
        {profile && (
          <>
            <div className="stat-row">
              <Stat label="Requests" value={count(profile.stat.requests)} />
              <Stat label="Distinct paths" value={count(profile.stat.paths)} />
              <Stat label="Anomaly total" value={count(profile.stat.anomaly)} />
              <Stat label="Would block" value={count(profile.stat.would_block)} />
              <Stat label="Network" value={profile.stat.asn ? `AS${profile.stat.asn}` : '—'} />
              <Stat label="Country" value={profile.stat.country || '—'} />
            </div>

            <div className="two-col">
              <Panel title="Paths requested" rows={profile.top_paths.map((p) => [p.key, count(p.requests)])} />
              <Panel
                title="TLS fingerprints"
                rows={profile.fingerprints.map((f) => [f.key, count(f.requests)])}
              />
              <Panel
                title="Rules triggered"
                rows={profile.top_rules.map((r) => [`${r.rule_id} ${r.message ?? ''}`, count(r.hits)])}
              />
            </div>
          </>
        )}
      </div>
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
