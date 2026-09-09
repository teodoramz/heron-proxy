import { useCallback, useEffect, useState } from 'react'
import { api, type VerdictSummary } from '../api/client'
import { count } from '../components/format'
import type { App, Exclusion, Filter, RuleStat, Simulation } from '../api/types'

/**
 * Tuning is where a false positive becomes a rule exclusion, and where you
 * check what a blocking threshold would have done before turning it on.
 */
export function Tuning() {
  const [apps, setApps] = useState<App[]>([])
  const [appId, setAppId] = useState('')
  const [rules, setRules] = useState<RuleStat[]>([])
  const [verdicts, setVerdicts] = useState<VerdictSummary[]>([])
  const [exclusions, setExclusions] = useState<Exclusion[]>([])
  const [threshold, setThreshold] = useState(5)
  const [sim, setSim] = useState<Simulation>()
  const [error, setError] = useState('')

  const filter = useCallback((): Filter => {
    const to = new Date()
    return {
      from: new Date(to.getTime() - 7 * 24 * 60 * 60_000).toISOString(),
      to: to.toISOString(),
      apps: appId ? [appId] : undefined,
      root: { op: 'and', conditions: [] },
    }
  }, [appId])

  const reload = useCallback(() => {
    setError('')
    Promise.all([
      api.topRules(filter(), 25),
      api.verdictSummaries(appId || undefined),
      api.exclusions(appId || undefined),
      api.simulate(filter(), threshold),
    ])
      .then(([r, v, e, s]) => {
        setRules(r.rules ?? [])
        setVerdicts(v.summaries ?? [])
        setExclusions(e.exclusions ?? [])
        setSim(s)
      })
      .catch((err) => setError(err.message))
  }, [appId, filter, threshold])

  useEffect(() => {
    api.apps().then((r) => setApps(r.apps ?? [])).catch(() => setApps([]))
  }, [])

  useEffect(reload, [reload])

  async function exclude(ruleId: number) {
    if (!appId) {
      setError('Choose an app before adding an exclusion.')
      return
    }
    await api.createExclusion({ app_id: appId, rule_id: ruleId, reason: 'Marked from tuning', enabled: true })
    reload()
  }

  const fpFor = (ruleId: number) => verdicts.find((v) => v.rule_id === ruleId)?.false_positive ?? 0

  return (
    <>
      <div className="page-head">
        <h1 className="page-title">Rule tuning</h1>
        <span className="spacer" />
        <select
          className="select"
          style={{ width: 180 }}
          value={appId}
          onChange={(e) => setAppId(e.target.value)}
          aria-label="App"
        >
          <option value="">All apps</option>
          {apps.map((a) => (
            <option key={a.id} value={a.id}>
              {a.name}
            </option>
          ))}
        </select>
      </div>

      <div className="page-body">
        {error && <p className="error-msg">{error}</p>}

        <section className="panel">
          <div className="panel-head">
            <h2>Threshold simulation</h2>
            <div className="row">
              <label htmlFor="threshold" className="muted">
                Anomaly threshold
              </label>
              <input
                id="threshold"
                className="input"
                style={{ width: 70 }}
                type="number"
                min={1}
                value={threshold}
                onChange={(e) => setThreshold(Number(e.target.value) || 1)}
              />
            </div>
          </div>
          <div className="panel-body">
            {sim ? (
              <p style={{ margin: 0 }}>
                Over the last 7 days,{' '}
                <strong className="block-flag mono">{count(sim.would_block)}</strong> of{' '}
                <span className="mono">{count(sim.total)}</span> requests would have been blocked at
                threshold {sim.threshold} — {sim.percent.toFixed(2)}% of traffic.
              </p>
            ) : (
              <p className="muted">Loading…</p>
            )}
          </div>
        </section>

        <section className="panel">
          <div className="panel-head">
            <h2>Rules by volume</h2>
          </div>
          <div className="panel-body">
            {rules.length === 0 ? (
              <p className="muted">No rules fired in the last 7 days.</p>
            ) : (
              <table className="data">
                <thead>
                  <tr>
                    <th>Rule</th>
                    <th>Message</th>
                    <th className="num">Hits</th>
                    <th className="num">Sources</th>
                    <th className="num">Marked false</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {rules.map((r) => (
                    <tr key={r.rule_id}>
                      <td>{r.rule_id}</td>
                      <td className="muted">{r.message}</td>
                      <td className="num">{count(r.hits)}</td>
                      <td className="num">{count(r.clients)}</td>
                      <td className="num">{fpFor(r.rule_id) || '—'}</td>
                      <td className="num">
                        <button className="btn btn-sm" onClick={() => exclude(r.rule_id)}>
                          Exclude
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </section>

        <section className="panel">
          <div className="panel-head">
            <h2>Active exclusions</h2>
          </div>
          <div className="panel-body">
            {exclusions.length === 0 ? (
              <p className="muted">
                No exclusions yet. Excluding a rule generates a SecLang directive the proxy loads on
                its next configuration poll.
              </p>
            ) : (
              <table className="data">
                <thead>
                  <tr>
                    <th>App</th>
                    <th>Rule</th>
                    <th>Directive</th>
                    <th>Reason</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {exclusions.map((e) => (
                    <tr key={e.id}>
                      <td>{e.app_id}</td>
                      <td>{e.rule_id}</td>
                      <td className="muted">{e.seclang}</td>
                      <td className="muted">{e.reason}</td>
                      <td className="num nowrap">
                        <button
                          className="btn btn-sm"
                          onClick={() => api.setExclusionEnabled(e.id, !e.enabled).then(reload)}
                        >
                          {e.enabled ? 'Disable' : 'Enable'}
                        </button>{' '}
                        <button
                          className="btn btn-sm btn-danger"
                          onClick={() => api.deleteExclusion(e.id).then(reload)}
                        >
                          Delete
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </section>
      </div>
    </>
  )
}
