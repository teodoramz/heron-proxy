import { useCallback, useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { api, type VerdictSummary } from '../api/client'
import { count } from '../components/format'
import type { App, Exclusion, Filter, RuleStat, Simulation } from '../api/types'

const THRESHOLDS = [3, 5, 7, 10, 15, 20, 30]
const WINDOW_DAYS = 7

/**
 * Tuning turns recorded detections into a decision: which rules are wrong for
 * this application, and what threshold would be safe to enforce.
 */
export function Tuning() {
  const [apps, setApps] = useState<App[]>([])
  const [appId, setAppId] = useState('')
  const [rules, setRules] = useState<RuleStat[]>([])
  const [verdicts, setVerdicts] = useState<VerdictSummary[]>([])
  const [exclusions, setExclusions] = useState<Exclusion[]>([])
  const [ladder, setLadder] = useState<Simulation[]>([])
  const [chosen, setChosen] = useState(5)
  const [excluding, setExcluding] = useState<RuleStat | null>(null)
  const [error, setError] = useState('')

  const filter = useCallback((): Filter => {
    const to = new Date()
    return {
      from: new Date(to.getTime() - WINDOW_DAYS * 24 * 60 * 60_000).toISOString(),
      to: to.toISOString(),
      apps: appId ? [appId] : undefined,
      root: { op: 'and', conditions: [] },
    }
  }, [appId])

  const reload = useCallback(() => {
    setError('')
    const f = filter()
    Promise.all([
      api.topRules(f, 25),
      api.verdictSummaries(appId || undefined),
      api.exclusions(appId || undefined),
      Promise.all(THRESHOLDS.map((t) => api.simulate(f, t))),
    ])
      .then(([r, v, e, sims]) => {
        setRules(r.rules ?? [])
        setVerdicts(v.summaries ?? [])
        setExclusions(e.exclusions ?? [])
        setLadder(sims)
      })
      .catch((err) => setError(err.message))
  }, [appId, filter])

  useEffect(() => {
    api.apps().then((r) => setApps(r.apps ?? [])).catch(() => setApps([]))
  }, [])

  useEffect(reload, [reload])

  const verdictFor = (ruleId: number) => verdicts.find((v) => v.rule_id === ruleId)

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
          aria-label="Application"
        >
          <option value="">All applications</option>
          {apps.map((a) => (
            <option key={a.id} value={a.id}>
              {a.name}
            </option>
          ))}
        </select>
      </div>

      <div className="page-body">
        {error && <p className="error-msg">{error}</p>}

        <p className="lede">
          The Core Rule Set catches attacks and, at first, some of your own application. This page
          separates them. Work down the rules below: open the requests a rule matched, decide whether
          it caught an attack or your own users, and exclude the ones that are wrong. Then use the
          threshold ladder to see what enforcing would have cost.{' '}
          <strong>Nothing here blocks traffic</strong> — this proxy only ever records.
        </p>

        <ThresholdLadder
          ladder={ladder}
          chosen={chosen}
          onChoose={setChosen}
          days={WINDOW_DAYS}
        />

        <RuleTable
          rules={rules}
          appId={appId}
          verdictFor={verdictFor}
          onExclude={setExcluding}
        />

        <ExclusionList exclusions={exclusions} onChanged={reload} />
      </div>

      {excluding && (
        <ExclusionDialog
          rule={excluding}
          apps={apps}
          appId={appId}
          onClose={() => setExcluding(null)}
          onSaved={() => {
            setExcluding(null)
            reload()
          }}
        />
      )}
    </>
  )
}

function ThresholdLadder({
  ladder,
  chosen,
  onChoose,
  days,
}: {
  ladder: Simulation[]
  chosen: number
  onChoose: (t: number) => void
  days: number
}) {
  const worst = Math.max(...ladder.map((l) => l.would_block), 1)
  const selected = ladder.find((l) => l.threshold === chosen)

  return (
    <section className="panel">
      <div className="panel-head">
        <h2>What would enforcing cost?</h2>
        <span className="muted">last {days} days</span>
      </div>
      <div className="panel-body">
        {ladder.length === 0 ? (
          <p className="muted">Loading…</p>
        ) : (
          <>
            <div className="ladder">
              {ladder.map((l) => (
                <div
                  key={l.threshold}
                  className="ladder-row"
                  role="button"
                  tabIndex={0}
                  aria-selected={l.threshold === chosen}
                  onClick={() => onChoose(l.threshold)}
                  onKeyDown={(e) => (e.key === 'Enter' || e.key === ' ') && onChoose(l.threshold)}
                >
                  <span>score ≥ {l.threshold}</span>
                  <span className="block-flag">{count(l.would_block)}</span>
                  <span className="ladder-bar">
                    <span style={{ width: `${(l.would_block / worst) * 100}%` }} />
                  </span>
                  <span className="cell-num muted">{l.percent.toFixed(2)}%</span>
                </div>
              ))}
            </div>
            <p className="hint">
              {selected ? (
                <>
                  At a threshold of <strong>{selected.threshold}</strong>, {count(selected.would_block)}{' '}
                  of {count(selected.total)} recorded requests would have been rejected. Open them and
                  read a sample: if any are your own users, that rule needs excluding before this
                  threshold is safe. A lower threshold catches more attacks and more of your own
                  traffic.
                </>
              ) : (
                'Pick a threshold to see what it would have rejected.'
              )}
            </p>
          </>
        )}
      </div>
    </section>
  )
}

function RuleTable({
  rules,
  appId,
  verdictFor,
  onExclude,
}: {
  rules: RuleStat[]
  appId: string
  verdictFor: (id: number) => VerdictSummary | undefined
  onExclude: (r: RuleStat) => void
}) {
  const navigate = useNavigate()

  return (
    <section className="panel">
      <div className="panel-head">
        <h2>Rules that fired, most frequent first</h2>
      </div>
      <div className="panel-body">
        {rules.length === 0 ? (
          <p className="muted">No rules fired in this window. Nothing to tune yet.</p>
        ) : (
          <>
            <table className="data">
              <thead>
                <tr>
                  <th>Rule</th>
                  <th>What it detects</th>
                  <th className="num">Requests</th>
                  <th className="num">Sources</th>
                  <th>Your verdicts</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {rules.map((r) => {
                  const v = verdictFor(r.rule_id)
                  return (
                    <tr key={r.rule_id}>
                      <td>{r.rule_id}</td>
                      <td className="muted">{r.message || '—'}</td>
                      <td className="num">{count(r.hits)}</td>
                      <td className="num">{count(r.clients)}</td>
                      <td>
                        {v ? (
                          <>
                            {v.false_positive > 0 && (
                              <span className="tag" title="Marked as your own traffic">
                                {v.false_positive} false
                              </span>
                            )}
                            {v.true_positive > 0 && (
                              <span className="tag" title="Marked as a real attack">
                                {v.true_positive} real
                              </span>
                            )}
                          </>
                        ) : (
                          <span className="muted">none yet</span>
                        )}
                      </td>
                      <td className="num nowrap">
                        <button
                          className="btn btn-sm"
                          onClick={() =>
                            navigate(`/?rule=${r.rule_id}${appId ? `&app=${appId}` : ''}`)
                          }
                          title="Open the requests this rule matched"
                        >
                          View requests
                        </button>{' '}
                        <button className="btn btn-sm" onClick={() => onExclude(r)}>
                          Exclude…
                        </button>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
            <p className="hint">
              A rule matching many requests from many different sources is usually catching your own
              application. A rule matching a lot from one or two sources is usually catching an
              attacker. Open the requests before deciding.
            </p>
          </>
        )}
      </div>
    </section>
  )
}

type Scope = 'rule' | 'target' | 'path' | 'both'

function ExclusionDialog({
  rule,
  apps,
  appId,
  onClose,
  onSaved,
}: {
  rule: RuleStat
  apps: App[]
  appId: string
  onClose: () => void
  onSaved: () => void
}) {
  const [scope, setScope] = useState<Scope>('target')
  const [target, setTarget] = useState('ARGS:comment')
  const [path, setPath] = useState('/')
  const [reason, setReason] = useState('')
  const [app, setApp] = useState(appId || apps[0]?.id || '')
  const [preview, setPreview] = useState('')
  const [error, setError] = useState('')

  const body = {
    rule_id: rule.rule_id,
    target: scope === 'target' || scope === 'both' ? target : '',
    path: scope === 'path' || scope === 'both' ? path : '',
  }

  useEffect(() => {
    api
      .previewExclusion(body)
      .then((r) => setPreview(r.seclang))
      .catch(() => setPreview(''))
    // The preview depends only on the generated directive's inputs.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scope, target, path, rule.rule_id])

  async function save() {
    setError('')
    if (!app) {
      setError('Choose which application this exclusion applies to.')
      return
    }
    try {
      await api.createExclusion({ ...body, app_id: app, reason, enabled: true })
      onSaved()
    } catch (e) {
      setError((e as Error).message)
    }
  }

  return (
    <div className="dialog-scrim" onClick={onClose}>
      <div className="dialog" role="dialog" aria-label="Create exclusion" onClick={(e) => e.stopPropagation()}>
        <div className="dialog-head">
          <h2>Stop rule {rule.rule_id} matching</h2>
        </div>
        <div className="dialog-body">
          <p className="hint" style={{ marginTop: 0 }}>
            {rule.message || 'This rule'} — currently {count(rule.hits)} matches. Choose the narrowest
            scope that solves the problem: removing a rule entirely turns that detection off for every
            request to the application.
          </p>

          <div className="field">
            <label htmlFor="excl-app">Application</label>
            <select id="excl-app" className="select" value={app} onChange={(e) => setApp(e.target.value)}>
              <option value="">Choose one</option>
              {apps.map((a) => (
                <option key={a.id} value={a.id}>
                  {a.name}
                </option>
              ))}
            </select>
          </div>

          <div className="choice">
            <label>
              <input type="radio" checked={scope === 'target'} onChange={() => setScope('target')} />
              <span>
                Ignore one field
                <span className="why">The rule still runs, but stops looking at this parameter.</span>
              </span>
            </label>
            <label>
              <input type="radio" checked={scope === 'path'} onChange={() => setScope('path')} />
              <span>
                Turn the rule off under one path
                <span className="why">Everywhere else on the application it keeps working.</span>
              </span>
            </label>
            <label>
              <input type="radio" checked={scope === 'both'} onChange={() => setScope('both')} />
              <span>
                Ignore one field, under one path
                <span className="why">The narrowest option, and usually the right one.</span>
              </span>
            </label>
            <label>
              <input type="radio" checked={scope === 'rule'} onChange={() => setScope('rule')} />
              <span>
                Turn the rule off completely
                <span className="why">This detection stops for the whole application.</span>
              </span>
            </label>
          </div>

          {(scope === 'target' || scope === 'both') && (
            <div className="field">
              <label htmlFor="excl-target">Field to ignore</label>
              <input
                id="excl-target"
                className="input"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder="ARGS:comment"
              />
              <span className="why muted">
                For example <code>ARGS:comment</code> for a form field, <code>REQUEST_COOKIES:sid</code>{' '}
                for a cookie, or <code>REQUEST_HEADERS:Referer</code> for a header.
              </span>
            </div>
          )}

          {(scope === 'path' || scope === 'both') && (
            <div className="field">
              <label htmlFor="excl-path">Path prefix</label>
              <input
                id="excl-path"
                className="input"
                value={path}
                onChange={(e) => setPath(e.target.value)}
                placeholder="/admin/posts"
              />
            </div>
          )}

          <div className="field">
            <label htmlFor="excl-reason">Why (for whoever reads this later)</label>
            <input
              id="excl-reason"
              className="input"
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              placeholder="The rich text editor posts HTML here"
            />
          </div>

          <label className="field" style={{ marginBottom: 0 }}>
            <span>Rule this will add</span>
            <pre className="code" style={{ maxHeight: 120 }}>{preview || '…'}</pre>
          </label>

          {error && <p className="error-msg" style={{ marginTop: 10 }}>{error}</p>}
        </div>
        <div className="dialog-foot">
          <button className="btn" onClick={onClose}>
            Cancel
          </button>
          <button className="btn btn-primary" onClick={save}>
            Add exclusion
          </button>
        </div>
      </div>
    </div>
  )
}

function ExclusionList({
  exclusions,
  onChanged,
}: {
  exclusions: Exclusion[]
  onChanged: () => void
}) {
  return (
    <section className="panel">
      <div className="panel-head">
        <h2>Exclusions in effect</h2>
      </div>
      <div className="panel-body">
        {exclusions.length === 0 ? (
          <p className="muted">
            None yet. An exclusion becomes a rule the proxy loads within a few seconds, and it changes
            what gets detected from that point on.
          </p>
        ) : (
          <table className="data">
            <thead>
              <tr>
                <th>Application</th>
                <th>Rule</th>
                <th>Scope</th>
                <th>Why</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {exclusions.map((e) => (
                <tr key={e.id} style={{ opacity: e.enabled ? 1 : 0.5 }}>
                  <td>{e.app_id}</td>
                  <td>{e.rule_id}</td>
                  <td className="muted">
                    {e.target || e.path
                      ? [e.target && `field ${e.target}`, e.path && `under ${e.path}`]
                          .filter(Boolean)
                          .join(', ')
                      : 'entire rule'}
                  </td>
                  <td className="muted">{e.reason || '—'}</td>
                  <td className="num nowrap">
                    <button
                      className="btn btn-sm"
                      onClick={() => api.setExclusionEnabled(e.id, !e.enabled).then(onChanged)}
                    >
                      {e.enabled ? 'Disable' : 'Enable'}
                    </button>{' '}
                    <button
                      className="btn btn-sm btn-danger"
                      onClick={() => api.deleteExclusion(e.id).then(onChanged)}
                    >
                      Remove
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </section>
  )
}
