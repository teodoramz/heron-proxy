import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { api } from '../api/client'
import { count } from '../components/format'
import type { CrsRule, RuleFacets } from '../api/types'

const PAGE_SIZE = 50

/**
 * Rules is a reference view of the Core Rule Set the proxy has loaded: what a
 * rule ID means, what it looks for, and which requests have matched it.
 */
export function Rules() {
  const navigate = useNavigate()
  const [facets, setFacets] = useState<RuleFacets>()
  const [text, setText] = useState('')
  const [tag, setTag] = useState('')
  const [paranoia, setParanoia] = useState('')
  const [severity, setSeverity] = useState('')
  const [rules, setRules] = useState<CrsRule[]>([])
  const [matched, setMatched] = useState(0)
  const [offset, setOffset] = useState(0)
  const [expanded, setExpanded] = useState<number | null>(null)
  const [error, setError] = useState('')

  useEffect(() => {
    api.ruleFacets().then(setFacets).catch((e) => setError(e.message))
  }, [])

  // Reset to the first page whenever the search changes.
  useEffect(() => setOffset(0), [text, tag, paranoia, severity])

  useEffect(() => {
    const timer = setTimeout(() => {
      api
        .rules({ q: text, tag, paranoia, severity, limit: PAGE_SIZE, offset })
        .then((r) => {
          setRules(r.rules ?? [])
          setMatched(r.total)
        })
        .catch((e) => setError(e.message))
    }, 150) // debounce, so typing does not fire a request per keystroke
    return () => clearTimeout(timer)
  }, [text, tag, paranoia, severity, offset])

  return (
    <>
      <div className="page-head">
        <h1 className="page-title">Rules</h1>
        <span className="muted">
          {facets ? `${count(facets.total)} loaded` : ''}
        </span>
      </div>

      <div className="page-body">
        {error && <p className="error-msg">{error}</p>}

        <p className="lede">
          Every rule the proxy evaluates, from the OWASP Core Rule Set. Search by rule number, by
          what it detects, or by tag — then open the requests it has matched on your own traffic.
        </p>

        <section className="panel">
          <div className="panel-body">
            <div className="filter-row" style={{ marginBottom: 0 }}>
              <input
                className="input"
                style={{ maxWidth: 320 }}
                placeholder="Rule number, or words from the description"
                value={text}
                onChange={(e) => setText(e.target.value)}
                aria-label="Search rules"
              />
              <select
                className="select"
                style={{ width: 170 }}
                value={tag}
                onChange={(e) => setTag(e.target.value)}
                aria-label="Attack type"
              >
                <option value="">Any attack type</option>
                {facets?.tags.map((t) => (
                  <option key={t} value={t}>
                    {t.replace('attack-', '')}
                  </option>
                ))}
              </select>
              <select
                className="select"
                style={{ width: 150 }}
                value={paranoia}
                onChange={(e) => setParanoia(e.target.value)}
                aria-label="Paranoia level"
              >
                <option value="">Any paranoia level</option>
                {[1, 2, 3, 4].map((n) => (
                  <option key={n} value={n}>
                    Paranoia {n}
                  </option>
                ))}
              </select>
              <select
                className="select"
                style={{ width: 140 }}
                value={severity}
                onChange={(e) => setSeverity(e.target.value)}
                aria-label="Severity"
              >
                <option value="">Any severity</option>
                {facets?.severities.map((s) => (
                  <option key={s} value={s}>
                    {s.toLowerCase()}
                  </option>
                ))}
              </select>
              {(text || tag || paranoia || severity) && (
                <button
                  className="btn btn-sm"
                  onClick={() => {
                    setText('')
                    setTag('')
                    setParanoia('')
                    setSeverity('')
                  }}
                >
                  Clear
                </button>
              )}
              <span className="spacer" />
              <span className="muted mono">{count(matched)} rules</span>
            </div>
          </div>
        </section>

        <section className="panel">
          <div className="panel-body">
            {rules.length === 0 ? (
              <p className="muted">Nothing matches that search.</p>
            ) : (
              <table className="data">
                <thead>
                  <tr>
                    <th style={{ width: 80 }}>Rule</th>
                    <th>Detects</th>
                    <th style={{ width: 150 }}>Category</th>
                    <th style={{ width: 90 }}>Severity</th>
                    <th className="num" style={{ width: 70 }}>
                      Paranoia
                    </th>
                    <th style={{ width: 190 }} />
                  </tr>
                </thead>
                <tbody>
                  {rules.map((r) => (
                    <>
                      <tr key={r.id}>
                        <td>
                          <button
                            className="linkish"
                            onClick={() => setExpanded(expanded === r.id ? null : r.id)}
                          >
                            {r.id}
                          </button>
                        </td>
                        <td className="muted">{r.message || '—'}</td>
                        <td className="muted">{r.category}</td>
                        <td className="muted">{r.severity ? r.severity.toLowerCase() : '—'}</td>
                        <td className="num muted">{r.paranoia || '—'}</td>
                        <td className="num nowrap">
                          <button
                            className="btn btn-sm"
                            onClick={() => setExpanded(expanded === r.id ? null : r.id)}
                          >
                            {expanded === r.id ? 'Hide' : 'Definition'}
                          </button>{' '}
                          <button className="btn btn-sm" onClick={() => navigate(`/?rule=${r.id}`)}>
                            Matches
                          </button>
                        </td>
                      </tr>
                      {expanded === r.id && (
                        <tr key={`${r.id}-detail`}>
                          <td colSpan={6}>
                            <div className="row" style={{ flexWrap: 'wrap', gap: 6, marginBottom: 8 }}>
                              {r.tags.map((t) => (
                                <span className="tag" key={t}>
                                  {t}
                                </span>
                              ))}
                            </div>
                            <pre className="code">{r.source}</pre>
                            <p className="hint">Defined in {r.file}, phase {r.phase || '—'}.</p>
                          </td>
                        </tr>
                      )}
                    </>
                  ))}
                </tbody>
              </table>
            )}

            <div className="pager" style={{ borderTop: 0, paddingLeft: 0, paddingRight: 0 }}>
              <button
                className="btn btn-sm"
                onClick={() => setOffset((o) => Math.max(0, o - PAGE_SIZE))}
                disabled={offset === 0}
              >
                ← Previous
              </button>
              <button
                className="btn btn-sm"
                onClick={() => setOffset((o) => o + PAGE_SIZE)}
                disabled={offset + PAGE_SIZE >= matched}
              >
                Next →
              </button>
              <span className="muted mono">
                {matched === 0
                  ? 'nothing'
                  : `${(offset + 1).toLocaleString()}–${Math.min(offset + PAGE_SIZE, matched).toLocaleString()} of ${count(matched)}`}
              </span>
            </div>
          </div>
        </section>
      </div>
    </>
  )
}
