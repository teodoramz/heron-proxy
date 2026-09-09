import { useEffect, useState } from 'react'
import { api, type ReplayResult } from '../api/client'
import type { EventDetail } from '../api/types'
import { useAuth } from '../hooks/useAuth'
import { bytes, duration, fullTime, statusClass } from './format'

type Tab = 'overview' | 'request' | 'response' | 'waf' | 'client' | 'replay'

const TABS: { id: Tab; label: string }[] = [
  { id: 'overview', label: 'Overview' },
  { id: 'request', label: 'Request' },
  { id: 'response', label: 'Response' },
  { id: 'waf', label: 'WAF' },
  { id: 'client', label: 'Client' },
  { id: 'replay', label: 'Replay' },
]

export function DetailDrawer({ id, onClose }: { id: string; onClose: () => void }) {
  const [detail, setDetail] = useState<EventDetail | null>(null)
  const [tab, setTab] = useState<Tab>('overview')
  const [error, setError] = useState('')

  useEffect(() => {
    setDetail(null)
    setError('')
    api.event(id).then(setDetail).catch((e) => setError(e.message))
  }, [id])

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && onClose()
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])

  return (
    <>
      <div className="drawer-scrim" onClick={onClose} />
      <aside className="drawer" role="dialog" aria-label="Request detail">
        <div className="drawer-head">
          <div>
            <div className="drawer-title">
              {detail ? `${detail.method} ${detail.host}${detail.path}` : 'Loading…'}
            </div>
            {detail && (
              <div className="muted mono" style={{ fontSize: 12, marginTop: 2 }}>
                {fullTime(detail.ts)} · {detail.id}
              </div>
            )}
          </div>
          <span className="spacer" />
          <button className="btn btn-sm" onClick={onClose}>
            Close
          </button>
        </div>

        <div className="tabs">
          {TABS.map((t) => (
            <button
              key={t.id}
              className="tab"
              aria-selected={tab === t.id}
              onClick={() => setTab(t.id)}
            >
              {t.label}
            </button>
          ))}
        </div>

        <div className="drawer-body">
          {error && <p className="error-msg">{error}</p>}
          {!detail && !error && <p className="muted">Loading…</p>}
          {detail && tab === 'overview' && <Overview detail={detail} />}
          {detail && tab === 'request' && <RequestTab detail={detail} />}
          {detail && tab === 'response' && <ResponseTab detail={detail} />}
          {detail && tab === 'waf' && <WafTab detail={detail} />}
          {detail && tab === 'client' && <ClientTab detail={detail} />}
          {detail && tab === 'replay' && <ReplayTab detail={detail} />}
        </div>
      </aside>
    </>
  )
}

function Overview({ detail }: { detail: EventDetail }) {
  return (
    <dl className="kv">
      <dt>App</dt>
      <dd>{detail.app_id || 'unrouted'}</dd>
      <dt>Status</dt>
      <dd className={statusClass(detail.status)}>{detail.status}</dd>
      <dt>Anomaly score</dt>
      <dd>
        {detail.anomaly_score}
        {detail.would_block && <span className="block-flag"> · suspicious</span>}
      </dd>
      <dt>Total time</dt>
      <dd>{duration(detail.duration_ms)}</dd>
      <dt>Upstream time</dt>
      <dd>{duration(detail.upstream_ms)}</dd>
      <dt>WAF time</dt>
      <dd>{duration(detail.waf_ms)}</dd>
      <dt>Request size</dt>
      <dd>{bytes(detail.req_body_size)}{detail.req_truncated && ' (truncated)'}</dd>
      <dt>Response size</dt>
      <dd>{bytes(detail.resp_size)}</dd>
      <dt>Upstream</dt>
      <dd>{detail.upstream || '—'}</dd>
      {detail.error && (
        <>
          <dt>Error</dt>
          <dd className="status-5xx">{detail.error}</dd>
        </>
      )}
    </dl>
  )
}

function RequestTab({ detail }: { detail: EventDetail }) {
  const [raw, setRaw] = useState('')
  return (
    <>
      <div className="row" style={{ marginBottom: 10 }}>
        <button
          className="btn btn-sm"
          onClick={() => api.exportEvent(detail.id, 'raw').then(setRaw)}
        >
          Show raw HTTP
        </button>
        <button
          className="btn btn-sm"
          onClick={() => api.exportEvent(detail.id, 'curl').then(setRaw)}
        >
          Copy as curl
        </button>
        <button
          className="btn btn-sm"
          onClick={() => api.exportEvent(detail.id, 'har').then(setRaw)}
        >
          Export HAR
        </button>
      </div>
      {raw && <pre className="code">{raw}</pre>}

      <h3 style={{ fontSize: 13 }}>Headers</h3>
      <Headers map={detail.req_headers} />

      <h3 style={{ fontSize: 13 }}>Body</h3>
      {detail.body ? (
        <pre className="code">{detail.body}</pre>
      ) : (
        <p className="muted">
          {detail.req_body_size > 0
            ? 'The body was not stored for this request.'
            : 'This request had no body.'}
        </p>
      )}
    </>
  )
}

function ResponseTab({ detail }: { detail: EventDetail }) {
  return (
    <>
      <dl className="kv" style={{ marginBottom: 14 }}>
        <dt>Status</dt>
        <dd className={statusClass(detail.status)}>{detail.status}</dd>
        <dt>Content type</dt>
        <dd>{detail.resp_content_type || '—'}</dd>
        <dt>Size</dt>
        <dd>{bytes(detail.resp_size)}</dd>
      </dl>
      <h3 style={{ fontSize: 13 }}>Headers</h3>
      <Headers map={detail.resp_headers} />
      <p className="muted" style={{ marginTop: 14 }}>
        Response bodies are never recorded. Use Replay to fetch the current response.
      </p>
    </>
  )
}

function WafTab({ detail }: { detail: EventDetail }) {
  const [note, setNote] = useState('')
  const [saved, setSaved] = useState('')
  const rules = detail.matched_rules ?? []

  async function mark(ruleId: number, verdict: string) {
    await api.verdict(detail.id, { app_id: detail.app_id, rule_id: ruleId, verdict, note })
    setSaved(`Recorded ${verdict.replace('_', ' ')} for rule ${ruleId}.`)
  }

  if (rules.length === 0) return <p className="muted">No rules matched this request.</p>

  return (
    <>
      <dl className="kv" style={{ marginBottom: 14 }}>
        <dt>Anomaly score</dt>
        <dd>{detail.anomaly_score}</dd>
        <dt>Highest severity</dt>
        <dd>{detail.rule_severity}</dd>
        <dt>Paranoia level</dt>
        <dd>{detail.paranoia_max}</dd>
        <dt>Assessment</dt>
        <dd className={detail.would_block ? 'block-flag' : ''}>
          {detail.would_block
            ? 'Suspicious — the score passed this app’s threshold'
            : 'Below the threshold'}
        </dd>
      </dl>

      <p className="hint" style={{ marginTop: 0 }}>
        Nothing was blocked; the request reached the application either way. A rule matching is
        evidence to read, not a conclusion — check what actually matched below before treating it as
        an attack.
      </p>

      <p className="hint" style={{ marginTop: 0 }}>
        Recording a verdict does not change detection or block anything. It labels this match so the
        tuning page can rank which rules are worth excluding, and so whoever looks next can see what
        you concluded.
      </p>

      <div className="field">
        <label htmlFor="verdict-note">Note (optional)</label>
        <input
          id="verdict-note"
          className="input"
          value={note}
          onChange={(e) => setNote(e.target.value)}
          placeholder="Why is this a false positive?"
        />
      </div>
      {saved && <p className="muted">{saved}</p>}

      {rules.map((r) => (
        <div className="rule-card" key={r.rule_id}>
          <h4>{r.rule_id}</h4>
          <p>{r.message || 'No message recorded.'}</p>
          <div className="row">
            <button
              className="btn btn-sm"
              onClick={() => mark(r.rule_id, 'false_positive')}
              title="This matched our own application, not an attack"
            >
              Our own traffic
            </button>
            <button
              className="btn btn-sm"
              onClick={() => mark(r.rule_id, 'true_positive')}
              title="This really was an attack"
            >
              Real attack
            </button>
          </div>
        </div>
      ))}

      {detail.rule_tags && detail.rule_tags.length > 0 && (
        <div className="row" style={{ flexWrap: 'wrap', gap: 6, marginTop: 10 }}>
          {detail.rule_tags.map((t) => (
            <span className="tag" key={t}>
              {t}
            </span>
          ))}
        </div>
      )}
    </>
  )
}

function ClientTab({ detail }: { detail: EventDetail }) {
  return (
    <dl className="kv">
      <dt>Source address</dt>
      <dd>{detail.client_ip}</dd>
      <dt>Claimed address</dt>
      <dd>
        {detail.client_ip_claimed && detail.client_ip_claimed !== '::'
          ? `${detail.client_ip_claimed} (not trusted)`
          : '—'}
      </dd>
      <dt>Country</dt>
      <dd>{detail.country || '—'}</dd>
      <dt>Network</dt>
      <dd>{detail.asn ? `AS${detail.asn} ${detail.as_org ?? ''}` : '—'}</dd>
      <dt>JA3</dt>
      <dd>{detail.ja3 || '—'}</dd>
      <dt>JA4</dt>
      <dd>{detail.ja4 || '—'}</dd>
      <dt>User agent</dt>
      <dd>{detail.user_agent || '—'}</dd>
      <dt>All requests</dt>
      <dd>
        <a href={`/ip/${encodeURIComponent(detail.client_ip)}`}>Open source profile</a>
      </dd>
    </dl>
  )
}

function ReplayTab({ detail }: { detail: EventDetail }) {
  const { atLeast } = useAuth()
  const [target, setTarget] = useState('')
  const [raw, setRaw] = useState('')
  const [result, setResult] = useState<ReplayResult | null>(null)
  const [error, setError] = useState('')
  const [sending, setSending] = useState(false)

  // Load the recorded request as text, which is what gets edited and sent.
  useEffect(() => {
    api
      .exportEvent(detail.id, 'raw')
      .then(setRaw)
      .catch(() => setRaw(`${detail.method} ${detail.path} HTTP/1.1\r\nHost: ${detail.host}\r\n\r\n`))
  }, [detail.id, detail.method, detail.path, detail.host])

  if (!atLeast('analyst')) return <p className="muted">Replay needs the analyst role.</p>

  async function send() {
    setSending(true)
    setError('')
    try {
      setResult(await api.replay(detail.id, { raw, target: target || undefined }))
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setSending(false)
    }
  }

  return (
    <>
      <p className="hint" style={{ marginTop: 0 }}>
        Edit the request and send it again. The request line, headers and body are all yours to
        change; Content-Length is recalculated on send, so you do not need to keep it correct.
      </p>

      <div className="field">
        <label htmlFor="replay-target">Send to</label>
        <input
          id="replay-target"
          className="input"
          placeholder={detail.upstream || "this app's upstream"}
          value={target}
          onChange={(e) => setTarget(e.target.value)}
        />
        <span className="why muted">
          Leave empty to use the app's own upstream. A different target needs the admin role, and
          private or link-local addresses are refused. The path comes from the request below, so put
          only the scheme, host and port here, such as <code>https://10.0.0.5:8443</code>.
        </span>
      </div>

      <div className="field">
        <label htmlFor="replay-raw">Request</label>
        <textarea
          id="replay-raw"
          className="textarea"
          rows={16}
          spellCheck={false}
          value={raw}
          onChange={(e) => setRaw(e.target.value)}
        />
        <span className="why muted">
          The Host header here is what the upstream sees. The source address is the proxy's, not the
          original client's.
        </span>
      </div>

      <div className="row">
        <button className="btn btn-primary" onClick={send} disabled={sending || !raw}>
          {sending ? 'Sending…' : 'Send request'}
        </button>
        <button
          className="btn"
          onClick={() => api.exportEvent(detail.id, 'raw').then(setRaw)}
          disabled={sending}
        >
          Reset to the recorded request
        </button>
      </div>

      {error && <p className="error-msg" style={{ marginTop: 10 }}>{error}</p>}

      {result && (
        <div style={{ marginTop: 16 }}>
          <h3 style={{ fontSize: 13, marginBottom: 6 }}>Response</h3>
          <dl className="kv">
            <dt>Sent to</dt>
            <dd>{result.url}</dd>
            <dt>Status</dt>
            <dd className={statusClass(result.status)}>
              {result.status}
              {result.diff.status_changed && (
                <span className="muted"> · recorded response was {result.diff.status_from}</span>
              )}
            </dd>
            <dt>Time</dt>
            <dd>{duration(result.duration_ms)}</dd>
            <dt>Size change</dt>
            <dd>
              {result.diff.size_delta >= 0 ? '+' : ''}
              {result.diff.size_delta} bytes against the recording
            </dd>
          </dl>

          <h4 style={{ fontSize: 12, margin: '12px 0 4px' }}>Headers</h4>
          <Headers map={result.headers} />

          <h4 style={{ fontSize: 12, margin: '12px 0 4px' }}>Body</h4>
          <pre className="code">
            {result.body || '(empty)'}
            {result.truncated && '\n… truncated'}
          </pre>
        </div>
      )}
    </>
  )
}

function Headers({ map }: { map?: Record<string, string> }) {
  const entries = Object.entries(map ?? {}).sort(([a], [b]) => a.localeCompare(b))
  if (entries.length === 0) return <p className="muted">None recorded.</p>
  return (
    <dl className="kv">
      {entries.map(([k, v]) => (
        <div key={k} style={{ display: 'contents' }}>
          <dt>{k}</dt>
          <dd>{v}</dd>
        </div>
      ))}
    </dl>
  )
}
