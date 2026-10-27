import { useCallback, useEffect, useState } from 'react'
import { api } from '../api/client'
import type { App, CertificateAuthority, Certificate } from '../api/types'

const BLANK = {
  id: '',
  name: '',
  hostnames: '',
  upstream_url: '',
  trusted_cidrs: '',
  client_ip_header: 'X-Real-IP',
  root_redirect: '',
  retention_days: 90,
  preserve_host: false,
  http_only: false,
  upstream_tls_verify: true,
  paranoia_level: 1,
  threshold: 5,
  mode: 'detect',
  no_log: false,
}

/** An empty row, so the form always offers one to fill in. */
const BLANK_HEADER = { name: '', value: '' }

export function Apps() {
  const [apps, setApps] = useState<App[]>([])
  const [certs, setCerts] = useState<Certificate[]>([])
  const [ca, setCA] = useState<CertificateAuthority>()
  const [editing, setEditing] = useState('')
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')

  const reload = useCallback(() => {
    api.apps().then((r) => setApps(r.apps ?? [])).catch((e) => setError(e.message))
    api.certificates().then((r) => setCerts(r.certificates ?? [])).catch(() => setCerts([]))
    api.certificateAuthority().then(setCA).catch(() => setCA(undefined))
  }, [])

  useEffect(reload, [reload])

  return (
    <>
      <div className="page-head">
        <h1 className="page-title">Applications</h1>
      </div>
      <div className="page-body">
        {error && <p className="error-msg">{error}</p>}
        {notice && <p className="muted">{notice}</p>}

        <section className="panel">
          <div className="panel-head">
            <h2>Certificate authority</h2>
            {ca && <span className="muted mono">expires in {ca.expires_in_days} days</span>}
          </div>
          <div className="panel-body">
            <p className="hint" style={{ marginTop: 0 }}>
              Applications with no certificate of their own are served one signed here, minted for
              whatever name the client asked for. Install this certificate as trusted and those
              sites load without a warning; leave it uninstalled and browsers will warn, which is
              the honest result of a proxy reading the traffic.
            </p>
            {ca ? (
              <div className="row" style={{ gap: 10, flexWrap: 'wrap' }}>
                <a className="btn btn-sm" href="/api/ca.crt" download>
                  Download the certificate
                </a>
                <span className="muted mono" title={ca.fingerprint}>
                  {ca.fingerprint.slice(0, 32)}…
                </span>
                <span className="spacer" />
                <button
                  className="btn btn-sm btn-danger"
                  onClick={() => {
                    if (
                      !confirm(
                        'Replacing the authority means every client that trusted the old one will ' +
                          'warn until the new certificate is installed. Continue?',
                      )
                    )
                      return
                    api.regenerateCertificateAuthority().then(() => {
                      api.certificateAuthority().then(setCA)
                      setNotice('A new authority was generated. Install it wherever the old one was trusted.')
                    })
                  }}
                >
                  Replace
                </button>
              </div>
            ) : (
              <p className="muted">Not available.</p>
            )}
          </div>
        </section>

        <section className="panel">
          <div className="panel-head">
            <h2>Proxied applications</h2>
          </div>
          <div className="panel-body">
            {apps.length === 0 ? (
              <p className="muted">No applications yet. Add one below to start recording traffic.</p>
            ) : (
              <table className="data">
                <thead>
                  <tr>
                    <th>ID</th>
                    <th>Hostnames</th>
                    <th>Upstream</th>
                    <th>Served on</th>
                    <th className="num">Headers</th>
                    <th>Mode</th>
                    <th className="num">Paranoia</th>
                    <th className="num">Threshold</th>
                    <th className="num">Retention</th>
                    <th className="actions" />
                  </tr>
                </thead>
                <tbody>
                  {apps.map((a) => (
                    <tr key={a.id}>
                      <td title={a.id}>{a.id}</td>
                      <td className="clip" title={a.hostnames.join(', ')}>{a.hostnames.join(', ')}</td>
                      <td className="muted clip-wide" title={a.upstream_url}>{a.upstream_url}</td>
                      <td className="muted">{a.http_only ? 'http' : 'http + https'}</td>
                      <td
                        className="num muted"
                        title={(a.extra_headers ?? []).map((h) => h.name).join(', ') || 'none'}
                      >
                        {a.extra_headers?.length || '—'}
                      </td>
                      <td className={a.waf.mode === 'block' ? 'blocked-flag' : 'muted'}>
                        {a.waf.mode === 'block' ? 'enforcing' : 'detect only'}
                      </td>
                      <td className="num">{a.waf.paranoia_level}</td>
                      <td className="num">{a.waf.threshold}</td>
                      <td className={a.no_log ? 'muted' : 'num'}>
                        {a.no_log ? 'not recorded' : `${a.retention_days} d`}
                      </td>
                      <td className="actions nowrap">
                        <button className="btn btn-sm" onClick={() => setEditing(editing === a.id ? '' : a.id)}>
                          {editing === a.id ? 'Close' : 'Edit'}
                        </button>{' '}
                        <button
                          className="btn btn-sm btn-danger"
                          onClick={() => api.deleteApp(a.id).then(reload)}
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

        <div className="two-col">
        {editing ? (
          // Keyed, so switching rows remounts the form with that app's values
          // instead of keeping the previous one's.
          <AppForm
            key={editing}
            app={apps.find((a) => a.id === editing)}
            onSaved={(id) => {
              setEditing('')
              setNotice(`Saved ${id}. The proxy picks it up within a few seconds.`)
              reload()
            }}
            onCancel={() => setEditing('')}
          />
        ) : (
          <AppForm
            key="new"
            onSaved={(id) => {
              setNotice(`Saved ${id}. The proxy picks it up within a few seconds.`)
              reload()
            }}
          />
        )}

          <section className="panel">
            <div className="panel-head">
              <h2>Certificates</h2>
            </div>
            <div className="panel-body">
              {certs.length === 0 ? (
                <p className="muted">
                  None uploaded. Hosts without one are served a certificate signed by the authority
                  above, so they work either way; upload one here to serve the real thing.
                </p>
              ) : (
                <table className="data">
                  <thead>
                    <tr>
                      <th>Names</th>
                      <th>App</th>
                      <th className="num">Expires</th>
                      <th />
                    </tr>
                  </thead>
                  <tbody>
                    {certs.map((c) => (
                      <tr key={c.id}>
                        <td>{c.sni_names.join(', ')}</td>
                        <td className="muted">{c.app_id || '—'}</td>
                        <td className={`num ${c.expires_in_days < 14 ? 'status-4xx' : ''}`}>
                          {c.expires_in_days} d
                        </td>
                        <td className="num">
                          <button
                            className="btn btn-sm btn-danger"
                            onClick={() => api.deleteCertificate(c.id).then(reload)}
                          >
                            Delete
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
              <CertificateForm apps={apps} onSaved={reload} />
            </div>
          </section>
        </div>
      </div>
    </>
  )
}

function CertificateForm({ apps, onSaved }: { apps: App[]; onSaved: () => void }) {
  const [appId, setAppId] = useState('')
  const [cert, setCert] = useState('')
  const [key, setKey] = useState('')
  const [error, setError] = useState('')

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    setError('')
    try {
      await api.saveCertificate({ app_id: appId, cert_pem: cert, private_key_pem: key, is_default: false })
      setCert('')
      setKey('')
      onSaved()
    } catch (err) {
      setError((err as Error).message)
    }
  }

  return (
    <form onSubmit={submit} style={{ marginTop: 14 }}>
      <h3 style={{ fontSize: 13 }}>Add a certificate</h3>
      {error && <p className="error-msg">{error}</p>}
      <div className="field">
        <label htmlFor="cert-app">Application</label>
        <select id="cert-app" className="select" value={appId} onChange={(e) => setAppId(e.target.value)}>
          <option value="">Any (default certificate)</option>
          {apps.map((a) => (
            <option key={a.id} value={a.id}>
              {a.name}
            </option>
          ))}
        </select>
      </div>
      <div className="field">
        <label htmlFor="cert-pem">Certificate chain (PEM)</label>
        <textarea
          id="cert-pem"
          className="textarea"
          rows={4}
          value={cert}
          onChange={(e) => setCert(e.target.value)}
          placeholder="-----BEGIN CERTIFICATE-----"
          required
        />
      </div>
      <div className="field">
        <label htmlFor="key-pem">Private key (PEM)</label>
        <textarea
          id="key-pem"
          className="textarea"
          rows={4}
          value={key}
          onChange={(e) => setKey(e.target.value)}
          placeholder="-----BEGIN PRIVATE KEY-----"
          required
        />
      </div>
      <button className="btn" type="submit">
        Add certificate
      </button>
    </form>
  )
}

function Field({
  label,
  value,
  onChange,
  placeholder,
  required,
  hint,
  readOnly,
  type = 'text',
}: {
  label: string
  value: string
  onChange: (v: string) => void
  placeholder?: string
  required?: boolean
  hint?: string
  readOnly?: boolean
  type?: string
}) {
  const id = label.toLowerCase().replace(/[^a-z]+/g, '-')
  return (
    <div className="field">
      <label htmlFor={id}>{label}</label>
      <input
        id={id}
        className="input"
        type={type}
        value={value}
        placeholder={placeholder}
        required={required}
        readOnly={readOnly}
        onChange={(e) => onChange(e.target.value)}
      />
      {hint && <span className="hint">{hint}</span>}
    </div>
  )
}

function split(v: string): string[] {
  return v
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)
}

/**
 * AppForm adds an application or edits one in place. The identifier names the
 * row in storage, so it is fixed once the application exists.
 */
function AppForm({
  app,
  onSaved,
  onCancel,
}: {
  app?: App
  onSaved: (id: string) => void
  onCancel?: () => void
}) {
  const [form, setForm] = useState(() => toForm(app))
  const [headers, setHeaders] = useState(() =>
    app?.extra_headers?.length ? app.extra_headers.map((h) => ({ ...h })) : [{ ...BLANK_HEADER }],
  )
  const [error, setError] = useState('')

  async function save(e: React.FormEvent) {
    e.preventDefault()
    setError('')
    try {
      await api.saveApp({
        id: form.id,
        name: form.name || form.id,
        hostnames: split(form.hostnames),
        upstream_url: form.upstream_url,
        trusted_cidrs: split(form.trusted_cidrs),
        client_ip_header: form.client_ip_header,
        root_redirect: form.root_redirect,
        retention_days: Number(form.retention_days),
        preserve_host: form.preserve_host,
        http_only: form.http_only,
        upstream_tls_verify: form.upstream_tls_verify,
        extra_headers: headers.filter((h) => h.name.trim() !== '' || h.value !== ''),
        no_log: form.no_log,
        enabled: true,
        waf: {
          enabled: true,
          mode: form.mode as 'detect' | 'block',
          paranoia_level: Number(form.paranoia_level),
          threshold: Number(form.threshold),
        },
      } as Partial<App>, Boolean(app))
      if (!app) {
        setForm(toForm(undefined))
        setHeaders([{ ...BLANK_HEADER }])
      }
      onSaved(form.id)
    } catch (err) {
      setError((err as Error).message)
    }
  }

  return (
    <section className="panel">
      <div className="panel-head">
        <h2>{app ? `Edit ${app.id}` : 'Add an application'}</h2>
        {onCancel && (
          <button className="btn btn-sm" type="button" onClick={onCancel}>
            Cancel
          </button>
        )}
      </div>
      <form className="panel-body" onSubmit={save}>
        {error && <p className="error-msg">{error}</p>}
          <Field
            label="Identifier"
            value={form.id}
            onChange={(v) => setForm({ ...form, id: v })}
            required
            readOnly={Boolean(app)}
            hint={app ? 'The identifier names this application everywhere it is recorded, so it cannot be changed.' : undefined}
          />
          <Field label="Name" value={form.name} onChange={(v) => setForm({ ...form, name: v })} />
          <Field
            label="Hostnames (comma separated)"
            value={form.hostnames}
            onChange={(v) => setForm({ ...form, hostnames: v })}
            placeholder="app.example.com, *.app.example.com"
            required
          />
          <Field
            label="Upstream URL"
            value={form.upstream_url}
            onChange={(v) => setForm({ ...form, upstream_url: v })}
            placeholder="https://10.0.0.5:8443"
            required
          />
          <Field
            label="Trusted proxy ranges"
            value={form.trusted_cidrs}
            onChange={(v) => setForm({ ...form, trusted_cidrs: v })}
            placeholder="10.0.0.0/8"
          />
          <Field
            label="Client IP header"
            value={form.client_ip_header}
            onChange={(v) => setForm({ ...form, client_ip_header: v })}
          />
          <div className="row" style={{ gap: 12 }}>
            <Field
              label="Paranoia level"
              value={String(form.paranoia_level)}
              onChange={(v) => setForm({ ...form, paranoia_level: Number(v) })}
              type="number"
            />
            <Field
              label="Anomaly threshold"
              value={String(form.threshold)}
              onChange={(v) => setForm({ ...form, threshold: Number(v) })}
              type="number"
            />
            <Field
              label="Retention (days)"
              value={String(form.retention_days)}
              onChange={(v) => setForm({ ...form, retention_days: Number(v) })}
              type="number"
            />
          </div>
          <div className="field">
            <label htmlFor="mode">What to do with a request over the threshold</label>
            <select
              id="mode"
              className="select"
              value={form.mode}
              onChange={(e) => setForm({ ...form, mode: e.target.value })}
            >
              <option value="detect">Record it and forward it anyway</option>
              <option value="block">Reject it with 403</option>
            </select>
            <span className="why muted">
              Start by recording. Check on Rule tuning what enforcing would have cost before
              turning it on.
            </span>
          </div>

          <label className="row" style={{ gap: 6, marginBottom: 8 }}>
            <input
              type="checkbox"
              checked={form.preserve_host}
              onChange={(e) => setForm({ ...form, preserve_host: e.target.checked })}
            />
            Send the original Host header upstream
          </label>
          <label className="row" style={{ gap: 6, marginBottom: 8 }}>
            <input
              type="checkbox"
              checked={form.upstream_tls_verify}
              onChange={(e) => setForm({ ...form, upstream_tls_verify: e.target.checked })}
            />
            Verify the upstream TLS certificate
          </label>
          <label className="row" style={{ gap: 6, marginBottom: 4 }}>
            <input
              type="checkbox"
              checked={form.http_only}
              onChange={(e) => setForm({ ...form, http_only: e.target.checked })}
            />
            Serve this application over plain HTTP only
          </label>
          <span className="hint" style={{ display: 'block', marginBottom: 12 }}>
            No certificate is minted for its hostnames, and none is presented. A client
            reaching for HTTPS is refused rather than handed a certificate for a site that
            was never meant to have one.
          </span>
          <label className="row" style={{ gap: 6, marginBottom: 4 }}>
            <input
              type="checkbox"
              checked={form.no_log}
              onChange={(e) => setForm({ ...form, no_log: e.target.checked })}
            />
            Do not record this application's traffic
          </label>
          <span className="hint" style={{ display: 'block', marginBottom: 12 }}>
            Requests are still proxied and checked against the rules, and still rejected if
            enforcing, but nothing about them is written down: no event, no body.
          </span>
          <Field
            label="Redirect / to"
            value={form.root_redirect}
            onChange={(v) => setForm({ ...form, root_redirect: v })}
            placeholder="/geoserver/web/"
            hint="Leave empty to proxy the root normally. An application that lives under a path can send visitors straight there; the redirect is still inspected and recorded."
          />

          <div className="field" style={{ marginTop: 10 }}>
            <label>Extra request headers</label>
            {headers.map((h, i) => (
              <div className="row" style={{ gap: 6, marginBottom: 6 }} key={i}>
                <input
                  className="input"
                  style={{ flex: '0 0 200px' }}
                  placeholder="X-Api-Key"
                  value={h.name}
                  aria-label={`Header name ${i + 1}`}
                  onChange={(e) =>
                    setHeaders(headers.map((x, j) => (j === i ? { ...x, name: e.target.value } : x)))
                  }
                />
                <input
                  className="input"
                  style={{ flex: 1 }}
                  placeholder="value"
                  value={h.value}
                  aria-label={`Header value ${i + 1}`}
                  onChange={(e) =>
                    setHeaders(headers.map((x, j) => (j === i ? { ...x, value: e.target.value } : x)))
                  }
                />
                <button
                  type="button"
                  className="btn btn-sm"
                  aria-label={`Remove header ${i + 1}`}
                  onClick={() =>
                    setHeaders(headers.length === 1 ? [{ ...BLANK_HEADER }] : headers.filter((_, j) => j !== i))
                  }
                >
                  ×
                </button>
              </div>
            ))}
            <button
              type="button"
              className="btn btn-sm"
              onClick={() => setHeaders([...headers, { ...BLANK_HEADER }])}
            >
              Add another header
            </button>
            <span className="hint" style={{ display: 'block', marginTop: 6 }}>
              Sent to the upstream with every request, after the forwarding headers, so they
              win if the names clash. <code>Host</code> and the headers that frame the
              connection are refused. Values are hidden from analysts, since they are usually
              credentials.
            </span>
          </div>

          <button className="btn btn-primary" type="submit">
            Save application
          </button>
      </form>
    </section>
  )
}

/** toForm turns a stored application into the strings the form edits. */
function toForm(app?: App) {
  if (!app) return { ...BLANK }
  return {
    id: app.id,
    name: app.name,
    hostnames: (app.hostnames ?? []).join(', '),
    upstream_url: app.upstream_url,
    trusted_cidrs: (app.trusted_cidrs ?? []).join(', '),
    client_ip_header: app.client_ip_header || 'X-Real-IP',
    root_redirect: app.root_redirect ?? '',
    retention_days: app.retention_days,
    preserve_host: app.preserve_host,
    http_only: app.http_only,
    upstream_tls_verify: app.upstream_tls_verify,
    paranoia_level: app.waf?.paranoia_level ?? 1,
    threshold: app.waf?.threshold ?? 5,
    mode: app.waf?.mode ?? 'detect',
    no_log: app.no_log ?? false,
  }
}
