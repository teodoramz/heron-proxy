import { useCallback, useEffect, useState } from 'react'
import { api } from '../api/client'
import type { App, Certificate } from '../api/types'

const BLANK = {
  id: '',
  name: '',
  hostnames: '',
  upstream_url: '',
  trusted_cidrs: '',
  client_ip_header: 'X-Real-IP',
  retention_days: 90,
  preserve_host: false,
  upstream_tls_verify: true,
  paranoia_level: 1,
  threshold: 5,
}

export function Apps() {
  const [apps, setApps] = useState<App[]>([])
  const [certs, setCerts] = useState<Certificate[]>([])
  const [form, setForm] = useState({ ...BLANK })
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')

  const reload = useCallback(() => {
    api.apps().then((r) => setApps(r.apps ?? [])).catch((e) => setError(e.message))
    api.certificates().then((r) => setCerts(r.certificates ?? [])).catch(() => setCerts([]))
  }, [])

  useEffect(reload, [reload])

  async function save(e: React.FormEvent) {
    e.preventDefault()
    setError('')
    setNotice('')
    try {
      await api.saveApp({
        id: form.id,
        name: form.name || form.id,
        hostnames: split(form.hostnames),
        upstream_url: form.upstream_url,
        trusted_cidrs: split(form.trusted_cidrs),
        client_ip_header: form.client_ip_header,
        retention_days: Number(form.retention_days),
        preserve_host: form.preserve_host,
        upstream_tls_verify: form.upstream_tls_verify,
        enabled: true,
        waf: { enabled: true, paranoia_level: Number(form.paranoia_level), threshold: Number(form.threshold) },
      } as Partial<App>)
      setNotice(`Saved ${form.id}. The proxy picks it up within a few seconds.`)
      setForm({ ...BLANK })
      reload()
    } catch (err) {
      setError((err as Error).message)
    }
  }

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
                    <th className="num">Paranoia</th>
                    <th className="num">Threshold</th>
                    <th className="num">Retention</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {apps.map((a) => (
                    <tr key={a.id}>
                      <td>{a.id}</td>
                      <td>{a.hostnames.join(', ')}</td>
                      <td className="muted">{a.upstream_url}</td>
                      <td className="num">{a.waf.paranoia_level}</td>
                      <td className="num">{a.waf.threshold}</td>
                      <td className="num">{a.retention_days} d</td>
                      <td className="num">
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
          <section className="panel">
            <div className="panel-head">
              <h2>Add an application</h2>
            </div>
            <form className="panel-body" onSubmit={save}>
              <Field label="Identifier" value={form.id} onChange={(v) => setForm({ ...form, id: v })} required />
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
              <label className="row" style={{ gap: 6, marginBottom: 8 }}>
                <input
                  type="checkbox"
                  checked={form.preserve_host}
                  onChange={(e) => setForm({ ...form, preserve_host: e.target.checked })}
                />
                Send the original Host header upstream
              </label>
              <label className="row" style={{ gap: 6, marginBottom: 12 }}>
                <input
                  type="checkbox"
                  checked={form.upstream_tls_verify}
                  onChange={(e) => setForm({ ...form, upstream_tls_verify: e.target.checked })}
                />
                Verify the upstream TLS certificate
              </label>
              <button className="btn btn-primary" type="submit">
                Save application
              </button>
            </form>
          </section>

          <section className="panel">
            <div className="panel-head">
              <h2>Certificates</h2>
            </div>
            <div className="panel-body">
              {certs.length === 0 ? (
                <p className="muted">
                  No certificates loaded. The proxy needs one per hostname it terminates TLS for.
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
  type = 'text',
}: {
  label: string
  value: string
  onChange: (v: string) => void
  placeholder?: string
  required?: boolean
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
        onChange={(e) => onChange(e.target.value)}
      />
    </div>
  )
}

function split(v: string): string[] {
  return v
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)
}
