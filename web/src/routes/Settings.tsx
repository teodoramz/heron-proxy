import { useCallback, useEffect, useState } from 'react'
import { api, type AuditEntry } from '../api/client'
import type { AlertRule, App, User } from '../api/types'

export function Settings() {
  const [users, setUsers] = useState<User[]>([])
  const [alerts, setAlerts] = useState<AlertRule[]>([])
  const [apps, setApps] = useState<App[]>([])
  const [audit, setAudit] = useState<AuditEntry[]>([])
  const [editing, setEditing] = useState('')
  const [error, setError] = useState('')

  const reload = useCallback(() => {
    api.users().then((r) => setUsers(r.users ?? [])).catch((e) => setError(e.message))
    api.alerts().then((r) => setAlerts(r.alerts ?? [])).catch(() => setAlerts([]))
    api.apps().then((r) => setApps(r.apps ?? [])).catch(() => setApps([]))
    api.audit().then((r) => setAudit(r.entries ?? [])).catch(() => setAudit([]))
  }, [])

  useEffect(reload, [reload])

  return (
    <>
      <div className="page-head">
        <h1 className="page-title">Settings</h1>
      </div>
      <div className="page-body">
        {error && <p className="error-msg">{error}</p>}

        <section className="panel">
          <div className="panel-head">
            <h2>People</h2>
          </div>
          <div className="panel-body">
            <table className="data">
              <thead>
                <tr>
                  <th>Username</th>
                  <th>Role</th>
                  <th>Last signed in</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {users.map((u) => (
                  <tr key={u.id}>
                    <td>{u.username}</td>
                    <td>
                      <select
                        className="select"
                        style={{ width: 110 }}
                        value={u.role}
                        onChange={(e) =>
                          api.updateUser(u.id, { role: e.target.value, enabled: u.enabled }).then(reload)
                        }
                        aria-label={`Role for ${u.username}`}
                      >
                        <option value="analyst">analyst</option>
                        <option value="admin">admin</option>
                      </select>
                    </td>
                    <td className="muted">
                      {u.last_login_at ? new Date(u.last_login_at).toLocaleString() : 'never'}
                    </td>
                    <td className="num">
                      <button className="btn btn-sm btn-danger" onClick={() => api.deleteUser(u.id).then(reload)}>
                        Remove
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            <NewUser apps={apps} onSaved={reload} />
          </div>
        </section>

        <section className="panel">
          <div className="panel-head">
            <h2>Alerts</h2>
          </div>
          <div className="panel-body">
            {alerts.length === 0 ? (
              <p className="muted">No alerts configured. Add one to get notified when a rule fires.</p>
            ) : (
              <table className="data">
                <thead>
                  <tr>
                    <th>Name</th>
                    <th>App</th>
                    <th>Channel</th>
                    <th>Message</th>
                    <th>Last fired</th>
                    <th className="actions" />
                  </tr>
                </thead>
                <tbody>
                  {alerts.map((a) => (
                    <tr key={a.id}>
                      <td title={a.name}>{a.name}</td>
                      <td className="muted">{a.app_id || 'all'}</td>
                      <td>{a.channel}</td>
                      <td className="clip" title={a.template || 'default wording'}>
                        {a.template ? 'custom' : 'default'}
                      </td>
                      <td className="muted">
                        {a.last_fired_at ? new Date(a.last_fired_at).toLocaleString() : 'never'}
                      </td>
                      <td className="actions nowrap">
                        <button className="btn btn-sm" onClick={() => setEditing(editing === a.id ? '' : a.id)}>
                          {editing === a.id ? 'Close' : 'Edit'}
                        </button>{' '}
                        <button className="btn btn-sm btn-danger" onClick={() => api.deleteAlert(a.id).then(reload)}>
                          Remove
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
            {editing ? (
              // Keyed so switching rules remounts the form: without it React
              // reuses the instance and keeps the previous rule's values.
              <AlertForm
                key={editing}
                apps={apps}
                rule={alerts.find((a) => a.id === editing)}
                onSaved={() => {
                  setEditing('')
                  reload()
                }}
                onCancel={() => setEditing('')}
              />
            ) : (
              <AlertForm key="new" apps={apps} onSaved={reload} />
            )}
          </div>
        </section>

        <section className="panel">
          <div className="panel-head">
            <h2>Recent changes</h2>
          </div>
          <div className="panel-body">
            {audit.length === 0 ? (
              <p className="muted">Nothing recorded yet.</p>
            ) : (
              <table className="data">
                <thead>
                  <tr>
                    <th>When</th>
                    <th>Action</th>
                    <th>Detail</th>
                  </tr>
                </thead>
                <tbody>
                  {audit.slice(0, 25).map((e) => (
                    <tr key={e.id}>
                      <td className="muted nowrap">{new Date(e.ts).toLocaleString()}</td>
                      <td>{e.action}</td>
                      <td className="muted">{JSON.stringify(e.detail)}</td>
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

function NewUser({ apps, onSaved }: { apps: App[]; onSaved: () => void }) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [role, setRole] = useState('analyst')
  const [scoped, setScoped] = useState<string[]>([])
  const [error, setError] = useState('')

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    setError('')
    try {
      await api.createUser({ username, password, role, apps: scoped })
      setUsername('')
      setPassword('')
      setScoped([])
      onSaved()
    } catch (err) {
      setError((err as Error).message)
    }
  }

  return (
    <form onSubmit={submit} style={{ marginTop: 14 }}>
      <h3 style={{ fontSize: 13 }}>Add a person</h3>
      {error && <p className="error-msg">{error}</p>}
      <div className="row" style={{ gap: 8, alignItems: 'flex-end', flexWrap: 'wrap' }}>
        <div className="field" style={{ marginBottom: 0 }}>
          <label htmlFor="new-username">Username</label>
          <input
            id="new-username"
            className="input"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            placeholder="letters, digits, . - _"
            autoCapitalize="none"
            spellCheck={false}
            required
          />
        </div>
        <div className="field" style={{ marginBottom: 0 }}>
          <label htmlFor="new-password">Password (12 characters or more)</label>
          <input
            id="new-password"
            className="input"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            minLength={12}
            required
          />
        </div>
        <div className="field" style={{ marginBottom: 0 }}>
          <label htmlFor="new-role">Role</label>
          <select id="new-role" className="select" value={role} onChange={(e) => setRole(e.target.value)}>
            <option value="analyst">analyst</option>
            <option value="admin">admin</option>
          </select>
        </div>
        <div className="field" style={{ marginBottom: 0 }}>
          <label htmlFor="new-scope">Limit to apps</label>
          <select
            id="new-scope"
            className="select"
            multiple
            size={3}
            value={scoped}
            onChange={(e) => setScoped(Array.from(e.target.selectedOptions, (o) => o.value))}
          >
            {apps.map((a) => (
              <option key={a.id} value={a.id}>
                {a.name}
              </option>
            ))}
          </select>
        </div>
        <button className="btn btn-primary" type="submit">
          Add person
        </button>
      </div>
    </form>
  )
}

/**
 * AlertForm creates a rule or edits one in place. The preview shows the exact
 * body that would be posted, rendered by the same code that sends it, so a
 * custom message can be checked before it goes anywhere.
 */
function AlertForm({
  apps,
  rule,
  onSaved,
  onCancel,
}: {
  apps: App[]
  rule?: AlertRule
  onSaved: () => void
  onCancel?: () => void
}) {
  const [name, setName] = useState(rule?.name ?? '')
  const [appId, setAppId] = useState(rule?.app_id ?? '')
  const [channel, setChannel] = useState<AlertRule['channel']>(rule?.channel ?? 'webhook')
  const [url, setUrl] = useState(rule?.target_url ?? '')
  const [template, setTemplate] = useState(rule?.template ?? '')
  const [minAnomaly, setMinAnomaly] = useState(rule?.condition?.min_anomaly ?? 5)
  const [throttle, setThrottle] = useState(rule?.throttle_seconds ?? 300)
  const [enabled, setEnabled] = useState(rule?.enabled ?? true)
  const [error, setError] = useState('')
  const [preview, setPreview] = useState('')

  const draft = (): AlertRule => ({
    ...(rule ?? {}),
    id: rule?.id ?? '',
    name,
    app_id: appId,
    channel,
    target_url: url,
    template,
    throttle_seconds: throttle,
    enabled,
    condition: { min_anomaly: minAnomaly },
  })

  // Re-render the preview as the message is typed, but only once typing pauses.
  useEffect(() => {
    const timer = setTimeout(() => {
      api
        .previewAlert(draft())
        .then((r) => {
          setPreview(r.body)
          setError('')
        })
        .catch((e) => {
          setPreview('')
          setError((e as Error).message)
        })
    }, 400)
    return () => clearTimeout(timer)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [template, channel, appId, name])

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    setError('')
    try {
      await api.saveAlert(draft())
      if (!rule) {
        setName('')
        setUrl('')
        setTemplate('')
      }
      onSaved()
    } catch (err) {
      setError((err as Error).message)
    }
  }

  return (
    <form onSubmit={submit} style={{ marginTop: 14 }}>
      <h3 style={{ fontSize: 13 }}>{rule ? `Edit “${rule.name}”` : 'Add an alert'}</h3>
      {error && <p className="error-msg">{error}</p>}
      <div className="row" style={{ gap: 8, alignItems: 'flex-end', flexWrap: 'wrap' }}>
        <div className="field" style={{ marginBottom: 0 }}>
          <label htmlFor={`alert-name-${rule?.id ?? 'new'}`}>Name</label>
          <input
            id={`alert-name-${rule?.id ?? 'new'}`}
            className="input"
            value={name}
            onChange={(e) => setName(e.target.value)}
            required
          />
        </div>
        <div className="field" style={{ marginBottom: 0 }}>
          <label htmlFor={`alert-app-${rule?.id ?? 'new'}`}>App</label>
          <select
            id={`alert-app-${rule?.id ?? 'new'}`}
            className="select"
            value={appId}
            onChange={(e) => setAppId(e.target.value)}
          >
            <option value="">All apps</option>
            {apps.map((a) => (
              <option key={a.id} value={a.id}>
                {a.name}
              </option>
            ))}
          </select>
        </div>
        <div className="field" style={{ marginBottom: 0 }}>
          <label htmlFor={`alert-channel-${rule?.id ?? 'new'}`}>Channel</label>
          <select
            id={`alert-channel-${rule?.id ?? 'new'}`}
            className="select"
            value={channel}
            onChange={(e) => setChannel(e.target.value as AlertRule['channel'])}
          >
            <option value="webhook">webhook</option>
            <option value="mattermost">mattermost</option>
          </select>
        </div>
        <div className="field" style={{ marginBottom: 0, flex: '1 1 260px' }}>
          <label htmlFor={`alert-url-${rule?.id ?? 'new'}`}>Target URL</label>
          <input
            id={`alert-url-${rule?.id ?? 'new'}`}
            className="input"
            type="url"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            required
          />
        </div>
        <div className="field" style={{ marginBottom: 0 }}>
          <label htmlFor={`alert-anomaly-${rule?.id ?? 'new'}`}>Anomaly at least</label>
          <input
            id={`alert-anomaly-${rule?.id ?? 'new'}`}
            className="input"
            style={{ width: 80 }}
            type="number"
            value={minAnomaly}
            onChange={(e) => setMinAnomaly(Number(e.target.value))}
          />
        </div>
        <div className="field" style={{ marginBottom: 0 }}>
          <label htmlFor={`alert-throttle-${rule?.id ?? 'new'}`}>No more than every</label>
          <input
            id={`alert-throttle-${rule?.id ?? 'new'}`}
            className="input"
            style={{ width: 90 }}
            type="number"
            min={1}
            value={throttle}
            onChange={(e) => setThrottle(Number(e.target.value))}
            title="Seconds between notifications from this rule"
          />
        </div>
        <label className="row" style={{ gap: 6, marginBottom: 0 }}>
          <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
          Enabled
        </label>
        <button className="btn btn-primary" type="submit">
          {rule ? 'Save changes' : 'Add alert'}
        </button>
        {onCancel && (
          <button className="btn" type="button" onClick={onCancel}>
            Cancel
          </button>
        )}
      </div>

      <div className="two-col" style={{ marginTop: 10 }}>
        <div className="field" style={{ marginBottom: 0 }}>
          <label htmlFor={`alert-template-${rule?.id ?? 'new'}`}>Message (optional)</label>
          <textarea
            id={`alert-template-${rule?.id ?? 'new'}`}
            className="textarea"
            rows={7}
            placeholder={'{{.Method}} {{.Host}}{{.Path}} from {{.ClientIP}} scored {{.Anomaly}}'}
            value={template}
            onChange={(e) => setTemplate(e.target.value)}
            spellCheck={false}
          />
          <span className="hint">
            Leave empty for the default wording. Fields: <code>{'{{.Alert}}'}</code>{' '}
            <code>{'{{.AppID}}'}</code> <code>{'{{.EventID}}'}</code> <code>{'{{.ClientIP}}'}</code>{' '}
            <code>{'{{.Method}}'}</code> <code>{'{{.Host}}'}</code> <code>{'{{.Path}}'}</code>{' '}
            <code>{'{{.Status}}'}</code> <code>{'{{.Anomaly}}'}</code>{' '}
            <code>{'{{.WouldBlock}}'}</code> <code>{'{{.RuleIDs}}'}</code>. On mattermost this
            becomes the message text; on a plain webhook it is the whole request body, so you can
            write any JSON the receiver expects.
          </span>
        </div>
        <div className="field" style={{ marginBottom: 0 }}>
          <label>What gets posted</label>
          <pre className="code" style={{ margin: 0, minHeight: 130, maxHeight: 260 }}>
            {preview || '—'}
          </pre>
          <span className="hint">
            The body for a sample request that would match this rule, built by the same code that
            sends it.
          </span>
        </div>
      </div>
    </form>
  )
}
