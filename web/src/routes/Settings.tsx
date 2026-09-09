import { useCallback, useEffect, useState } from 'react'
import { api, type AuditEntry } from '../api/client'
import type { AlertRule, App, User } from '../api/types'

export function Settings() {
  const [users, setUsers] = useState<User[]>([])
  const [alerts, setAlerts] = useState<AlertRule[]>([])
  const [apps, setApps] = useState<App[]>([])
  const [audit, setAudit] = useState<AuditEntry[]>([])
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
                  <th>Email</th>
                  <th>Role</th>
                  <th>Last signed in</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {users.map((u) => (
                  <tr key={u.id}>
                    <td>{u.email}</td>
                    <td>
                      <select
                        className="select"
                        style={{ width: 110 }}
                        value={u.role}
                        onChange={(e) =>
                          api.updateUser(u.id, { role: e.target.value, enabled: u.enabled }).then(reload)
                        }
                        aria-label={`Role for ${u.email}`}
                      >
                        <option value="viewer">viewer</option>
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
                    <th>Last fired</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {alerts.map((a) => (
                    <tr key={a.id}>
                      <td>{a.name}</td>
                      <td className="muted">{a.app_id || 'all'}</td>
                      <td>{a.channel}</td>
                      <td className="muted">
                        {a.last_fired_at ? new Date(a.last_fired_at).toLocaleString() : 'never'}
                      </td>
                      <td className="num">
                        <button className="btn btn-sm btn-danger" onClick={() => api.deleteAlert(a.id).then(reload)}>
                          Remove
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
            <NewAlert apps={apps} onSaved={reload} />
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
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [role, setRole] = useState('viewer')
  const [scoped, setScoped] = useState<string[]>([])
  const [error, setError] = useState('')

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    setError('')
    try {
      await api.createUser({ email, password, role, apps: scoped })
      setEmail('')
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
          <label htmlFor="new-email">Email</label>
          <input id="new-email" className="input" type="email" value={email} onChange={(e) => setEmail(e.target.value)} required />
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
            <option value="viewer">viewer</option>
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

function NewAlert({ apps, onSaved }: { apps: App[]; onSaved: () => void }) {
  const [name, setName] = useState('')
  const [appId, setAppId] = useState('')
  const [channel, setChannel] = useState<'webhook' | 'slack' | 'discord'>('webhook')
  const [url, setUrl] = useState('')
  const [minAnomaly, setMinAnomaly] = useState(5)
  const [error, setError] = useState('')

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    setError('')
    try {
      await api.saveAlert({
        name,
        app_id: appId,
        channel,
        target_url: url,
        throttle_seconds: 300,
        enabled: true,
        condition: { min_anomaly: minAnomaly },
      })
      setName('')
      setUrl('')
      onSaved()
    } catch (err) {
      setError((err as Error).message)
    }
  }

  return (
    <form onSubmit={submit} style={{ marginTop: 14 }}>
      <h3 style={{ fontSize: 13 }}>Add an alert</h3>
      {error && <p className="error-msg">{error}</p>}
      <div className="row" style={{ gap: 8, alignItems: 'flex-end', flexWrap: 'wrap' }}>
        <div className="field" style={{ marginBottom: 0 }}>
          <label htmlFor="alert-name">Name</label>
          <input id="alert-name" className="input" value={name} onChange={(e) => setName(e.target.value)} required />
        </div>
        <div className="field" style={{ marginBottom: 0 }}>
          <label htmlFor="alert-app">App</label>
          <select id="alert-app" className="select" value={appId} onChange={(e) => setAppId(e.target.value)}>
            <option value="">All apps</option>
            {apps.map((a) => (
              <option key={a.id} value={a.id}>
                {a.name}
              </option>
            ))}
          </select>
        </div>
        <div className="field" style={{ marginBottom: 0 }}>
          <label htmlFor="alert-channel">Channel</label>
          <select
            id="alert-channel"
            className="select"
            value={channel}
            onChange={(e) => setChannel(e.target.value as typeof channel)}
          >
            <option value="webhook">webhook</option>
            <option value="slack">slack</option>
            <option value="discord">discord</option>
          </select>
        </div>
        <div className="field" style={{ marginBottom: 0 }}>
          <label htmlFor="alert-url">Target URL</label>
          <input id="alert-url" className="input" type="url" value={url} onChange={(e) => setUrl(e.target.value)} required />
        </div>
        <div className="field" style={{ marginBottom: 0 }}>
          <label htmlFor="alert-anomaly">Anomaly at least</label>
          <input
            id="alert-anomaly"
            className="input"
            style={{ width: 80 }}
            type="number"
            value={minAnomaly}
            onChange={(e) => setMinAnomaly(Number(e.target.value))}
          />
        </div>
        <button className="btn btn-primary" type="submit">
          Add alert
        </button>
      </div>
    </form>
  )
}
