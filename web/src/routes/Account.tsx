import { useState } from 'react'
import { api } from '../api/client'
import { useAuth } from '../hooks/useAuth'

/** Account is the one settings page every signed-in person can reach. */
export function Account() {
  const { user } = useAuth()
  const [current, setCurrent] = useState('')
  const [next, setNext] = useState('')
  const [confirm, setConfirm] = useState('')
  const [error, setError] = useState('')
  const [done, setDone] = useState(false)

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    setError('')
    setDone(false)
    if (next !== confirm) {
      setError('The two new passwords do not match.')
      return
    }
    try {
      await api.changeOwnPassword(current, next)
      setCurrent('')
      setNext('')
      setConfirm('')
      setDone(true)
    } catch (err) {
      setError((err as Error).message)
    }
  }

  return (
    <>
      <div className="page-head">
        <h1 className="page-title">Account</h1>
      </div>

      <div className="page-body">
        <section className="panel" style={{ maxWidth: 520 }}>
          <div className="panel-head">
            <h2>Signed in as {user?.username}</h2>
            <span className="muted mono">{user?.role}</span>
          </div>
          <div className="panel-body">
            <form onSubmit={submit}>
              <h3 style={{ fontSize: 13, marginTop: 0 }}>Change your password</h3>
              {error && <p className="error-msg">{error}</p>}
              {done && <p className="ok-msg">Your password has been changed.</p>}

              <div className="field">
                <label htmlFor="current-password">Current password</label>
                <input
                  id="current-password"
                  className="input"
                  type="password"
                  autoComplete="current-password"
                  value={current}
                  onChange={(e) => setCurrent(e.target.value)}
                  required
                />
              </div>
              <div className="field">
                <label htmlFor="new-password">New password</label>
                <input
                  id="new-password"
                  className="input"
                  type="password"
                  autoComplete="new-password"
                  minLength={12}
                  value={next}
                  onChange={(e) => setNext(e.target.value)}
                  required
                />
                <span className="hint">At least 12 characters.</span>
              </div>
              <div className="field">
                <label htmlFor="confirm-password">New password again</label>
                <input
                  id="confirm-password"
                  className="input"
                  type="password"
                  autoComplete="new-password"
                  value={confirm}
                  onChange={(e) => setConfirm(e.target.value)}
                  required
                />
              </div>

              <button className="btn btn-primary" type="submit">
                Change password
              </button>
              <span className="hint" style={{ display: 'block', marginTop: 8 }}>
                Sessions already signed in elsewhere stay valid until they expire. Sign out
                everywhere by having an administrator disable and re-enable the account.
              </span>
            </form>
          </div>
        </section>
      </div>
    </>
  )
}
