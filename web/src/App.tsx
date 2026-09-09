import { NavLink, Navigate, Route, Routes } from 'react-router-dom'
import { useAuth } from './hooks/useAuth'
import { useTheme } from './hooks/useTheme'
import { Apps } from './routes/Apps'
import { Dashboard } from './routes/Dashboard'
import { IPProfileRoute } from './routes/IPProfile'
import { Login } from './routes/Login'
import { Settings } from './routes/Settings'
import { Traffic } from './routes/Traffic'
import { Tuning } from './routes/Tuning'

export default function App() {
  const { user, loading, atLeast } = useAuth()
  const [theme, toggleTheme] = useTheme()

  if (loading) return <div className="login-page muted">Loading…</div>
  if (!user) return <Login />

  return (
    <div className="shell">
      <nav className="rail">
        <div className="rail-brand">
          proxy-waf
          <span>detection only</span>
        </div>
        <div className="rail-nav">
          <NavLink className="rail-link" to="/">
            Traffic
          </NavLink>
          <NavLink className="rail-link" to="/dashboard">
            Dashboard
          </NavLink>
          <NavLink className="rail-link" to="/tuning">
            Rule tuning
          </NavLink>
          {atLeast('admin') && (
            <>
              <NavLink className="rail-link" to="/apps">
                Applications
              </NavLink>
              <NavLink className="rail-link" to="/settings">
                Settings
              </NavLink>
            </>
          )}
        </div>
        <div className="rail-foot">
          <span className="mono">{user.email}</span>
          <span className="muted">{user.role}</span>
          <div className="row">
            <button className="btn btn-sm" onClick={toggleTheme}>
              {theme === 'dark' ? 'Light' : 'Dark'}
            </button>
            <SignOut />
          </div>
        </div>
      </nav>

      <main className="main">
        <Routes>
          <Route path="/" element={<Traffic />} />
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="/tuning" element={<Tuning />} />
          <Route path="/ip/:ip" element={<IPProfileRoute />} />
          {atLeast('admin') && <Route path="/apps" element={<Apps />} />}
          {atLeast('admin') && <Route path="/settings" element={<Settings />} />}
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </main>
    </div>
  )
}

function SignOut() {
  const { signOut } = useAuth()
  return (
    <button className="btn btn-sm" onClick={() => signOut()}>
      Sign out
    </button>
  )
}
