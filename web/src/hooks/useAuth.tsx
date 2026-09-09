import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react'
import type { ReactNode } from 'react'
import { api } from '../api/client'
import type { Role, User } from '../api/types'

interface AuthState {
  user: User | null
  apps: string[]
  loading: boolean
  signIn: (email: string, password: string) => Promise<void>
  signOut: () => Promise<void>
  atLeast: (role: Role) => boolean
}

const rank: Record<Role, number> = { viewer: 1, analyst: 2, admin: 3 }
const AuthContext = createContext<AuthState | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null)
  const [apps, setApps] = useState<string[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    api
      .me()
      .then((res) => {
        setUser(res.user)
        setApps(res.apps ?? [])
      })
      .catch(() => setUser(null))
      .finally(() => setLoading(false))
  }, [])

  const signIn = useCallback(async (email: string, password: string) => {
    const res = await api.login(email, password)
    setUser(res.user)
    const me = await api.me()
    setApps(me.apps ?? [])
  }, [])

  const signOut = useCallback(async () => {
    await api.logout()
    setUser(null)
    setApps([])
  }, [])

  const atLeast = useCallback(
    (role: Role) => (user ? rank[user.role] >= rank[role] : false),
    [user],
  )

  const value = useMemo(
    () => ({ user, apps, loading, signIn, signOut, atLeast }),
    [user, apps, loading, signIn, signOut, atLeast],
  )
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used inside AuthProvider')
  return ctx
}
