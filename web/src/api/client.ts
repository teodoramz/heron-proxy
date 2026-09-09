import type {
  AlertRule, App, Certificate, EventDetail, Exclusion, FieldSchema, Filter,
  GroupStat, IPStat, Page, RuleStat, SavedFilter, SeriesPoint, Simulation,
  RuleFacets, CrsRule, CertificateAuthority, Summary, User,
} from './types'

export class ApiError extends Error {
  constructor(readonly status: number, message: string) {
    super(message)
  }
}

function csrfToken(): string {
  const match = document.cookie.match(/(?:^|;\s*)pw_csrf=([^;]*)/)
  return match ? decodeURIComponent(match[1]) : ''
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers)
  headers.set('Content-Type', 'application/json')
  if (init.method && init.method !== 'GET') headers.set('X-CSRF-Token', csrfToken())

  const res = await fetch(path, { ...init, headers, credentials: 'same-origin' })
  if (res.status === 204) return undefined as T
  const text = await res.text()
  const body = text ? JSON.parse(text) : undefined
  if (!res.ok) throw new ApiError(res.status, body?.error ?? res.statusText)
  return body as T
}

const post = <T>(path: string, body?: unknown) =>
  request<T>(path, { method: 'POST', body: body === undefined ? undefined : JSON.stringify(body) })

/** rangeParams serializes the time window every read endpoint accepts. */
export function rangeParams(from: Date, to: Date, extra: Record<string, string> = {}) {
  return new URLSearchParams({ from: from.toISOString(), to: to.toISOString(), ...extra }).toString()
}

export const api = {
  login: (username: string, password: string) =>
    post<{ user: User; csrf_token: string }>('/api/auth/login', { username, password }),
  logout: () => post<void>('/api/auth/logout'),
  me: () => request<{ user: User; apps: string[] }>('/api/me'),

  searchTraffic: (filter: Filter) => post<Page>('/api/traffic/search', filter),
  countTraffic: (filter: Filter) =>
    post<{ count: number; capped: boolean; cap: number }>('/api/traffic/count', filter),
  event: (id: string) => request<EventDetail>(`/api/traffic/${id}`),
  exportEvent: (id: string, format: 'raw' | 'curl' | 'har') =>
    fetch(`/api/traffic/${id}/export?format=${format}`, { credentials: 'same-origin' }).then((r) => r.text()),
  annotate: (id: string, body: { app_id: string; tags: string[]; note: string; bookmarked: boolean }) =>
    post<void>(`/api/traffic/${id}/annotate`, body),
  verdict: (id: string, body: { app_id: string; rule_id: number; verdict: string; note: string }) =>
    post<void>(`/api/traffic/${id}/verdict`, body),
  replay: (id: string, body: Record<string, unknown>) =>
    post<ReplayResult>(`/api/traffic/${id}/replay`, body),

  summary: (filter: Filter) => post<Summary>('/api/stats/summary', filter),
  series: (filter: Filter, bucket: string) =>
    post<{ bucket: string; points: SeriesPoint[] }>(`/api/stats/series?bucket=${bucket}`, filter),
  topRules: (filter: Filter, limit = 20) =>
    post<{ rules: RuleStat[] }>(`/api/stats/rules?limit=${limit}`, filter),
  topIPs: (filter: Filter, limit = 20) =>
    post<{ ips: IPStat[] }>(`/api/stats/ips?limit=${limit}`, filter),
  topBy: (filter: Filter, field: string, limit = 20) =>
    post<{ rows: GroupStat[] }>(`/api/stats/top/${field}?limit=${limit}`, filter),
  simulate: (filter: Filter, threshold: number) =>
    post<Simulation>(`/api/simulate?threshold=${threshold}`, filter),
  ipProfile: (ip: string, query: string) =>
    request<IPProfile>(`/api/ip/${encodeURIComponent(ip)}?${query}`),

  rules: (q: { q?: string; tag?: string; paranoia?: string; severity?: string; limit?: number; offset?: number }) =>
    request<{ rules: CrsRule[]; total: number }>(
      '/api/rules?' +
        new URLSearchParams(
          Object.entries(q)
            .filter(([, v]) => v !== '' && v !== undefined)
            .map(([k, v]) => [k, String(v)]),
        ).toString(),
    ),
  ruleFacets: () => request<RuleFacets>('/api/rules/facets'),

  apps: () => request<{ apps: App[] }>('/api/apps'),
  saveApp: (app: Partial<App>) => post<App>('/api/apps', app),
  deleteApp: (id: string) => request<void>(`/api/apps/${id}`, { method: 'DELETE' }),

  certificateAuthority: () => request<CertificateAuthority>('/api/ca'),
  regenerateCertificateAuthority: () => post<{ fingerprint: string }>('/api/ca/regenerate'),

  certificates: () => request<{ certificates: Certificate[] }>('/api/certificates'),
  saveCertificate: (body: { app_id: string; cert_pem: string; private_key_pem: string; is_default: boolean }) =>
    post<Certificate>('/api/certificates', body),
  deleteCertificate: (id: string) => request<void>(`/api/certificates/${id}`, { method: 'DELETE' }),

  exclusions: (app?: string) =>
    request<{ exclusions: Exclusion[] }>(`/api/exclusions${app ? `?app=${app}` : ''}`),
  previewExclusion: (body: Partial<Exclusion>) => post<{ seclang: string }>('/api/exclusions/preview', body),
  createExclusion: (body: Partial<Exclusion>) => post<Exclusion>('/api/exclusions', body),
  setExclusionEnabled: (id: string, enabled: boolean) =>
    request<void>(`/api/exclusions/${id}`, { method: 'PATCH', body: JSON.stringify({ enabled }) }),
  deleteExclusion: (id: string) => request<void>(`/api/exclusions/${id}`, { method: 'DELETE' }),
  verdictSummaries: (app?: string) =>
    request<{ summaries: VerdictSummary[] }>(`/api/exclusions/verdicts${app ? `?app=${app}` : ''}`),

  filters: () => request<{ filters: SavedFilter[] }>('/api/filters'),
  saveFilter: (body: { name: string; query: Filter; shared: boolean }) =>
    post<SavedFilter>('/api/filters', body),
  deleteFilter: (id: string) => request<void>(`/api/filters/${id}`, { method: 'DELETE' }),
  schema: () => request<{ fields: FieldSchema[]; max_limit: number }>('/api/filters/schema'),

  users: () => request<{ users: User[] }>('/api/users'),
  createUser: (body: { username: string; password: string; role: string; apps?: string[] }) =>
    post<User>('/api/users', body),
  updateUser: (id: string, body: Record<string, unknown>) =>
    request<void>(`/api/users/${id}`, { method: 'PATCH', body: JSON.stringify(body) }),
  deleteUser: (id: string) => request<void>(`/api/users/${id}`, { method: 'DELETE' }),

  alerts: () => request<{ alerts: AlertRule[] }>('/api/alerts'),
  saveAlert: (body: Partial<AlertRule>) => post<AlertRule>('/api/alerts', body),
  deleteAlert: (id: string) => request<void>(`/api/alerts/${id}`, { method: 'DELETE' }),

  audit: () => request<{ entries: AuditEntry[] }>('/api/audit'),
  streamStatus: () => request<{ connected: boolean }>('/api/stream/status'),
}

export interface ReplayResult {
  url: string
  status: number
  headers: Record<string, string>
  body: string
  truncated: boolean
  duration_ms: number
  original: { status: number; size: number; duration_ms: number }
  diff: { status_changed: boolean; status_from: number; status_to: number; size_delta: number }
}

export interface IPProfile {
  client_ip: string
  stat: IPStat
  fingerprints: GroupStat[]
  top_paths: GroupStat[]
  top_rules: RuleStat[]
}

export interface VerdictSummary {
  app_id: string
  rule_id: number
  false_positive: number
  true_positive: number
  unsure: number
}

export interface AuditEntry {
  id: number
  user_id: string
  action: string
  detail: Record<string, unknown>
  ts: string
}
