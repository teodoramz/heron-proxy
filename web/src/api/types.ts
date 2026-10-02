export type Role = 'admin' | 'analyst'

export interface User {
  id: string
  username: string
  role: Role
  enabled: boolean
  created_at: string
  last_login_at?: string
}

export interface TrafficEvent {
  id: string
  ts: string
  app_id: string
  client_ip: string
  client_ip_claimed?: string
  country: string
  asn: number
  as_org?: string
  ja3: string
  ja4: string
  method: string
  scheme: string
  host: string
  path: string
  query: string
  http_version: string
  req_headers?: Record<string, string>
  req_body_size: number
  req_body_inline?: string
  req_body_preview?: string
  req_body_sha256?: string
  req_body_blob?: string
  req_truncated: boolean
  user_agent: string
  status: number
  resp_headers?: Record<string, string>
  resp_size: number
  resp_content_type: string
  duration_ms: number
  upstream_ms: number
  waf_ms: number
  anomaly_score: number
  rule_ids: number[] | null
  rule_msgs?: string[] | null
  rule_tags: string[] | null
  rule_severity: number
  paranoia_max: number
  would_block: boolean
  blocked: boolean
  upstream: string
  error: string
  is_websocket: boolean
}

export interface EventDetail extends TrafficEvent {
  body?: string
  body_source?: string
  annotation?: Annotation
  fp_marks?: FPMark[]
  matched_rules?: { rule_id: number; message?: string }[]
}

export interface Annotation {
  event_id: string
  app_id: string
  tags: string[]
  note: string
  bookmarked: boolean
  updated_at: string
}

export interface FPMark {
  id: string
  event_id: string
  app_id: string
  rule_id: number
  verdict: 'false_positive' | 'true_positive' | 'unsure'
  note: string
  created_at: string
}

export interface Page {
  events: TrafficEvent[]
  next_cursor?: string
  has_more: boolean
}

export type Op =
  | 'eq' | 'ne' | 'lt' | 'lte' | 'gt' | 'gte' | 'in'
  | 'contains' | 'prefix' | 'suffix' | 'regex' | 'cidr' | 'has' | 'exists'

export interface Condition {
  field: string
  op: Op
  value?: unknown
  key?: string
}

export interface Group {
  op: 'and' | 'or'
  not?: boolean
  conditions?: Condition[]
  groups?: Group[]
}

export interface Filter {
  from?: string
  to?: string
  apps?: string[]
  root: Group
  limit?: number
  cursor?: string
  sort?: string
  order?: 'asc' | 'desc'
  /**
   * Minutes back from now, when the window is relative. Held client-side and
   * turned into from/to for each request, so the window keeps sliding; absent
   * means from/to are fixed and stay where the user put them.
   */
  range?: number
}

export interface FieldSchema {
  field: string
  kind: string
  operators: Op[]
  needs_key?: boolean
}

export interface Summary {
  requests: number
  clients: number
  would_block: number
  blocked: number
  errors: number
  bytes: number
  p50_duration_ms: number
  p95_duration_ms: number
  p99_duration_ms: number
  avg_anomaly: number
  websockets: number
}

export interface SeriesPoint {
  bucket: string
  requests: number
  s2xx: number
  s3xx: number
  s4xx: number
  s5xx: number
  would_block: number
  p50_duration_ms: number
  p95_duration_ms: number
  p99_duration_ms: number
}

export interface RuleStat {
  rule_id: number
  hits: number
  clients: number
  tags?: string[]
  message?: string
}

export interface IPStat {
  client_ip: string
  country: string
  asn: number
  as_org: string
  requests: number
  paths: number
  anomaly: number
  would_block: number
  errors: number
  first_seen: string
  last_seen: string
}

export interface GroupStat {
  key: string
  requests: number
  errors: number
  would_block: number
}

export interface Simulation {
  threshold: number
  total: number
  would_block: number
  percent: number
}

export interface App {
  id: string
  name: string
  hostnames: string[]
  upstream_url: string
  upstream_tls_verify: boolean
  http_only: boolean
  extra_headers?: { name: string; value: string }[]
  preserve_host: boolean
  trusted_cidrs: string[]
  client_ip_header: string
  retention_days: number
  enabled: boolean
  capture: { enabled: boolean; body_cap_bytes: number; inline_max_bytes: number; skip_paths: string[] }
  redaction: { enabled: boolean; headers: string[]; fields: string[]; mask: string }
  waf: { enabled: boolean; mode: 'detect' | 'block'; paranoia_level: number; threshold: number }
}

export interface Certificate {
  id: string
  app_id: string
  sni_names: string[]
  fingerprint: string
  not_before: string
  not_after: string
  is_default: boolean
  expires_in_days: number
}

export interface Exclusion {
  id: string
  app_id: string
  rule_id: number
  target: string
  path: string
  reason: string
  seclang: string
  enabled: boolean
  created_at: string
}

export interface AlertRule {
  id: string
  name: string
  app_id: string
  channel: 'webhook' | 'mattermost'
  template?: string
  post_as?: string
  post_icon?: string
  target_url: string
  throttle_seconds: number
  enabled: boolean
  last_fired_at?: string
  condition: {
    rule_ids?: number[]
    rule_tags?: string[]
    min_anomaly?: number
    would_block?: boolean
    status_at_least?: number
    path_prefix?: string
  }
}

export interface SavedFilter {
  id: string
  user_id: string
  name: string
  query: Filter
  shared: boolean
}

export interface CrsRule {
  id: number
  message: string
  tags: string[]
  severity: string
  paranoia: number
  phase: number
  file: string
  category: string
  source: string
}

export interface RuleFacets {
  total: number
  tags: string[]
  categories: string[]
  severities: string[]
}

export interface CertificateAuthority {
  cert_pem: string
  fingerprint: string
  not_after: string
  created_at: string
  expires_in_days: number
}
