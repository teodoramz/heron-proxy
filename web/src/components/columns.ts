import type { TrafficEvent } from '../api/types'
import { bytes, clockTime, duration, statusClass } from './format'

export interface ColumnDef {
  id: string
  label: string
  /** Grid width. A fraction unit lets the column absorb spare space. */
  width: string
  align?: 'right'
  /** Text shown in the cell. */
  value: (e: TrafficEvent) => string
  /** Optional class applied to the cell, used for status colouring. */
  className?: (e: TrafficEvent) => string
}

const dim = () => 'cell-dim'

export const COLUMNS: ColumnDef[] = [
  { id: 'time', label: 'Time', width: '86px', value: (e) => clockTime(e.ts), className: dim },
  { id: 'date', label: 'Date', width: '84px', value: (e) => e.ts.slice(0, 10), className: dim },
  { id: 'app', label: 'App', width: '90px', value: (e) => e.app_id || '—', className: dim },
  { id: 'method', label: 'Method', width: '62px', value: (e) => e.method },
  { id: 'host', label: 'Host', width: '150px', value: (e) => e.host },
  { id: 'path', label: 'Path', width: 'minmax(220px, 2fr)', value: (e) => e.path },
  { id: 'query', label: 'Query', width: 'minmax(140px, 1fr)', value: (e) => e.query || '—', className: dim },
  { id: 'client_ip', label: 'Source', width: '132px', value: (e) => e.client_ip },
  {
    id: 'client_ip_claimed',
    label: 'Claimed source',
    width: '132px',
    value: (e) => (e.client_ip_claimed && e.client_ip_claimed !== '::' ? e.client_ip_claimed : '—'),
    className: dim,
  },
  { id: 'country', label: 'Country', width: '64px', value: (e) => e.country || '—', className: dim },
  {
    id: 'asn',
    label: 'Network',
    width: '150px',
    value: (e) => (e.asn ? `AS${e.asn} ${e.as_org ?? ''}`.trim() : '—'),
    className: dim,
  },
  { id: 'upstream', label: 'Upstream', width: 'minmax(160px, 1fr)', value: (e) => e.upstream || '—', className: dim },
  {
    id: 'status',
    label: 'Status',
    width: '58px',
    align: 'right',
    value: (e) => (e.status ? String(e.status) : '—'),
    className: (e) => statusClass(e.status),
  },
  {
    id: 'anomaly',
    label: 'Score',
    width: '58px',
    align: 'right',
    value: (e) => String(e.anomaly_score),
    className: (e) => (e.would_block ? 'block-flag' : e.anomaly_score ? '' : 'cell-dim'),
  },
  {
    // "Suspicious", not "blocked": nothing was stopped, and the rules are not
    // authoritative. The word should send someone to look, not settle the matter.
    id: 'would_block',
    label: 'Flag',
    width: '90px',
    value: (e) => (e.would_block ? 'suspicious' : '—'),
    className: (e) => (e.would_block ? 'block-flag' : 'cell-dim'),
  },
  {
    id: 'rules',
    label: 'Rules',
    width: 'minmax(120px, 1fr)',
    value: (e) => (e.rule_ids?.length ? e.rule_ids.join(' ') : '—'),
    className: (e) => (e.rule_ids?.length ? '' : 'cell-dim'),
  },
  {
    id: 'tags',
    label: 'Tags',
    width: 'minmax(140px, 1fr)',
    value: (e) => (e.rule_tags?.length ? e.rule_tags.filter((t) => t.startsWith('attack-')).join(' ') || e.rule_tags.join(' ') : '—'),
    className: dim,
  },
  { id: 'duration', label: 'Time', width: '72px', align: 'right', value: (e) => duration(e.duration_ms), className: dim },
  { id: 'upstream_ms', label: 'Upstream', width: '76px', align: 'right', value: (e) => duration(e.upstream_ms), className: dim },
  { id: 'waf_ms', label: 'WAF', width: '62px', align: 'right', value: (e) => duration(e.waf_ms), className: dim },
  { id: 'req_size', label: 'Req size', width: '76px', align: 'right', value: (e) => bytes(e.req_body_size), className: dim },
  { id: 'resp_size', label: 'Resp size', width: '80px', align: 'right', value: (e) => bytes(e.resp_size), className: dim },
  { id: 'content_type', label: 'Type', width: '130px', value: (e) => e.resp_content_type || '—', className: dim },
  { id: 'user_agent', label: 'User agent', width: 'minmax(200px, 2fr)', value: (e) => e.user_agent || '—', className: dim },
  { id: 'ja4', label: 'JA4', width: '190px', value: (e) => e.ja4 || '—', className: dim },
  { id: 'ja3', label: 'JA3', width: '190px', value: (e) => e.ja3 || '—', className: dim },
  { id: 'scheme', label: 'Scheme', width: '64px', value: (e) => e.scheme, className: dim },
  { id: 'http_version', label: 'Version', width: '76px', value: (e) => e.http_version, className: dim },
  { id: 'error', label: 'Error', width: 'minmax(140px, 1fr)', value: (e) => e.error || '—', className: (e) => (e.error ? 'status-5xx' : 'cell-dim') },
]

export const COLUMNS_BY_ID = new Map(COLUMNS.map((c) => [c.id, c]))

/** The columns shown before anyone changes anything. */
export const DEFAULT_COLUMNS = [
  'time', 'app', 'method', 'host', 'path', 'client_ip', 'status', 'anomaly', 'duration', 'rules',
]

const STORAGE_KEY = 'pw-columns'

export function loadColumns(): string[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    if (!raw) return DEFAULT_COLUMNS
    const parsed = JSON.parse(raw) as string[]
    const valid = parsed.filter((id) => COLUMNS_BY_ID.has(id))
    return valid.length ? valid : DEFAULT_COLUMNS
  } catch {
    return DEFAULT_COLUMNS
  }
}

export function saveColumns(ids: string[]): void {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(ids))
  } catch {
    // A browser with storage blocked simply loses the preference.
  }
}


const WIDTHS_KEY = 'pw-column-widths'

/** Column widths a person has set by dragging, in pixels. */
export function loadWidths(): Record<string, number> {
  try {
    const raw = localStorage.getItem(WIDTHS_KEY)
    return raw ? (JSON.parse(raw) as Record<string, number>) : {}
  } catch {
    return {}
  }
}

export function saveWidths(widths: Record<string, number>): void {
  try {
    localStorage.setItem(WIDTHS_KEY, JSON.stringify(widths))
  } catch {
    // A browser with storage blocked simply loses the preference.
  }
}

/** trackFor returns the grid track for a column, honouring a dragged width. */
export function trackFor(c: ColumnDef, widths: Record<string, number>): string {
  const w = widths[c.id]
  return w ? `${w}px` : c.width
}
