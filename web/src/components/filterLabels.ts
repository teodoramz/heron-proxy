import type { Op } from '../api/types'

/** Plain-language names for the filter fields, so nobody has to know the schema. */
export const FIELD_LABELS: Record<string, string> = {
  id: 'Event ID',
  ts: 'Time',
  app_id: 'Application',
  method: 'Method',
  scheme: 'Scheme',
  host: 'Website address',
  path: 'Path',
  query: 'Query string',
  body: 'Request body',
  req_body_size: 'Request size',
  req_truncated: 'Body was truncated',
  req_header: 'Request header',
  user_agent: 'User agent',
  client_ip: 'Source address',
  client_ip_claimed: 'Claimed source address',
  country: 'Country',
  asn: 'Network number',
  as_org: 'Network name',
  ja3: 'TLS fingerprint (JA3)',
  ja4: 'TLS fingerprint (JA4)',
  status: 'Response status',
  resp_size: 'Response size',
  resp_content_type: 'Response type',
  resp_header: 'Response header',
  duration_ms: 'Time taken',
  upstream_ms: 'Time the app took',
  waf_ms: 'Time checking rules',
  anomaly_score: 'Anomaly score',
  rule_id: 'Rule number',
  rule_tag: 'Attack type',
  rule_severity: 'Severity',
  paranoia_max: 'Paranoia level',
  would_block: 'Flagged suspicious',
  upstream: 'Sent to',
  error: 'Error',
  is_websocket: 'WebSocket',
  http_version: 'HTTP version',
}

/** Fields worth offering first; the rest follow alphabetically. */
export const COMMON_FIELDS = [
  'path', 'status', 'client_ip', 'method', 'body', 'would_block',
  'rule_tag', 'rule_id', 'anomaly_score', 'user_agent', 'app_id', 'host',
]

export const OP_LABELS: Record<Op, string> = {
  eq: 'is',
  ne: 'is not',
  lt: 'is less than',
  lte: 'is at most',
  gt: 'is more than',
  gte: 'is at least',
  in: 'is one of',
  contains: 'contains',
  prefix: 'starts with',
  suffix: 'ends with',
  regex: 'matches pattern',
  cidr: 'is in the range',
  has: 'includes',
  exists: 'is present',
}

export function fieldLabel(field: string): string {
  return FIELD_LABELS[field] ?? field
}

/** describe renders one condition as a sentence for the chip. */
export function describe(field: string, op: Op, value: unknown, key?: string): string {
  const name = key ? `${fieldLabel(field)} “${key}”` : fieldLabel(field)
  if (op === 'exists') return `${name} is present`
  if (field === 'would_block') return value ? 'Flagged suspicious' : 'Not flagged'
  return `${name} ${OP_LABELS[op] ?? op} ${String(value)}`
}

/** Preset is a one-click filter for a question people actually ask. */
export interface Preset {
  id: string
  label: string
  title: string
  conditions: { field: string; op: Op; value?: unknown; key?: string }[]
}

export const PRESETS: Preset[] = [
  {
    id: 'suspicious',
    label: 'Suspicious',
    title: 'Requests the rules would have blocked',
    conditions: [{ field: 'would_block', op: 'eq', value: true }],
  },
  {
    id: 'attacks',
    label: 'Rule matches',
    title: 'Requests where at least one rule fired',
    conditions: [{ field: 'anomaly_score', op: 'gte', value: 1 }],
  },
  {
    id: 'errors',
    label: 'Errors',
    title: 'Responses of 400 and above',
    conditions: [{ field: 'status', op: 'gte', value: 400 }],
  },
  {
    id: 'server-errors',
    label: 'App failures',
    title: 'Responses of 500 and above',
    conditions: [{ field: 'status', op: 'gte', value: 500 }],
  },
  {
    id: 'slow',
    label: 'Slow',
    title: 'Requests that took more than a second',
    conditions: [{ field: 'duration_ms', op: 'gte', value: 1000 }],
  },
  {
    id: 'posts',
    label: 'With a body',
    title: 'Requests that carried data',
    conditions: [{ field: 'req_body_size', op: 'gt', value: 0 }],
  },
  {
    id: 'sqli',
    label: 'SQL injection',
    title: 'Requests matching a SQL injection rule',
    conditions: [{ field: 'rule_tag', op: 'has', value: 'attack-sqli' }],
  },
  {
    id: 'xss',
    label: 'Cross-site scripting',
    title: 'Requests matching an XSS rule',
    conditions: [{ field: 'rule_tag', op: 'has', value: 'attack-xss' }],
  },
]

/**
 * activePreset reports which preset the current conditions are, if any.
 *
 * A preset replaces the filter rather than adding to it, so at most one can be
 * in effect. Knowing which lets the button show as pressed and toggle off.
 */
export function activePreset(conditions: { field: string; op: Op; value?: unknown }[]): string | null {
  for (const preset of PRESETS) {
    if (preset.conditions.length !== conditions.length) continue
    const same = preset.conditions.every((want) =>
      conditions.some(
        (have) => have.field === want.field && have.op === want.op && have.value === want.value,
      ),
    )
    if (same) return preset.id
  }
  return null
}

/** searchConditions turns a plain search box into an OR across the text fields. */
export function searchConditions(text: string) {
  return [
    { field: 'path', op: 'contains' as Op, value: text },
    { field: 'query', op: 'contains' as Op, value: text },
    { field: 'body', op: 'contains' as Op, value: text },
    { field: 'user_agent', op: 'contains' as Op, value: text },
    { field: 'host', op: 'contains' as Op, value: text },
  ]
}
