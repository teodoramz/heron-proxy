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
  blocked: 'Rejected by the proxy',
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

/** One line on what a field holds, with a value that would actually work. */
export const FIELD_HELP: Record<string, { what: string; example: string }> = {
  path: { what: 'The part of the URL after the host, without the query string.', example: '/api/v1/orders' },
  query: { what: 'Everything after the ? in the URL, after redaction.', example: 'page=2&sort=asc' },
  body: { what: 'The data a request carried. Only what was recorded.', example: 'password' },
  host: { what: 'The address the client asked for.', example: 'shop.local' },
  method: { what: 'The HTTP verb.', example: 'POST' },
  status: { what: 'What the application answered with. 200 is fine, 404 missing, 500 broken.', example: '404' },
  client_ip: { what: 'Where the request came from, as the proxy determined it.', example: '203.0.113.9' },
  client_ip_claimed: { what: 'The address the request claimed, believed only from a trusted proxy.', example: '10.0.0.5' },
  app_id: { what: 'Which of your applications received it.', example: 'shop' },
  user_agent: { what: 'What the client said it was. Easily faked.', example: 'sqlmap' },
  country: { what: 'Two-letter country code for the source address.', example: 'DE' },
  asn: { what: 'The network the source belongs to, as a number.', example: '64512' },
  as_org: { what: 'The name of that network.', example: 'Example Hosting' },
  ja3: { what: 'A fingerprint of the TLS handshake. Follows a client across addresses.', example: '03117a8e' },
  ja4: { what: 'A newer TLS fingerprint. Its prefix groups clients by stack.', example: 't13d' },
  would_block: { what: 'Whether the score passed this application’s threshold.', example: 'Yes' },
  blocked: { what: 'Whether the request was actually rejected. Only happens where enforcing is on.', example: 'Yes' },
  anomaly_score: { what: 'How much rule evidence accumulated. Higher is more suspicious.', example: '5' },
  rule_id: { what: 'A specific Core Rule Set rule. Look one up on the Rules page.', example: '942100' },
  rule_tag: { what: 'The kind of attack a rule detects.', example: 'attack-sqli' },
  rule_severity: { what: 'How serious the worst matching rule was. Higher is worse.', example: '5' },
  paranoia_max: { what: 'The paranoia level of the strictest rule that matched.', example: '1' },
  duration_ms: { what: 'How long the whole request took, in milliseconds.', example: '1000' },
  upstream_ms: { what: 'How much of that your application took.', example: '900' },
  waf_ms: { what: 'How much of that was spent checking rules.', example: '5' },
  req_body_size: { what: 'How large the request body was, in bytes.', example: '1024' },
  resp_size: { what: 'How large the response was, in bytes.', example: '4096' },
  resp_content_type: { what: 'What kind of thing the application returned.', example: 'application/json' },
  req_header: { what: 'A header the client sent. Name it, then match its value.', example: 'content-type' },
  resp_header: { what: 'A header the application returned.', example: 'server' },
  error: { what: 'Set when the proxy could not complete the request.', example: 'connection refused' },
  upstream: { what: 'Where the request was forwarded.', example: 'http://10.0.0.5:8080' },
  is_websocket: { what: 'Whether the connection was upgraded to a websocket.', example: 'Yes' },
  req_truncated: { what: 'Whether the body was larger than the capture limit.', example: 'Yes' },
  scheme: { what: 'http or https.', example: 'https' },
  http_version: { what: 'The protocol version the client used.', example: 'HTTP/1.1' },
  id: { what: 'The event identifier, matching X-Request-Id in your application logs.', example: '' },
  ts: { what: 'When the request arrived.', example: '' },
}

/** What each comparison does, for the help panel. */
export const OP_HELP: Record<Op, string> = {
  eq: 'Exactly this value.',
  ne: 'Anything except this value.',
  lt: 'Smaller than this number.',
  lte: 'This number or smaller.',
  gt: 'Larger than this number.',
  gte: 'This number or larger.',
  in: 'Any one of several values.',
  contains: 'The value appears somewhere inside. Case is ignored.',
  prefix: 'The value begins with this.',
  suffix: 'The value ends with this.',
  regex: 'Matches a regular expression. For when the other comparisons are not enough. ^ anchors the start, $ the end, \\d a digit, .* anything.',
  cidr: 'The address falls inside this range, such as 10.0.0.0/8.',
  has: 'This list contains the value.',
  exists: 'The field has any value at all.',
}

/** Worked examples for the help panel: what someone actually wants to ask. */
export const EXAMPLES: { question: string; how: string }[] = [
  { question: 'Who is attacking us?', how: 'Click Suspicious, then add Source address · is one of, or sort by score.' },
  { question: 'Did anyone reach the admin page?', how: 'Path · starts with · /admin' },
  { question: 'What is failing?', how: 'Click App failures, or Response status · is at least · 500' },
  { question: 'Everything from one address', how: 'Source address · is · 203.0.113.9' },
  { question: 'Everything from one network', how: 'Source address · is in the range · 203.0.113.0/24' },
  { question: 'Requests carrying a password field', how: 'Request body · contains · password' },
  { question: 'One scanner across changing addresses', how: 'TLS fingerprint (JA4) · is · the value from a request you already found' },
  { question: 'What did rule 942100 catch?', how: 'Rule number · includes · 942100' },
  { question: 'Slow pages', how: 'Time taken · is at least · 1000' },
  { question: 'JSON APIs only', how: 'Request header “content-type” · contains · json' },
  { question: 'Any versioned API path', how: 'Path · matches regex · ^/api/v\\d+/' },
  { question: 'Requests for scripts', how: 'Path · matches regex · \\.(php|asp|jsp)$' },
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
  regex: 'matches regex',
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
  if (field === 'blocked') return value ? 'Rejected by the proxy' : 'Not rejected'
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
    id: 'blocked',
    label: 'Rejected',
    title: 'Requests the proxy refused to forward',
    conditions: [{ field: 'blocked', op: 'eq', value: true }],
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
