/**
 * humanize turns an API error into something worth reading.
 *
 * The API's messages are precise but written for whoever is holding the schema.
 * Anything not recognised is passed through rather than swallowed, so a real
 * fault is still visible.
 */
export function humanize(message: string): string {
  const m = message.toLowerCase()

  if (m.includes('unknown field')) {
    const field = message.match(/unknown field "([^"]+)"/)?.[1]
    return field
      ? `There is nothing recorded called “${field}”. Pick a field from the list instead.`
      : 'That field cannot be filtered on. Pick one from the list.'
  }
  if (m.includes('not allowed on field') || m.includes('unhandled operator')) {
    return 'That comparison does not work on this field. Try a different one, such as “is” or “contains”.'
  }
  if (m.includes('invalid cidr')) {
    const value = message.match(/invalid CIDR "([^"]+)"/)?.[1]
    return `“${value ?? 'that'}” is not an address range. Use something like 203.0.113.0/24, or switch the comparison to “is”.`
  }
  if (m.includes('cannot parse') && m.includes('datetime')) {
    return 'That is not a date the server understands. Use the date picker, or a date like 2026-09-09 14:30.'
  }
  if (m.includes('requires a key')) {
    return 'Name the header you want to match, for example content-type.'
  }
  if (m.includes('invalid regular expression')) {
    const detail = message.split('invalid regular expression:').pop()?.trim()
    return `That pattern is not valid${detail ? `: ${detail}` : ''}. Check the brackets are balanced.`
  }
  if (m.includes('regex longer than')) {
    return 'That pattern is too long. Keep it under 256 characters.'
  }
  if (m.includes('nested deeper')) {
    return 'This filter has too many nested groups. Remove a few conditions.'
  }
  if (m.includes('invalid cursor')) {
    return 'This page link is no longer valid. Go back to the first page.'
  }
  if (m.includes('no access to the requested apps')) {
    return 'You do not have access to that application.'
  }
  if (m.includes('csrf')) {
    return 'Your session expired in another tab. Reload the page and try again.'
  }
  if (m.includes('authentication required') || m.includes('session expired')) {
    return 'Your session has ended. Sign in again.'
  }
  // A ClickHouse failure is a bug, not something to phrase prettily; keep it
  // recognisable but say what it means.
  if (m.includes('code:') && m.includes('clickhouse')) {
    return `The query could not be run. ${message}`
  }
  return message
}
