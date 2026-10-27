const DAY = 24 * 60 * 60_000

/**
 * daysToCover is the smallest window, in whole days back from now, that still
 * includes a request made at ts. Never less than a week, which is what a
 * profile shows when nothing older is asked for.
 */
export function daysToCover(ts?: string): number {
  if (!ts) return 7
  const age = Date.now() - new Date(ts).getTime()
  if (!Number.isFinite(age)) return 7
  return Math.max(7, Math.ceil(age / DAY) + 1)
}

/** profileLink opens an address's profile over a window that includes ts. */
export function profileLink(ip: string, ts?: string): string {
  return `/ip/${encodeURIComponent(ip)}?days=${daysToCover(ts)}`
}

/** requestsLink opens Traffic filtered to one address. */
export function requestsLink(ip: string, days = 7): string {
  return `/?${new URLSearchParams({ ip, days: String(days) })}`
}
