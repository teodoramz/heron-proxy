/** Formatting helpers shared by the table, drawer and dashboard. */

export function statusClass(status: number): string {
  if (status >= 500) return 'status-5xx'
  if (status >= 400) return 'status-4xx'
  if (status >= 300) return 'status-3xx'
  if (status >= 200) return 'status-2xx'
  return 'cell-dim'
}

/** anomalyLevel buckets a score into the four gutter intensities. */
export function anomalyLevel(score: number): 0 | 1 | 2 | 3 | 4 {
  if (score <= 0) return 0
  if (score < 5) return 1
  if (score < 10) return 2
  if (score < 20) return 3
  return 4
}

export function clockTime(ts: string): string {
  const d = new Date(ts)
  return d.toLocaleTimeString('en-GB', { hour12: false }) + '.' + String(d.getMilliseconds()).padStart(3, '0')
}

export function fullTime(ts: string): string {
  return new Date(ts).toISOString().replace('T', ' ').replace('Z', ' UTC')
}

export function bytes(n: number): string {
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} kB`
  return `${(n / 1024 / 1024).toFixed(1)} MB`
}

export function duration(ms: number): string {
  if (ms < 1000) return `${ms} ms`
  return `${(ms / 1000).toFixed(2)} s`
}

export function count(n: number): string {
  return n.toLocaleString('en-US')
}
