import { useEffect, useState } from 'react'
import type { Filter } from '../api/types'

/** Quick windows, in minutes back from now. */
const QUICK = [
  { label: '15m', title: 'Last 15 minutes', minutes: 15 },
  { label: '1h', title: 'Last hour', minutes: 60 },
  { label: '6h', title: 'Last 6 hours', minutes: 360 },
  { label: '24h', title: 'Last 24 hours', minutes: 1440 },
  { label: '7d', title: 'Last 7 days', minutes: 10080 },
  { label: '30d', title: 'Last 30 days', minutes: 43200 },
]

/** toLocalInput formats an instant for a datetime-local input, in local time. */
function toLocalInput(iso?: string): string {
  const d = iso ? new Date(iso) : new Date()
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`
}

const DAY = new Intl.DateTimeFormat(undefined, { day: 'numeric', month: 'short' })
const CLOCK = new Intl.DateTimeFormat(undefined, { hour: '2-digit', minute: '2-digit' })

/** describe says what window is in effect, in the reader's own timezone. */
function describe(filter: Filter): string {
  if (filter.range) {
    const quick = QUICK.find((q) => q.minutes === filter.range)?.title
    if (quick) return quick
    const days = filter.range / (24 * 60)
    return Number.isInteger(days) ? `Last ${days} days` : `Last ${filter.range} minutes`
  }
  if (!filter.from || !filter.to) return 'All recorded traffic'
  const from = new Date(filter.from)
  const to = new Date(filter.to)
  const sameDay = from.toDateString() === to.toDateString()
  return sameDay
    ? `${DAY.format(from)}, ${CLOCK.format(from)} — ${CLOCK.format(to)}`
    : `${DAY.format(from)} ${CLOCK.format(from)} — ${DAY.format(to)} ${CLOCK.format(to)}`
}

interface Props {
  filter: Filter
  onChange: (filter: Filter) => void
}

/**
 * TimeRange picks the window the search covers: one of the quick buttons,
 * which keep sliding, or an exact start and end.
 */
export function TimeRange({ filter, onChange }: Props) {
  const [open, setOpen] = useState(false)
  const [from, setFrom] = useState(() => toLocalInput(filter.from))
  const [to, setTo] = useState(() => toLocalInput(filter.to))
  const [problem, setProblem] = useState('')

  // Opening the editor starts from whatever window is showing.
  useEffect(() => {
    if (!open) return
    setFrom(toLocalInput(filter.from))
    setTo(toLocalInput(filter.to))
    setProblem('')
  }, [open, filter.from, filter.to])

  function quick(minutes: number) {
    setOpen(false)
    onChange({ ...filter, range: minutes, cursor: undefined })
  }

  function applyExact() {
    const start = new Date(from)
    const end = new Date(to)
    if (isNaN(start.getTime()) || isNaN(end.getTime())) {
      setProblem('Pick both a start and an end.')
      return
    }
    if (start >= end) {
      setProblem('The start has to come before the end.')
      return
    }
    setOpen(false)
    onChange({
      ...filter,
      range: undefined,
      from: start.toISOString(),
      to: end.toISOString(),
      cursor: undefined,
    })
  }

  /** Nudges the exact window by whole days, for walking back through history. */
  function shift(days: number) {
    const ms = days * 86_400_000
    const start = new Date(filter.from ?? Date.now())
    const end = new Date(filter.to ?? Date.now())
    onChange({
      ...filter,
      range: undefined,
      from: new Date(start.getTime() + ms).toISOString(),
      to: new Date(end.getTime() + ms).toISOString(),
      cursor: undefined,
    })
  }

  return (
    <>
      {QUICK.map((q) => (
        <button
          key={q.label}
          type="button"
          className="btn btn-sm"
          aria-pressed={filter.range === q.minutes}
          title={q.title}
          onClick={() => quick(q.minutes)}
        >
          {q.label}
        </button>
      ))}
      <button
        type="button"
        className="btn btn-sm"
        aria-pressed={!filter.range}
        title="Search between an exact start and end"
        onClick={() => setOpen((v) => !v)}
      >
        Exact…
      </button>
      <span className="range-summary" title="The window this search covers">
        {describe(filter)}
      </span>

      {/*
        A div, not a form: this sits inside the filter bar's own form, and a
        nested submit bubbles out to it, re-running the text search with a
        stale filter and undoing the window just chosen.
      */}
      {open && (
        <div className="range-editor">
          <label>
            From
            <input
              type="datetime-local"
              className="input"
              value={from}
              max={to}
              onChange={(e) => setFrom(e.target.value)}
            />
          </label>
          <label>
            To
            <input
              type="datetime-local"
              className="input"
              value={to}
              min={from}
              onChange={(e) => setTo(e.target.value)}
            />
          </label>
          <button className="btn btn-sm" type="button" onClick={applyExact}>
            Apply
          </button>
          <button type="button" className="btn btn-sm" onClick={() => shift(-1)} title="The same window, a day earlier">
            ← day
          </button>
          <button type="button" className="btn btn-sm" onClick={() => shift(1)} title="The same window, a day later">
            day →
          </button>
          <span className="hint">Times are your own, not UTC.</span>
          {problem && <span className="error-msg">{problem}</span>}
        </div>
      )}
    </>
  )
}
