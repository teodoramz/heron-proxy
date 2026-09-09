import { useEffect, useState } from 'react'
import { api } from '../api/client'
import { ColumnPicker } from './ColumnPicker'
import type { WidthMode } from './columns'
import type { Condition, FieldSchema, Filter, Op } from '../api/types'

interface Props {
  filter: Filter
  onChange: (f: Filter) => void
  live: boolean
  liveConnected: boolean
  onToggleLive: () => void
  columns: string[]
  onColumnsChange: (ids: string[]) => void
  widthMode: WidthMode
  onToggleWidthMode: () => void
  autoRefresh: boolean
  onToggleAutoRefresh: () => void
  onRefresh: () => void
  loading: boolean
  lastLoaded?: Date
}

const RANGES: { label: string; minutes: number }[] = [
  { label: '15m', minutes: 15 },
  { label: '1h', minutes: 60 },
  { label: '6h', minutes: 360 },
  { label: '24h', minutes: 1440 },
  { label: '7d', minutes: 10080 },
]

/** FilterBar edits the query. Conditions are chips so the whole filter is legible at a glance. */
export function FilterBar({
  filter,
  onChange,
  live,
  liveConnected,
  onToggleLive,
  columns,
  onColumnsChange,
  widthMode,
  onToggleWidthMode,
  autoRefresh,
  onToggleAutoRefresh,
  onRefresh,
  loading,
  lastLoaded,
}: Props) {
  const [schema, setSchema] = useState<FieldSchema[]>([])
  const [field, setField] = useState('path')
  const [op, setOp] = useState<Op>('contains')
  const [value, setValue] = useState('')
  const [key, setKey] = useState('')

  useEffect(() => {
    api.schema().then((s) => setSchema(s.fields)).catch(() => setSchema([]))
  }, [])

  const current = schema.find((f) => f.field === field)
  const conditions = filter.root.conditions ?? []

  function setRange(minutes: number) {
    const to = new Date()
    const from = new Date(to.getTime() - minutes * 60_000)
    onChange({ ...filter, from: from.toISOString(), to: to.toISOString(), cursor: undefined })
  }

  function addCondition(e: React.FormEvent) {
    e.preventDefault()
    if (!field) return
    const parsed = coerce(value, current?.kind)
    const cond: Condition = { field, op, value: parsed }
    if (current?.needs_key) {
      if (!key) return
      cond.key = key
    }
    onChange({
      ...filter,
      cursor: undefined,
      root: { ...filter.root, op: filter.root.op ?? 'and', conditions: [...conditions, cond] },
    })
    setValue('')
  }

  function removeCondition(index: number) {
    onChange({
      ...filter,
      cursor: undefined,
      root: { ...filter.root, conditions: conditions.filter((_, i) => i !== index) },
    })
  }

  return (
    <div className="filters">
      <form className="filter-row" onSubmit={addCondition}>
        <select
          className="select"
          style={{ width: 150 }}
          value={field}
          onChange={(e) => {
            setField(e.target.value)
            const next = schema.find((f) => f.field === e.target.value)
            if (next && !next.operators.includes(op)) setOp(next.operators[0])
          }}
          aria-label="Filter field"
        >
          {schema.map((f) => (
            <option key={f.field} value={f.field}>
              {f.field}
            </option>
          ))}
        </select>

        <select
          className="select"
          style={{ width: 110 }}
          value={op}
          onChange={(e) => setOp(e.target.value as Op)}
          aria-label="Operator"
        >
          {(current?.operators ?? ['eq']).map((o) => (
            <option key={o} value={o}>
              {o}
            </option>
          ))}
        </select>

        {current?.needs_key && (
          <input
            className="input"
            style={{ width: 140 }}
            placeholder="header name"
            value={key}
            onChange={(e) => setKey(e.target.value)}
            aria-label="Header name"
          />
        )}

        {op !== 'exists' && (
          <input
            className="input"
            style={{ width: 220 }}
            placeholder="value"
            value={value}
            onChange={(e) => setValue(e.target.value)}
            aria-label="Value"
          />
        )}

        <button className="btn" type="submit">
          Add filter
        </button>

        <span className="spacer" />

        {RANGES.map((r) => (
          <button key={r.label} type="button" className="btn btn-sm" onClick={() => setRange(r.minutes)}>
            {r.label}
          </button>
        ))}

        <button
          type="button"
          className="btn btn-sm"
          onClick={onRefresh}
          disabled={loading}
          title="Reload the table now"
        >
          {loading ? 'Loading…' : 'Refresh'}
        </button>

        <button
          type="button"
          className="btn btn-sm"
          onClick={onToggleAutoRefresh}
          aria-pressed={autoRefresh}
          disabled={live}
          title={live ? 'Live tail is already streaming' : 'Reload every 2 seconds'}
        >
          Auto {autoRefresh && !live ? 'on' : 'off'}
        </button>

        <button
          type="button"
          className="btn btn-sm"
          onClick={onToggleLive}
          aria-pressed={live}
          title={live ? 'Stop streaming new requests' : 'Stream new requests as they arrive'}
        >
          <span className={`live-dot ${live ? (liveConnected ? 'on' : 'pending') : ''}`} />{' '}
          {live ? (liveConnected ? 'Live' : 'Connecting') : 'Live'}
        </button>

        <button
          type="button"
          className="btn btn-sm"
          onClick={onToggleWidthMode}
          aria-pressed={widthMode === 'full'}
          title={
            widthMode === 'fit'
              ? 'Let columns take the width their content needs, and scroll sideways'
              : 'Fit every column into the window'
          }
        >
          {widthMode === 'fit' ? 'Fit width' : 'Full width'}
        </button>

        <ColumnPicker selected={columns} onChange={onColumnsChange} />
      </form>

      {(conditions.length > 0 || lastLoaded) && (
        <div className="filter-row">
          {conditions.map((c, i) => (
            <span className="chip" key={`${c.field}-${i}`}>
              {c.field}
              {c.key ? `[${c.key}]` : ''} <span className="chip-op">{c.op}</span>{' '}
              {c.op === 'exists' ? '' : String(c.value)}
              <button type="button" onClick={() => removeCondition(i)} aria-label={`Remove ${c.field} filter`}>
                ×
              </button>
            </span>
          ))}
          <span className="spacer" />
          {lastLoaded && (
            <span className="muted mono" title="When the table last reloaded">
              updated {lastLoaded.toLocaleTimeString('en-GB', { hour12: false })}
            </span>
          )}
        </div>
      )}
    </div>
  )
}

/** coerce turns the text input into the type the field expects. */
function coerce(raw: string, kind?: string): unknown {
  if (kind === 'number' || kind === 'number_array') {
    const n = Number(raw)
    return Number.isFinite(n) ? n : raw
  }
  if (kind === 'boolean') return raw === 'true' || raw === '1'
  return raw
}
