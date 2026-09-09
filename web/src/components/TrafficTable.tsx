import { useCallback, useLayoutEffect, useRef, useState } from 'react'
import type { TrafficEvent } from '../api/types'
import { COLUMNS_BY_ID, type ColumnDef } from './columns'
import { anomalyLevel } from './format'

const ROW_HEIGHT = 30
const OVERSCAN = 12

interface Props {
  events: TrafficEvent[]
  columns: string[]
  selectedId?: string
  hasMore: boolean
  loading: boolean
  onSelect: (e: TrafficEvent) => void
  onLoadMore: () => void
}

/**
 * TrafficTable renders only the rows in view, so a large loaded set stays
 * responsive. Header and rows share one grid template, which is what keeps the
 * columns aligned as the selection changes.
 */
export function TrafficTable({
  events,
  columns,
  selectedId,
  hasMore,
  loading,
  onSelect,
  onLoadMore,
}: Props) {
  const viewport = useRef<HTMLDivElement>(null)
  const [range, setRange] = useState({ start: 0, end: 60 })

  const defs = columns.map((id) => COLUMNS_BY_ID.get(id)).filter(Boolean) as ColumnDef[]
  // The leading 4px track is the anomaly gutter.
  const template = `4px ${defs.map((c) => c.width).join(' ')}`

  const recompute = useCallback(() => {
    const el = viewport.current
    if (!el) return
    const start = Math.max(0, Math.floor(el.scrollTop / ROW_HEIGHT) - OVERSCAN)
    const visible = Math.ceil(el.clientHeight / ROW_HEIGHT) + OVERSCAN * 2
    setRange({ start, end: start + visible })

    const nearBottom = el.scrollHeight - el.scrollTop - el.clientHeight < ROW_HEIGHT * 20
    if (nearBottom && hasMore && !loading) onLoadMore()
  }, [hasMore, loading, onLoadMore])

  useLayoutEffect(recompute, [recompute, events.length])

  if (events.length === 0 && !loading) {
    return (
      <div className="table-wrap">
        <div className="table-inner">
          <Header defs={defs} template={template} />
        </div>
        <p className="empty">
          <strong>No traffic matches this filter</strong>
          Widen the time range, or remove a condition to see more.
        </p>
      </div>
    )
  }

  const slice = events.slice(range.start, range.end)

  return (
    <div className="table-wrap" ref={viewport} onScroll={recompute}>
      <div className="table-inner">
        <Header defs={defs} template={template} />
        <div style={{ height: range.start * ROW_HEIGHT }} />
        {slice.map((e) => (
          <Row
            key={e.id}
            event={e}
            defs={defs}
            template={template}
            selected={e.id === selectedId}
            onSelect={onSelect}
          />
        ))}
        <div style={{ height: Math.max(0, (events.length - range.end) * ROW_HEIGHT) }} />
      </div>
      {loading && <p className="empty">Loading…</p>}
    </div>
  )
}

function Header({ defs, template }: { defs: ColumnDef[]; template: string }) {
  return (
    <div className="thead" style={{ gridTemplateColumns: template }}>
      <div />
      {defs.map((c) => (
        <div key={c.id} className={c.align === 'right' ? 'cell-num' : undefined}>
          {c.label}
        </div>
      ))}
    </div>
  )
}

function Row({
  event,
  defs,
  template,
  selected,
  onSelect,
}: {
  event: TrafficEvent
  defs: ColumnDef[]
  template: string
  selected: boolean
  onSelect: (e: TrafficEvent) => void
}) {
  return (
    <div
      className="trow"
      style={{ gridTemplateColumns: template }}
      role="row"
      tabIndex={0}
      aria-selected={selected}
      onClick={() => onSelect(event)}
      onKeyDown={(ev) => {
        if (ev.key === 'Enter' || ev.key === ' ') {
          ev.preventDefault()
          onSelect(event)
        }
      }}
    >
      <div
        className="gutter"
        data-level={anomalyLevel(event.anomaly_score)}
        title={`Anomaly score ${event.anomaly_score}`}
      />
      {defs.map((c) => {
        const text = c.value(event)
        const classes = [c.align === 'right' ? 'cell-num' : '', c.className?.(event) ?? '']
          .filter(Boolean)
          .join(' ')
        return (
          // The full value is on the title, so a clipped cell is still readable.
          <div key={c.id} className={classes} title={text}>
            {c.id === 'path' && event.is_websocket && <span className="tag">ws</span>}
            {text}
          </div>
        )
      })}
    </div>
  )
}
