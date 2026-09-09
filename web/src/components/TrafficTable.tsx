import { useCallback, useLayoutEffect, useRef, useState } from 'react'
import type { TrafficEvent } from '../api/types'
import { COLUMNS_BY_ID, trackFor, type ColumnDef, type WidthMode } from './columns'
import { anomalyLevel } from './format'

const ROW_HEIGHT = 30
const OVERSCAN = 12
const MIN_WIDTH = 48

interface Props {
  events: TrafficEvent[]
  columns: string[]
  widths: Record<string, number>
  widthMode: WidthMode
  onResize: (id: string, width: number) => void
  selectedId?: string
  loading: boolean
  onSelect: (e: TrafficEvent) => void
}

/** Movement beyond this many pixels counts as a drag rather than a click. */
const DRAG_SLOP = 5

/**
 * TrafficTable renders only the rows in view, so a large page stays responsive.
 * Header and rows share one grid template, which is what keeps the columns
 * aligned as the selection and the dragged widths change.
 */
export function TrafficTable({
  events,
  columns,
  widths,
  widthMode,
  onResize,
  selectedId,
  loading,
  onSelect,
}: Props) {
  const viewport = useRef<HTMLDivElement>(null)
  const [range, setRange] = useState({ start: 0, end: 60 })
  const dragged = useRef(false)

  const defs = columns.map((id) => COLUMNS_BY_ID.get(id)).filter(Boolean) as ColumnDef[]
  // The leading 4px track is the anomaly gutter.
  const template = `4px ${defs.map((c) => trackFor(c, widths, widthMode)).join(' ')}`

  // Press and drag anywhere on the table to pan sideways, so a wide row can be
  // read without reaching for the scrollbar. A press that does not move is
  // still a click, and opens the row.
  const startPan = useCallback((e: React.PointerEvent<HTMLDivElement>) => {
    const el = viewport.current
    if (!el || e.button !== 0) return
    if ((e.target as HTMLElement).classList.contains('th-resize')) return

    const startX = e.clientX
    const startY = e.clientY
    const startLeft = el.scrollLeft
    const startTop = el.scrollTop
    dragged.current = false

    function move(ev: PointerEvent) {
      const dx = ev.clientX - startX
      const dy = ev.clientY - startY
      if (!dragged.current && Math.abs(dx) + Math.abs(dy) < DRAG_SLOP) return
      dragged.current = true
      el!.scrollLeft = startLeft - dx
      el!.scrollTop = startTop - dy
      document.body.style.cursor = 'grabbing'
      document.body.style.userSelect = 'none'
    }
    function done() {
      window.removeEventListener('pointermove', move)
      window.removeEventListener('pointerup', done)
      document.body.style.cursor = ''
      document.body.style.userSelect = ''
    }
    window.addEventListener('pointermove', move)
    window.addEventListener('pointerup', done)
  }, [])

  // A wheel with shift held scrolls sideways, which is the other way people expect.
  const onWheel = useCallback((e: React.WheelEvent<HTMLDivElement>) => {
    if (!e.shiftKey || !viewport.current) return
    viewport.current.scrollLeft += e.deltaY
  }, [])

  const select = useCallback(
    (e: TrafficEvent) => {
      if (dragged.current) return // the pointer was panning, not choosing a row
      onSelect(e)
    },
    [onSelect],
  )

  const recompute = useCallback(() => {
    const el = viewport.current
    if (!el) return
    const start = Math.max(0, Math.floor(el.scrollTop / ROW_HEIGHT) - OVERSCAN)
    const visible = Math.ceil(el.clientHeight / ROW_HEIGHT) + OVERSCAN * 2
    setRange({ start, end: start + visible })
  }, [])

  useLayoutEffect(() => {
    viewport.current?.scrollTo({ top: 0 })
    recompute()
  }, [recompute, events])

  if (events.length === 0 && !loading) {
    return (
      <div className="table-wrap">
        <div className="table-inner">
          <Header defs={defs} template={template} widths={widths} onResize={onResize} />
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
    <div
      className="table-wrap pannable"
      ref={viewport}
      onScroll={recompute}
      onPointerDown={startPan}
      onWheel={onWheel}
    >
      <div className="table-inner">
        <Header defs={defs} template={template} widths={widths} onResize={onResize} />
        <div style={{ height: range.start * ROW_HEIGHT }} />
        {slice.map((e) => (
          <Row
            key={e.id}
            event={e}
            defs={defs}
            template={template}
            selected={e.id === selectedId}
            onSelect={select}
          />
        ))}
        <div style={{ height: Math.max(0, (events.length - range.end) * ROW_HEIGHT) }} />
      </div>
      {loading && <p className="empty">Loading…</p>}
    </div>
  )
}

function Header({
  defs,
  template,
  widths,
  onResize,
}: {
  defs: ColumnDef[]
  template: string
  widths: Record<string, number>
  onResize: (id: string, width: number) => void
}) {
  return (
    <div className="thead" style={{ gridTemplateColumns: template }}>
      <div />
      {defs.map((c) => (
        <div key={c.id} className={c.align === 'right' ? 'cell-num' : undefined}>
          <span className="th-label">{c.label}</span>
          <ResizeHandle id={c.id} widths={widths} onResize={onResize} />
        </div>
      ))}
    </div>
  )
}

/** ResizeHandle drags a column to a fixed pixel width. */
function ResizeHandle({
  id,
  widths,
  onResize,
}: {
  id: string
  widths: Record<string, number>
  onResize: (id: string, width: number) => void
}) {
  function start(e: React.PointerEvent<HTMLSpanElement>) {
    e.preventDefault()
    e.stopPropagation()

    // The starting width is whatever the column is rendering at right now, so a
    // flexible column becomes fixed at its current size rather than jumping.
    const cell = e.currentTarget.parentElement as HTMLElement
    const startWidth = widths[id] ?? cell.getBoundingClientRect().width
    const startX = e.clientX

    function move(ev: PointerEvent) {
      onResize(id, Math.max(MIN_WIDTH, Math.round(startWidth + ev.clientX - startX)))
    }
    function done() {
      window.removeEventListener('pointermove', move)
      window.removeEventListener('pointerup', done)
      document.body.style.cursor = ''
      document.body.style.userSelect = ''
    }
    window.addEventListener('pointermove', move)
    window.addEventListener('pointerup', done)
    document.body.style.cursor = 'col-resize'
    document.body.style.userSelect = 'none'
  }

  return (
    <span
      className="th-resize"
      onPointerDown={start}
      onDoubleClick={(e) => {
        e.stopPropagation()
        onResize(id, 0) // back to the column's natural width
      }}
      role="separator"
      aria-label="Resize column"
      title="Drag to resize, double-click to reset"
    />
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
