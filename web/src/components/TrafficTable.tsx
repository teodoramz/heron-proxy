import { useCallback, useLayoutEffect, useRef, useState } from 'react'
import type { TrafficEvent } from '../api/types'
import { COLUMNS_BY_ID, sortFieldFor, trackFor, type ColumnDef, type WidthMode } from './columns'
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
  sort: string
  order: 'asc' | 'desc'
  onSort: (field: string) => void
}



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
  sort,
  order,
  onSort,
}: Props) {
  const viewport = useRef<HTMLDivElement>(null)
  const [range, setRange] = useState({ start: 0, end: 60 })

  const defs = columns.map((id) => COLUMNS_BY_ID.get(id)).filter(Boolean) as ColumnDef[]
  // The leading 4px track is the anomaly gutter.
  const template = `4px ${defs.map((c) => trackFor(c, widths, widthMode)).join(' ')}`

  // Panning is on the middle button only. The left button has to stay free for
  // selecting text inside a cell, which is the whole point of showing it.
  const startPan = useCallback((e: React.PointerEvent<HTMLDivElement>) => {
    const el = viewport.current
    if (!el || e.button !== 1) return
    e.preventDefault()

    const startX = e.clientX
    const startY = e.clientY
    const startLeft = el.scrollLeft
    const startTop = el.scrollTop

    function move(ev: PointerEvent) {
      el!.scrollLeft = startLeft - (ev.clientX - startX)
      el!.scrollTop = startTop - (ev.clientY - startY)
    }
    function done() {
      window.removeEventListener('pointermove', move)
      window.removeEventListener('pointerup', done)
      document.body.style.cursor = ''
    }
    window.addEventListener('pointermove', move)
    window.addEventListener('pointerup', done)
    document.body.style.cursor = 'grabbing'
  }, [])

  // Shift with the wheel scrolls sideways, the way people expect in a wide table.
  const onWheel = useCallback((e: React.WheelEvent<HTMLDivElement>) => {
    if (!e.shiftKey || !viewport.current) return
    viewport.current.scrollLeft += e.deltaY
  }, [])

  // Opening a row must not fight selecting text in it: a click that ends a
  // selection is the person copying a value, not asking for the detail.
  const select = useCallback(
    (e: TrafficEvent) => {
      const selection = window.getSelection()
      if (selection && !selection.isCollapsed && selection.toString().trim() !== '') return
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
          <Header
            defs={defs}
            template={template}
            widths={widths}
            onResize={onResize}
            sort={sort}
            order={order}
            onSort={onSort}
          />
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
      className="table-wrap"
      ref={viewport}
      onScroll={recompute}
      onPointerDown={startPan}
      onWheel={onWheel}
    >
      <div className="table-inner">
        <Header
          defs={defs}
          template={template}
          widths={widths}
          onResize={onResize}
          sort={sort}
          order={order}
          onSort={onSort}
        />
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
  sort,
  order,
  onSort,
}: {
  defs: ColumnDef[]
  template: string
  widths: Record<string, number>
  onResize: (id: string, width: number) => void
  sort: string
  order: 'asc' | 'desc'
  onSort: (field: string) => void
}) {
  return (
    <div className="thead" style={{ gridTemplateColumns: template }}>
      <div />
      {defs.map((c) => {
        const field = sortFieldFor(c)
        const active = field !== null && field === sort
        return (
          <div key={c.id} className={c.align === 'right' ? 'cell-num' : undefined}>
            {field ? (
              <button
                type="button"
                className={`th-sort${active ? ' on' : ''}`}
                onClick={() => onSort(field)}
                title={
                  active
                    ? `Sorted ${order === 'asc' ? 'lowest first' : 'highest first'} — click to reverse`
                    : `Sort by ${c.label.toLowerCase()}`
                }
              >
                {c.label}
                <span className="th-arrow">{active ? (order === 'asc' ? '▲' : '▼') : ''}</span>
              </button>
            ) : (
              <span className="th-label">{c.label}</span>
            )}
            <ResizeHandle id={c.id} widths={widths} onResize={onResize} />
          </div>
        )
      })}
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
