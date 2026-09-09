import { useCallback, useLayoutEffect, useRef, useState } from 'react'
import type { TrafficEvent } from '../api/types'
import { anomalyLevel, clockTime, duration, statusClass } from './format'

const ROW_HEIGHT = 30
const OVERSCAN = 12

interface Props {
  events: TrafficEvent[]
  selectedId?: string
  hasMore: boolean
  loading: boolean
  onSelect: (e: TrafficEvent) => void
  onLoadMore: () => void
}

/**
 * TrafficTable renders only the rows in view, so a hundred thousand loaded rows
 * stay responsive. Rows are fixed height, which keeps the maths exact.
 */
export function TrafficTable({ events, selectedId, hasMore, loading, onSelect, onLoadMore }: Props) {
  const viewport = useRef<HTMLDivElement>(null)
  const [range, setRange] = useState({ start: 0, end: 60 })

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
        <Header />
        <p className="empty">
          <strong>No traffic matches this filter</strong>
          Widen the time range, or clear a condition to see more.
        </p>
      </div>
    )
  }

  const slice = events.slice(range.start, range.end)
  const topPad = range.start * ROW_HEIGHT
  const bottomPad = Math.max(0, (events.length - range.end) * ROW_HEIGHT)

  return (
    <div className="table-wrap" ref={viewport} onScroll={recompute}>
      <Header />
      <div style={{ height: topPad }} />
      {slice.map((e) => (
        <Row key={e.id} event={e} selected={e.id === selectedId} onSelect={onSelect} />
      ))}
      <div style={{ height: bottomPad }} />
      {loading && <p className="empty">Loading…</p>}
    </div>
  )
}

function Header() {
  return (
    <div className="thead grid-cols">
      <div />
      <div>Time</div>
      <div>App</div>
      <div>Method</div>
      <div>Path</div>
      <div>Source</div>
      <div className="cell-num">Sts</div>
      <div className="cell-num">Score</div>
      <div className="cell-num">Time</div>
      <div>Rules</div>
    </div>
  )
}

function Row({
  event,
  selected,
  onSelect,
}: {
  event: TrafficEvent
  selected: boolean
  onSelect: (e: TrafficEvent) => void
}) {
  const rules = event.rule_ids ?? []
  return (
    <div
      className="trow grid-cols"
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
      <div className="cell-dim">{clockTime(event.ts)}</div>
      <div className="cell-dim">{event.app_id || '—'}</div>
      <div>{event.method}</div>
      <div className="cell-path">
        {event.is_websocket && <span className="tag" style={{ marginRight: 6 }}>ws</span>}
        {event.path}
        {event.query && <span className="cell-query">?{event.query}</span>}
      </div>
      <div className="cell-dim">
        {event.client_ip}
        {event.country && <span className="cell-query"> {event.country}</span>}
      </div>
      <div className={`cell-num ${statusClass(event.status)}`}>{event.status || '—'}</div>
      <div className="cell-num">
        {event.would_block ? (
          <span className="block-flag" title="CRS would have blocked this request">
            {event.anomaly_score}
          </span>
        ) : (
          <span className={event.anomaly_score ? '' : 'cell-dim'}>{event.anomaly_score}</span>
        )}
      </div>
      <div className="cell-num cell-dim">{duration(event.duration_ms)}</div>
      <div className="cell-dim">{rules.length ? rules.slice(0, 3).join(' ') : '—'}</div>
    </div>
  )
}
