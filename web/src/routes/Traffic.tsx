import { useCallback, useEffect, useRef, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { api } from '../api/client'
import { humanize } from '../api/errors'
import { DetailDrawer } from '../components/DetailDrawer'
import { FilterBar } from '../components/FilterBar'
import { Pager } from '../components/Pager'
import { TrafficTable } from '../components/TrafficTable'
import {
  loadColumns,
  loadWidthMode,
  loadWidths,
  saveColumns,
  saveWidthMode,
  saveWidths,
  type WidthMode,
} from '../components/columns'
import { useLiveTail } from '../hooks/useLiveTail'
import type { Filter, TrafficEvent } from '../api/types'

const MAX_LIVE_ROWS = 2000

/**
 * initialFilter seeds the view. Rule, app and source address can arrive in the
 * URL, which is how "View requests" on the tuning page and "List every request
 * from this address" land here already filtered. days widens the window.
 */
function initialFilter(params: URLSearchParams, limit: number): Filter {
  const conditions = []
  const rule = params.get('rule')
  if (rule) conditions.push({ field: 'rule_id', op: 'has' as const, value: Number(rule) })
  const ip = params.get('ip')
  if (ip) conditions.push({ field: 'client_ip', op: 'eq' as const, value: ip })
  const app = params.get('app')
  const days = Number(params.get('days'))

  return {
    range: days > 0 ? days * 24 * 60 : rule || ip ? 7 * 24 * 60 : 60,
    apps: app ? [app] : undefined,
    root: { op: 'and', conditions },
    limit,
    sort: 'ts',
    order: 'desc',
  }
}

export function Traffic() {
  const [params] = useSearchParams()
  // The filter is seeded from the URL once, so a link that changes the URL
  // while Traffic is already open has to start a fresh view.
  return <TrafficView key={params.toString()} params={params} />
}

function TrafficView({ params }: { params: URLSearchParams }) {
  const [pageSize, setPageSize] = useState(100)
  const [filter, setFilter] = useState<Filter>(() => initialFilter(params, 100))
  const [events, setEvents] = useState<TrafficEvent[]>([])
  const [hasMore, setHasMore] = useState(false)
  const [loading, setLoading] = useState(false)
  const [selected, setSelected] = useState<string | undefined>()
  const [live, setLive] = useState(false)
  const [total, setTotal] = useState<{ count: number; capped: boolean }>()
  const [error, setError] = useState('')
  const [columns, setColumns] = useState<string[]>(loadColumns)
  const [widths, setWidths] = useState<Record<string, number>>(loadWidths)
  const [widthMode, setWidthMode] = useState<WidthMode>(loadWidthMode)
  const [autoRefresh, setAutoRefresh] = useState(false)
  const [reloadToken, setReloadToken] = useState(0)
  const [lastLoaded, setLastLoaded] = useState<Date>()

  // One cursor per page start. Index 0 is the first page, which has no cursor.
  const [cursors, setCursors] = useState<(string | undefined)[]>([undefined])
  const [page, setPage] = useState(0)
  const requestId = useRef(0)

  function chooseColumns(ids: string[]) {
    setColumns(ids)
    saveColumns(ids)
  }

  const resizeColumn = useCallback((id: string, width: number) => {
    setWidths((prev) => {
      const next = { ...prev }
      if (width <= 0) delete next[id]
      else next[id] = width
      saveWidths(next)
      return next
    })
  }, [])

  function toggleWidthMode() {
    setWidthMode((prev) => {
      const next: WidthMode = prev === 'fit' ? 'full' : 'fit'
      saveWidthMode(next)
      return next
    })
  }

  // Clicking a header sorts by it; clicking the one already sorted reverses it.
  // Either way paging restarts, since the cursor belongs to the old ordering.
  const sortBy = useCallback((field: string) => {
    setFilter((prev) =>
      prev.sort === field
        ? { ...prev, order: prev.order === 'asc' ? 'desc' : 'asc', cursor: undefined }
        : { ...prev, sort: field, order: 'desc', cursor: undefined },
    )
  }, [])

  const refresh = useCallback(() => setReloadToken((n) => n + 1), [])

  // Changing the filter or the page size starts again from the first page.
  useEffect(() => {
    setCursors([undefined])
    setPage(0)
  }, [filter, pageSize])

  useEffect(() => {
    const id = ++requestId.current
    setLoading(true)
    setError('')

    api
      .searchTraffic({ ...filter, limit: pageSize, cursor: cursors[page] })
      .then((result) => {
        if (id !== requestId.current) return
        setEvents(result.events)
        setHasMore(result.has_more)
        // Remember where the next page starts so Older can move forward.
        if (result.has_more && result.next_cursor) {
          setCursors((prev) => {
            if (prev[page + 1] === result.next_cursor) return prev
            const next = prev.slice(0, page + 1)
            next[page + 1] = result.next_cursor
            return next
          })
        }
      })
      .catch((e) => id === requestId.current && setError(humanize(e.message)))
      .finally(() => {
        if (id !== requestId.current) return
        setLoading(false)
        setLastLoaded(new Date())
      })
  }, [filter, pageSize, page, cursors, reloadToken])

  // The count is for the whole filter, not the page, so it only follows the filter.
  useEffect(() => {
    api
      .countTraffic(filter)
      .then((c) => setTotal({ count: c.count, capped: c.capped }))
      .catch(() => setTotal(undefined))
  }, [filter, reloadToken])

  // Polling covers the gap when live tail is off, and only on the first page:
  // reloading a later page under a moving cursor would shuffle rows underfoot.
  useEffect(() => {
    if (!autoRefresh || live || page !== 0) return
    const timer = setInterval(refresh, 2000)
    return () => clearInterval(timer)
  }, [autoRefresh, live, page, refresh])

  // Live events are prepended, and only while looking at the newest page.
  const onLive = useCallback(
    (e: TrafficEvent) => {
      if (page !== 0) return
      setEvents((prev) => [e, ...prev].slice(0, MAX_LIVE_ROWS))
    },
    [page],
  )

  const connected = useLiveTail(live, filter, onLive)

  return (
    <>
      <FilterBar
        filter={filter}
        onChange={setFilter}
        live={live}
        liveConnected={connected}
        onToggleLive={() => setLive((v) => !v)}
        columns={columns}
        onColumnsChange={chooseColumns}
        widthMode={widthMode}
        onToggleWidthMode={toggleWidthMode}
        autoRefresh={autoRefresh}
        onToggleAutoRefresh={() => setAutoRefresh((v) => !v)}
        onRefresh={refresh}
        loading={loading}
        lastLoaded={lastLoaded}
      />
      {error && <p className="error-msg" style={{ padding: '8px 16px' }}>{error}</p>}
      <TrafficTable
        events={events}
        columns={columns}
        widths={widths}
        widthMode={widthMode}
        onResize={resizeColumn}
        selectedId={selected}
        loading={loading}
        onSelect={(e) => setSelected(e.id)}
        sort={filter.sort ?? 'ts'}
        order={filter.order ?? 'desc'}
        onSort={sortBy}
      />
      <Pager
        page={page}
        pageSize={pageSize}
        shown={events.length}
        total={total}
        hasMore={hasMore}
        loading={loading}
        onPrevious={() => setPage((p) => Math.max(0, p - 1))}
        onNext={() => setPage((p) => p + 1)}
        onPageSize={setPageSize}
      />
      {selected && <DetailDrawer id={selected} onClose={() => setSelected(undefined)} />}
    </>
  )
}
