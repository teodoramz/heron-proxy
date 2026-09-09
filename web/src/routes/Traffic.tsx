import { useCallback, useEffect, useRef, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { api } from '../api/client'
import { DetailDrawer } from '../components/DetailDrawer'
import { FilterBar } from '../components/FilterBar'
import { TrafficTable } from '../components/TrafficTable'
import { loadColumns, saveColumns } from '../components/columns'
import { useLiveTail } from '../hooks/useLiveTail'
import type { Filter, TrafficEvent } from '../api/types'

const MAX_LIVE_ROWS = 5000

/**
 * initialFilter seeds the view. Rule and app can arrive in the URL, which is how
 * "View requests" on the tuning page lands here already filtered.
 */
function initialFilter(params: URLSearchParams): Filter {
  const to = new Date()
  const conditions = []
  const rule = params.get('rule')
  if (rule) conditions.push({ field: 'rule_id', op: 'has' as const, value: Number(rule) })
  const app = params.get('app')

  return {
    from: new Date(to.getTime() - (rule ? 7 * 24 : 1) * 60 * 60_000).toISOString(),
    to: to.toISOString(),
    apps: app ? [app] : undefined,
    root: { op: 'and', conditions },
    limit: 200,
  }
}

export function Traffic() {
  const [params] = useSearchParams()
  const [filter, setFilter] = useState<Filter>(() => initialFilter(params))
  const [events, setEvents] = useState<TrafficEvent[]>([])
  const [cursor, setCursor] = useState<string | undefined>()
  const [hasMore, setHasMore] = useState(false)
  const [loading, setLoading] = useState(false)
  const [selected, setSelected] = useState<string | undefined>()
  const [live, setLive] = useState(false)
  const [total, setTotal] = useState<{ count: number; capped: boolean }>()
  const [error, setError] = useState('')
  const [columns, setColumns] = useState<string[]>(loadColumns)
  const [autoRefresh, setAutoRefresh] = useState(false)
  const [reloadToken, setReloadToken] = useState(0)
  const [lastLoaded, setLastLoaded] = useState<Date>()
  const requestId = useRef(0)

  function chooseColumns(ids: string[]) {
    setColumns(ids)
    saveColumns(ids)
  }

  const refresh = useCallback(() => setReloadToken((n) => n + 1), [])

  // Reload from the top whenever the filter changes.
  useEffect(() => {
    const id = ++requestId.current
    setLoading(true)
    setError('')
    api
      .searchTraffic({ ...filter, cursor: undefined })
      .then((page) => {
        if (id !== requestId.current) return
        setEvents(page.events)
        setCursor(page.next_cursor)
        setHasMore(page.has_more)
      })
      .catch((e) => id === requestId.current && setError(e.message))
      .finally(() => {
        if (id !== requestId.current) return
        setLoading(false)
        setLastLoaded(new Date())
      })

    api
      .countTraffic(filter)
      .then((c) => id === requestId.current && setTotal({ count: c.count, capped: c.capped }))
      .catch(() => setTotal(undefined))
  }, [filter, reloadToken])

  // Polling covers the gap when live tail is off, and keeps counts current.
  useEffect(() => {
    if (!autoRefresh || live) return
    const timer = setInterval(refresh, 2000)
    return () => clearInterval(timer)
  }, [autoRefresh, live, refresh])

  const loadMore = useCallback(() => {
    if (!cursor || loading) return
    setLoading(true)
    api
      .searchTraffic({ ...filter, cursor })
      .then((page) => {
        setEvents((prev) => [...prev, ...page.events])
        setCursor(page.next_cursor)
        setHasMore(page.has_more)
      })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false))
  }, [cursor, filter, loading])

  // Live events are prepended; the list is capped so memory stays bounded.
  const onLive = useCallback((e: TrafficEvent) => {
    setEvents((prev) => [e, ...prev].slice(0, MAX_LIVE_ROWS))
  }, [])

  const connected = useLiveTail(live, filter, onLive)

  return (
    <>
      <FilterBar
        filter={filter}
        onChange={setFilter}
        live={live}
        liveConnected={connected}
        onToggleLive={() => setLive((v) => !v)}
        total={total}
        columns={columns}
        onColumnsChange={chooseColumns}
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
        selectedId={selected}
        hasMore={hasMore}
        loading={loading}
        onSelect={(e) => setSelected(e.id)}
        onLoadMore={loadMore}
      />
      {selected && <DetailDrawer id={selected} onClose={() => setSelected(undefined)} />}
    </>
  )
}
