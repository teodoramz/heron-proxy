import { useCallback, useEffect, useRef, useState } from 'react'
import { api } from '../api/client'
import { DetailDrawer } from '../components/DetailDrawer'
import { FilterBar } from '../components/FilterBar'
import { TrafficTable } from '../components/TrafficTable'
import { useLiveTail } from '../hooks/useLiveTail'
import type { Filter, TrafficEvent } from '../api/types'

const MAX_LIVE_ROWS = 5000

function initialFilter(): Filter {
  const to = new Date()
  return {
    from: new Date(to.getTime() - 60 * 60_000).toISOString(),
    to: to.toISOString(),
    root: { op: 'and', conditions: [] },
    limit: 200,
  }
}

export function Traffic() {
  const [filter, setFilter] = useState<Filter>(initialFilter)
  const [events, setEvents] = useState<TrafficEvent[]>([])
  const [cursor, setCursor] = useState<string | undefined>()
  const [hasMore, setHasMore] = useState(false)
  const [loading, setLoading] = useState(false)
  const [selected, setSelected] = useState<string | undefined>()
  const [live, setLive] = useState(false)
  const [total, setTotal] = useState<{ count: number; capped: boolean }>()
  const [error, setError] = useState('')
  const requestId = useRef(0)

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
      .finally(() => id === requestId.current && setLoading(false))

    api
      .countTraffic(filter)
      .then((c) => id === requestId.current && setTotal({ count: c.count, capped: c.capped }))
      .catch(() => setTotal(undefined))
  }, [filter])

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
      />
      {error && <p className="error-msg" style={{ padding: '8px 16px' }}>{error}</p>}
      <TrafficTable
        events={events}
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
