import { useEffect, useRef, useState } from 'react'
import type { Filter, TrafficEvent } from '../api/types'

/**
 * useLiveTail streams matching events over a websocket. The server applies the
 * filter, so what arrives is already scoped to what the viewer may see.
 */
export function useLiveTail(enabled: boolean, filter: Filter, onEvent: (e: TrafficEvent) => void) {
  const [connected, setConnected] = useState(false)
  const handler = useRef(onEvent)
  handler.current = onEvent

  const serialized = JSON.stringify({ ...filter, cursor: undefined, limit: undefined })

  useEffect(() => {
    if (!enabled) {
      setConnected(false)
      return
    }
    const scheme = window.location.protocol === 'https:' ? 'wss' : 'ws'
    const url = `${scheme}://${window.location.host}/api/stream?filter=${encodeURIComponent(serialized)}`
    const socket = new WebSocket(url)

    socket.onopen = () => setConnected(true)
    socket.onclose = () => setConnected(false)
    socket.onerror = () => setConnected(false)
    socket.onmessage = (msg) => {
      try {
        handler.current(JSON.parse(msg.data) as TrafficEvent)
      } catch {
        // A malformed frame is dropped rather than breaking the stream.
      }
    }
    return () => socket.close()
  }, [enabled, serialized])

  return connected
}
