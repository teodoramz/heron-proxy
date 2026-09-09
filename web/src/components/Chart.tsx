import type { SeriesPoint } from '../api/types'

const CLASSES = [
  { key: 's2xx', color: 'var(--s2xx)', label: '2xx' },
  { key: 's3xx', color: 'var(--s3xx)', label: '3xx' },
  { key: 's4xx', color: 'var(--s4xx)', label: '4xx' },
  { key: 's5xx', color: 'var(--s5xx)', label: '5xx' },
] as const

/**
 * TrafficChart stacks requests by status class over time. Bars, not a line:
 * the composition of a spike is the point, not its smooth shape.
 */
export function TrafficChart({ points, height = 150 }: { points: SeriesPoint[]; height?: number }) {
  if (points.length === 0) return <p className="muted">No requests in this range.</p>

  const max = Math.max(...points.map((p) => p.requests), 1)
  const width = 100 / points.length

  return (
    <div>
      <svg
        viewBox={`0 0 100 ${height}`}
        preserveAspectRatio="none"
        style={{ width: '100%', height, display: 'block' }}
        role="img"
        aria-label="Requests over time by status class"
      >
        {points.map((p, i) => {
          let offset = 0
          return (
            <g key={p.bucket}>
              {CLASSES.map((c) => {
                const value = p[c.key]
                if (!value) return null
                const h = (value / max) * height
                const y = height - offset - h
                offset += h
                return (
                  <rect
                    key={c.key}
                    x={i * width + width * 0.1}
                    y={y}
                    width={width * 0.8}
                    height={h}
                    fill={c.color}
                  />
                )
              })}
              {p.would_block > 0 && (
                <rect
                  x={i * width + width * 0.1}
                  y={height - 2}
                  width={width * 0.8}
                  height={2}
                  fill="var(--block)"
                />
              )}
            </g>
          )
        })}
      </svg>
      <div className="row" style={{ gap: 14, marginTop: 8, fontSize: 12 }}>
        {CLASSES.map((c) => (
          <span key={c.key} className="row" style={{ gap: 5 }}>
            <span style={{ width: 9, height: 9, background: c.color, borderRadius: 2 }} />
            <span className="muted">{c.label}</span>
          </span>
        ))}
        <span className="row" style={{ gap: 5 }}>
          <span style={{ width: 9, height: 9, background: 'var(--block)', borderRadius: 2 }} />
          <span className="muted">suspicious</span>
        </span>
      </div>
    </div>
  )
}
