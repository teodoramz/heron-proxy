import { useEffect, useRef, useState } from 'react'
import { COLUMNS, DEFAULT_COLUMNS } from './columns'

interface Props {
  selected: string[]
  onChange: (ids: string[]) => void
}

/** ColumnPicker chooses which fields the traffic table shows, in table order. */
export function ColumnPicker({ selected, onChange }: Props) {
  const [open, setOpen] = useState(false)
  const box = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!open) return
    const away = (e: MouseEvent) => {
      if (box.current && !box.current.contains(e.target as Node)) setOpen(false)
    }
    const esc = (e: KeyboardEvent) => e.key === 'Escape' && setOpen(false)
    document.addEventListener('mousedown', away)
    document.addEventListener('keydown', esc)
    return () => {
      document.removeEventListener('mousedown', away)
      document.removeEventListener('keydown', esc)
    }
  }, [open])

  function toggle(id: string) {
    onChange(
      selected.includes(id)
        ? selected.filter((c) => c !== id)
        : // Keep the canonical order so the table stays readable.
          COLUMNS.filter((c) => c.id === id || selected.includes(c.id)).map((c) => c.id),
    )
  }

  return (
    <div className="picker" ref={box}>
      <button
        type="button"
        className="btn btn-sm"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
      >
        Columns ({selected.length})
      </button>

      {open && (
        <div className="picker-menu" role="group" aria-label="Table columns">
          <div className="picker-head">
            <span className="muted">Shown in table order</span>
            <button className="btn btn-sm" onClick={() => onChange(DEFAULT_COLUMNS)}>
              Reset
            </button>
          </div>
          <div className="picker-list">
            {COLUMNS.map((c) => (
              <label key={c.id} className="picker-item">
                <input
                  type="checkbox"
                  checked={selected.includes(c.id)}
                  onChange={() => toggle(c.id)}
                />
                {c.label}
              </label>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
