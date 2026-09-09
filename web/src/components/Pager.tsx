interface Props {
  page: number
  pageSize: number
  shown: number
  total?: { count: number; capped: boolean }
  hasMore: boolean
  loading: boolean
  onPrevious: () => void
  onNext: () => void
  onPageSize: (n: number) => void
}

const SIZES = [50, 100, 200, 500]

/** Pager steps through pages of traffic. Paging is keyset, so a later page
 *  costs the same as the first. */
export function Pager({
  page,
  pageSize,
  shown,
  total,
  hasMore,
  loading,
  onPrevious,
  onNext,
  onPageSize,
}: Props) {
  const first = page * pageSize + (shown > 0 ? 1 : 0)
  const last = page * pageSize + shown

  return (
    <div className="pager">
      <button className="btn btn-sm" onClick={onPrevious} disabled={page === 0 || loading}>
        ← Newer
      </button>
      <button className="btn btn-sm" onClick={onNext} disabled={!hasMore || loading}>
        Older →
      </button>

      <span className="muted mono">
        {shown > 0 ? `${first.toLocaleString()}–${last.toLocaleString()}` : 'nothing'}
        {total && (
          <> of {total.capped ? `${total.count.toLocaleString()}+` : total.count.toLocaleString()}</>
        )}
      </span>

      <span className="spacer" />

      <label className="row muted" style={{ gap: 6 }}>
        Rows
        <select
          className="select"
          style={{ width: 78 }}
          value={pageSize}
          onChange={(e) => onPageSize(Number(e.target.value))}
        >
          {SIZES.map((n) => (
            <option key={n} value={n}>
              {n}
            </option>
          ))}
        </select>
      </label>
    </div>
  )
}
