import { describe, expect, it } from 'vitest'
import { resolveRange } from './client'
import type { Filter } from './types'

const base: Filter = { root: { op: 'and', conditions: [] } }

describe('resolveRange', () => {
  it('turns a relative window into from and to', () => {
    const out = resolveRange({ ...base, range: 60 })
    const span = new Date(out.to!).getTime() - new Date(out.from!).getTime()
    expect(span).toBe(60 * 60_000)
    expect(out).not.toHaveProperty('range')
  })

  it('slides, so the same filter covers a later window', async () => {
    const first = resolveRange({ ...base, range: 15 })
    await new Promise((r) => setTimeout(r, 5))
    const second = resolveRange({ ...base, range: 15 })
    expect(new Date(second.to!).getTime()).toBeGreaterThan(new Date(first.to!).getTime())
  })

  it('leaves an exact window alone', () => {
    const exact = { ...base, from: '2026-09-01T00:00:00.000Z', to: '2026-09-02T00:00:00.000Z' }
    expect(resolveRange(exact)).toEqual(exact)
  })
})
