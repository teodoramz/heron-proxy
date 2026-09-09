import { describe, expect, it } from 'vitest'
import {
  PRESETS,
  activePreset,
  describe as describeCondition,
  fieldLabel,
  searchConditions,
} from './filterLabels'

describe('fieldLabel', () => {
  it('gives a plain name for a column', () => {
    expect(fieldLabel('client_ip')).toBe('Source address')
    expect(fieldLabel('would_block')).toBe('Flagged suspicious')
    expect(fieldLabel('rule_tag')).toBe('Attack type')
  })

  it('falls back to the raw name for anything unmapped', () => {
    expect(fieldLabel('something_new')).toBe('something_new')
  })
})

describe('describe', () => {
  it('reads as a sentence', () => {
    expect(describeCondition('status', 'gte', 400)).toBe('Response status is at least 400')
    expect(describeCondition('path', 'contains', '/admin')).toBe('Path contains /admin')
  })

  it('names the header for map fields', () => {
    expect(describeCondition('req_header', 'eq', 'application/json', 'content-type')).toBe(
      'Request header “content-type” is application/json',
    )
  })

  it('special-cases the suspicious flag, which reads badly as a comparison', () => {
    expect(describeCondition('would_block', 'eq', true)).toBe('Flagged suspicious')
    expect(describeCondition('would_block', 'eq', false)).toBe('Not flagged')
  })

  it('drops the value for presence checks', () => {
    expect(describeCondition('error', 'exists', undefined)).toBe('Error is present')
  })
})

describe('presets', () => {
  it('each has a distinct id and at least one condition', () => {
    const ids = new Set(PRESETS.map((p) => p.id))
    expect(ids.size).toBe(PRESETS.length)
    for (const p of PRESETS) {
      expect(p.conditions.length).toBeGreaterThan(0)
      expect(p.label).not.toBe('')
      expect(p.title).not.toBe('')
    }
  })
})

describe('searchConditions', () => {
  it('searches every field someone would expect', () => {
    const fields = searchConditions('admin').map((c) => c.field)
    expect(fields).toContain('path')
    expect(fields).toContain('body')
    expect(fields).toContain('user_agent')
    for (const c of searchConditions('admin')) {
      expect(c.op).toBe('contains')
      expect(c.value).toBe('admin')
    }
  })
})

describe('activePreset', () => {
  it('recognises the conditions a preset installed', () => {
    const suspicious = PRESETS.find((p) => p.id === 'suspicious')!
    expect(activePreset(suspicious.conditions)).toBe('suspicious')
  })

  it('recognises every preset by its own conditions', () => {
    for (const p of PRESETS) {
      expect(activePreset(p.conditions)).toBe(p.id)
    }
  })

  it('reports nothing for a filter built by hand', () => {
    expect(activePreset([{ field: 'path', op: 'contains', value: '/admin' }])).toBeNull()
    expect(activePreset([])).toBeNull()
  })

  it('does not match a preset that is only part of the filter', () => {
    const suspicious = PRESETS.find((p) => p.id === 'suspicious')!
    expect(
      activePreset([...suspicious.conditions, { field: 'status', op: 'gte', value: 500 }]),
    ).toBeNull()
  })
})
