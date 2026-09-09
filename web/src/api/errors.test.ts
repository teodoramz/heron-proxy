import { describe, expect, it } from 'vitest'
import { humanize } from './errors'

describe('humanize', () => {
  it('explains an unknown field and names it', () => {
    const out = humanize('query: unknown field "passwrd"')
    expect(out).toContain('passwrd')
    expect(out).toContain('Pick a field')
  })

  it('explains a bad address range', () => {
    const out = humanize('query: invalid CIDR "yesterday": bad prefix')
    expect(out).toContain('203.0.113.0/24')
  })

  it('explains a date that is not a date', () => {
    expect(humanize('cannot parse "soon" as DateTime')).toContain('date picker')
  })

  it('explains an operator that does not fit', () => {
    expect(humanize('query: operator "regex" not allowed on field "status"')).toContain(
      'does not work on this field',
    )
  })

  it('explains an expired session', () => {
    expect(humanize('csrf token mismatch')).toContain('Reload the page')
  })

  it('passes an unrecognised message through rather than hiding it', () => {
    expect(humanize('something nobody predicted')).toBe('something nobody predicted')
  })
})

describe('humanize, regex', () => {
  it('explains an invalid pattern and keeps the detail', () => {
    const out = humanize('query: invalid regular expression: error parsing regexp: missing closing ): `(unclosed`')
    expect(out).toContain('not valid')
    expect(out).toContain('missing closing')
  })
})
