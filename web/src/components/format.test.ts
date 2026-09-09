import { describe, expect, it } from 'vitest'
import { anomalyLevel, bytes, count, duration, statusClass } from './format'

describe('statusClass', () => {
  it('maps each response class to its own hue', () => {
    expect(statusClass(200)).toBe('status-2xx')
    expect(statusClass(301)).toBe('status-3xx')
    expect(statusClass(404)).toBe('status-4xx')
    expect(statusClass(503)).toBe('status-5xx')
  })

  it('dims a request with no response', () => {
    expect(statusClass(0)).toBe('cell-dim')
  })
})

describe('anomalyLevel', () => {
  it('rises with the score', () => {
    expect(anomalyLevel(0)).toBe(0)
    expect(anomalyLevel(3)).toBe(1)
    expect(anomalyLevel(5)).toBe(2)
    expect(anomalyLevel(12)).toBe(3)
    expect(anomalyLevel(40)).toBe(4)
  })

  it('never exceeds the top level', () => {
    expect(anomalyLevel(100000)).toBe(4)
  })
})

describe('bytes', () => {
  it('scales units', () => {
    expect(bytes(512)).toBe('512 B')
    expect(bytes(2048)).toBe('2.0 kB')
    expect(bytes(5 * 1024 * 1024)).toBe('5.0 MB')
  })
})

describe('duration', () => {
  it('switches to seconds past a thousand milliseconds', () => {
    expect(duration(250)).toBe('250 ms')
    expect(duration(1500)).toBe('1.50 s')
  })
})

describe('count', () => {
  it('groups thousands', () => {
    expect(count(1234567)).toBe('1,234,567')
  })
})
