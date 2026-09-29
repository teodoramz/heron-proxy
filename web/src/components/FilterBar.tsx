import { useEffect, useMemo, useState } from 'react'
import { api } from '../api/client'
import { ColumnPicker } from './ColumnPicker'
import { TimeRange } from './TimeRange'
import type { WidthMode } from './columns'
import {
  COMMON_FIELDS,
  EXAMPLES,
  FIELD_HELP,
  OP_HELP,
  OP_LABELS,
  PRESETS,
  activePreset,
  describe,
  fieldLabel,
  searchConditions,
} from './filterLabels'
import type { Condition, FieldSchema, Filter, Group, Op } from '../api/types'

interface Props {
  filter: Filter
  onChange: (f: Filter) => void
  live: boolean
  liveConnected: boolean
  onToggleLive: () => void
  columns: string[]
  onColumnsChange: (ids: string[]) => void
  widthMode: WidthMode
  onToggleWidthMode: () => void
  autoRefresh: boolean
  onToggleAutoRefresh: () => void
  onRefresh: () => void
  loading: boolean
  lastLoaded?: Date
}

/**
 * FilterBar is the whole query surface. A plain search box and one-click
 * presets cover the common questions; the condition builder underneath is for
 * everything else, and speaks in labels rather than column names.
 */
export function FilterBar({
  filter,
  onChange,
  live,
  liveConnected,
  onToggleLive,
  columns,
  onColumnsChange,
  widthMode,
  onToggleWidthMode,
  autoRefresh,
  onToggleAutoRefresh,
  onRefresh,
  loading,
  lastLoaded,
}: Props) {
  const [schema, setSchema] = useState<FieldSchema[]>([])
  const [attackTypes, setAttackTypes] = useState<string[]>([])
  const [advanced, setAdvanced] = useState(() => localStorage.getItem('pw-builder') !== 'closed')
  const [help, setHelp] = useState(false)
  const [search, setSearch] = useState('')

  const [field, setField] = useState('path')
  const [op, setOp] = useState<Op>('contains')
  const [value, setValue] = useState('')
  const [key, setKey] = useState('')
  const [problem, setProblem] = useState('')

  useEffect(() => {
    api.schema().then((s) => setSchema(s.fields)).catch(() => setSchema([]))
    api.ruleFacets().then((f) => setAttackTypes(f.tags)).catch(() => setAttackTypes([]))
  }, [])

  const current = schema.find((f) => f.field === field)
  const conditions = filter.root.conditions ?? []
  const groups = filter.root.groups ?? []

  // Common fields first, then the rest by their plain-language name.
  const ordered = useMemo(() => {
    const rest = schema
      .filter((f) => !COMMON_FIELDS.includes(f.field) && f.field !== 'ts' && f.field !== 'id')
      .sort((a, b) => fieldLabel(a.field).localeCompare(fieldLabel(b.field)))
    const common = COMMON_FIELDS.map((id) => schema.find((f) => f.field === id)).filter(
      Boolean,
    ) as FieldSchema[]
    return { common, rest }
  }, [schema])

  const join: 'and' | 'or' = filter.root.op === 'or' ? 'or' : 'and'

  function apply(next: Partial<Group>) {
    onChange({ ...filter, cursor: undefined, root: { ...filter.root, op: join, ...next } })
  }

  /** setJoin switches between requiring every condition and any one of them. */
  function setJoin(op: 'and' | 'or') {
    onChange({ ...filter, cursor: undefined, root: { ...filter.root, op } })
  }

  function runSearch(e: React.FormEvent) {
    e.preventDefault()
    const text = search.trim()
    if (!text) {
      apply({ groups: groups.filter((g) => !g.conditions?.some((c) => c.field === 'path' && c.op === 'contains')) })
      return
    }
    // One OR group, replaced each time, so searching again does not stack up.
    const others = groups.filter((g) => g.op !== 'or')
    apply({ groups: [...others, { op: 'or', conditions: searchConditions(text) }] })
  }

  // A preset replaces the filter rather than adding to it, so clicking two in
  // a row shows the second rather than the impossible intersection of both.
  // Clicking the one already in effect clears it.
  function choosePreset(id: string) {
    const preset = PRESETS.find((p) => p.id === id)
    if (!preset) return
    if (active === id) {
      apply({ conditions: [], groups: [] })
      return
    }
    setSearch('')
    apply({ conditions: preset.conditions as Condition[], groups: [] })
  }

  function addCondition(e: React.FormEvent) {
    e.preventDefault()
    setProblem('')

    if (current?.needs_key && !key.trim()) {
      setProblem(`Give the ${fieldLabel(field).toLowerCase()} a name, for example content-type.`)
      return
    }
    if (op !== 'exists' && value.trim() === '') {
      setProblem('Enter a value to compare against.')
      return
    }
    const parsed = coerce(value, current?.kind, op)
    if (parsed === INVALID) {
      setProblem(problemFor(current?.kind, value))
      return
    }

    const cond: Condition = { field, op, value: op === 'exists' ? undefined : parsed }
    if (current?.needs_key) cond.key = key.trim()
    apply({ conditions: [...conditions, cond] })
    setValue('')
  }

  function removeCondition(index: number) {
    apply({ conditions: conditions.filter((_, i) => i !== index) })
  }

  function clearAll() {
    setSearch('')
    apply({ conditions: [], groups: [] })
  }

  const searchGroup = groups.find((g) => g.op === 'or')
  const activeCount = conditions.length + (searchGroup ? 1 : 0)
  const active = activePreset(conditions)

  return (
    <div className="filters">
      <form className="filter-row" onSubmit={runSearch}>
        <input
          className="input"
          style={{ maxWidth: 300 }}
          placeholder="Search paths, bodies, user agents…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          aria-label="Search traffic"
        />
        <button className="btn btn-sm" type="submit">
          Search
        </button>

        <span className="divider" />

        <TimeRange filter={filter} onChange={onChange} />

        <span className="spacer" />

        <button type="button" className="btn btn-sm" onClick={onRefresh} disabled={loading}>
          {loading ? 'Loading…' : 'Refresh'}
        </button>
        <button
          type="button"
          className="btn btn-sm"
          onClick={onToggleAutoRefresh}
          aria-pressed={autoRefresh}
          disabled={live}
          title={live ? 'Live tail is already streaming' : 'Reload every 2 seconds'}
        >
          Auto {autoRefresh && !live ? 'on' : 'off'}
        </button>
        <button
          type="button"
          className="btn btn-sm"
          onClick={onToggleLive}
          aria-pressed={live}
          title={live ? 'Stop streaming new requests' : 'Stream new requests as they arrive'}
        >
          <span className={`live-dot ${live ? (liveConnected ? 'on' : 'pending') : ''}`} />{' '}
          {live ? (liveConnected ? 'Live' : 'Connecting') : 'Live'}
        </button>
        <button
          type="button"
          className="btn btn-sm"
          onClick={onToggleWidthMode}
          aria-pressed={widthMode === 'full'}
          title={
            widthMode === 'fit'
              ? 'Let columns take the width their content needs'
              : 'Squeeze every column into the window'
          }
        >
          {widthMode === 'fit' ? 'Fit width' : 'Full width'}
        </button>
        <ColumnPicker selected={columns} onChange={onColumnsChange} />
      </form>

      <div className="filter-row">
        <span className="muted">Show only</span>
        {PRESETS.map((p) => (
          <button
            key={p.id}
            type="button"
            className="btn btn-sm"
            aria-pressed={active === p.id}
            title={active === p.id ? `${p.title} — click again to clear` : p.title}
            onClick={() => choosePreset(p.id)}
          >
            {p.label}
          </button>
        ))}
        <span className="spacer" />
        <button
          type="button"
          className="btn btn-sm"
          aria-pressed={advanced}
          onClick={() => {
            setAdvanced((v) => {
              localStorage.setItem('pw-builder', v ? 'closed' : 'open')
              return !v
            })
          }}
        >
          {advanced ? 'Hide builder' : 'Build a filter'}
        </button>
        <button
          type="button"
          className="btn btn-sm"
          aria-pressed={help}
          onClick={() => setHelp((v) => !v)}
          title="What the fields and comparisons mean"
        >
          Help
        </button>
      </div>

      {advanced && (
        <form className="filter-row" onSubmit={addCondition}>
          <select
            className="select"
            style={{ width: 190 }}
            value={field}
            onChange={(e) => {
              setField(e.target.value)
              setProblem('')
              setValue('')
              const next = schema.find((f) => f.field === e.target.value)
              if (next && !next.operators.includes(op)) setOp(next.operators[0])
            }}
            aria-label="What to filter on"
          >
            <optgroup label="Common">
              {ordered.common.map((f) => (
                <option key={f.field} value={f.field}>
                  {fieldLabel(f.field)}
                </option>
              ))}
            </optgroup>
            <optgroup label="Everything else">
              {ordered.rest.map((f) => (
                <option key={f.field} value={f.field}>
                  {fieldLabel(f.field)}
                </option>
              ))}
            </optgroup>
          </select>

          <select
            className="select"
            style={{ width: 150 }}
            value={op}
            onChange={(e) => setOp(e.target.value as Op)}
            aria-label="How to compare"
          >
            {(current?.operators ?? ['eq']).map((o) => (
              <option key={o} value={o}>
                {OP_LABELS[o] ?? o}
              </option>
            ))}
          </select>

          {current?.needs_key && (
            <input
              className="input"
              style={{ width: 150 }}
              placeholder="header name"
              value={key}
              onChange={(e) => setKey(e.target.value)}
              aria-label="Header name"
            />
          )}

          {op !== 'exists' && (
            <ValueInput
              kind={current?.kind}
              field={field}
              op={op}
              value={value}
              onChange={setValue}
              attackTypes={attackTypes}
            />
          )}

          <button className="btn" type="submit">
            Add
          </button>
          {problem && <span className="error-msg" style={{ margin: 0 }}>{problem}</span>}
        </form>
      )}

      {advanced && !problem && (
        <p className="filter-hint">
          <strong>{fieldLabel(field)}</strong> — {FIELD_HELP[field]?.what ?? 'One of the recorded fields.'}{' '}
          <span className="muted">{OP_HELP[op]}</span>
          {op === 'regex' ? (
            <>
              {' '}
              <button type="button" className="linkish" onClick={() => setValue('^/api/v\\d+/')}>
                Try ^/api/v\d+/
              </button>
            </>
          ) : (
            FIELD_HELP[field]?.example && (
              <>
                {' '}
                <button
                  type="button"
                  className="linkish"
                  onClick={() => setValue(FIELD_HELP[field].example)}
                  title="Fill this in"
                >
                  Try {FIELD_HELP[field].example}
                </button>
              </>
            )
          )}
        </p>
      )}

      {help && <HelpPanel onClose={() => setHelp(false)} />}

      {(activeCount > 0 || lastLoaded) && (
        <div className="filter-row">
          {searchGroup && (
            <span className="chip">
              contains “{search || (searchGroup.conditions?.[0]?.value as string)}”
              <button
                type="button"
                onClick={() => {
                  setSearch('')
                  apply({ groups: groups.filter((g) => g !== searchGroup) })
                }}
                aria-label="Remove search"
              >
                ×
              </button>
            </span>
          )}
          {conditions.map((c, i) => (
            <span className="chip" key={`${c.field}-${i}`}>
              {describe(c.field, c.op, c.value, c.key)}
              <button type="button" onClick={() => removeCondition(i)} aria-label="Remove filter">
                ×
              </button>
            </span>
          ))}
          {activeCount > 1 && (
            <>
              <span className="chip-join" role="group" aria-label="How the conditions combine">
                <button
                  type="button"
                  className="btn btn-sm"
                  aria-pressed={join === 'and'}
                  title="A request has to match every condition"
                  onClick={() => setJoin('and')}
                >
                  match all
                </button>
                <button
                  type="button"
                  className="btn btn-sm"
                  aria-pressed={join === 'or'}
                  title="A request matching any one condition is enough"
                  onClick={() => setJoin('or')}
                >
                  match any
                </button>
              </span>
              <button className="btn btn-sm" onClick={clearAll}>
                Clear all
              </button>
            </>
          )}
          <span className="spacer" />
          {lastLoaded && (
            <span className="muted mono" title="When the table last reloaded">
              updated {lastLoaded.toLocaleTimeString('en-GB', { hour12: false })}
            </span>
          )}
        </div>
      )}
    </div>
  )
}

/** HelpPanel explains the vocabulary, and answers the questions people arrive with. */
function HelpPanel({ onClose }: { onClose: () => void }) {
  return (
    <div className="help-panel">
      <div className="help-head">
        <strong>Building a filter</strong>
        <button className="btn btn-sm" onClick={onClose}>
          Close
        </button>
      </div>

      <div className="help-body">
        <p className="hint" style={{ marginTop: 0 }}>
          A filter is one or more conditions. Pick what to look at, how to compare it, and the
          value. With more than one, <strong>match all</strong> requires every condition and{' '}
          <strong>match any</strong> accepts a request that meets just one. Choosing{' '}
          <strong>is one of</strong> lets a single condition take several values, and{' '}
          <strong>matches regex</strong> takes a pattern. The buttons above are shortcuts for the
          common ones.
        </p>

        <h4>Questions people ask</h4>
        <table className="data">
          <tbody>
            {EXAMPLES.map((e) => (
              <tr key={e.question}>
                <td style={{ width: '38%' }}>{e.question}</td>
                <td className="muted">{e.how}</td>
              </tr>
            ))}
          </tbody>
        </table>

        <h4>What the comparisons do</h4>
        <table className="data">
          <tbody>
            {(Object.keys(OP_LABELS) as (keyof typeof OP_LABELS)[]).map((op) => (
              <tr key={op}>
                <td style={{ width: 150 }}>{OP_LABELS[op]}</td>
                <td className="muted">{OP_HELP[op]}</td>
              </tr>
            ))}
          </tbody>
        </table>

        <p className="hint">
          Scores and rules: a request accumulates an <strong>anomaly score</strong> as rules match.
          Passing the application’s threshold marks it <strong>suspicious</strong> — that is a
          prompt to look, not a verdict. Rule numbers can be looked up on the Rules page.
        </p>
      </div>
    </div>
  )
}

/** ValueInput matches the control to the kind of value the field holds. */
function ValueInput({
  kind,
  field,
  op,
  value,
  onChange,
  attackTypes,
}: {
  kind?: string
  field: string
  op: Op
  value: string
  onChange: (v: string) => void
  attackTypes: string[]
}) {
  // Before any of the per-field pickers: choosing "matches regex" has to give a
  // box you can type a pattern into, whatever the field normally offers.
  if (op === 'regex') {
    return (
      <input
        className="input mono"
        style={{ width: 260 }}
        placeholder="^/api/v\\d+/"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        aria-label="Regular expression"
        spellCheck={false}
      />
    )
  }

  const choices = field === 'method' ? METHODS : field === 'rule_tag' ? attackTypes : null
  if (choices && choices.length > 0) {
    const label = (c: string) => (field === 'rule_tag' ? c.replace('attack-', '') : c)
    // "is one of" takes several at once; the rest take exactly one.
    if (op === 'in') {
      return <PickMany choices={choices} label={label} value={value} onChange={onChange} />
    }
    return (
      <select
        className="select"
        style={{ width: field === 'method' ? 140 : 200 }}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        aria-label={field === 'method' ? 'Method' : 'Attack type'}
      >
        <option value="">Choose one</option>
        {choices.map((c) => (
          <option key={c} value={c}>
            {label(c)}
          </option>
        ))}
      </select>
    )
  }
  if (kind === 'boolean') {
    return (
      <select className="select" style={{ width: 120 }} value={value} onChange={(e) => onChange(e.target.value)} aria-label="Yes or no">
        <option value="">Choose one</option>
        <option value="true">Yes</option>
        <option value="false">No</option>
      </select>
    )
  }
  if (kind === 'number') {
    return (
      <input
        className="input"
        style={{ width: 140 }}
        type="number"
        placeholder="a number"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        aria-label="Value"
      />
    )
  }
  if (kind === 'datetime') {
    return (
      <input
        className="input"
        style={{ width: 220 }}
        type="datetime-local"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        aria-label="Date and time"
      />
    )
  }
  return (
    <input
      className="input"
      style={{ width: 230 }}
      placeholder={
        op === 'in'
          ? 'several, separated by commas'
          : kind === 'ip'
            ? '203.0.113.9 or 203.0.113.0/24'
            : 'value'
      }
      value={value}
      onChange={(e) => onChange(e.target.value)}
      aria-label="Value"
    />
  )
}

/** INVALID marks a value the field cannot accept, so the form can say why. */
const INVALID = Symbol('invalid')

function coerce(raw: string, kind?: string, op?: Op): unknown {
  const text = raw.trim()
  // "is one of" is a list, however it was typed or ticked.
  if (op === 'in') {
    const parts = text
      .split(',')
      .map((v) => v.trim())
      .filter(Boolean)
    if (parts.length === 0) return INVALID
    if (kind === 'number' || kind === 'number_array') {
      const nums = parts.map(Number)
      return nums.every(Number.isFinite) ? nums : INVALID
    }
    return parts
  }
  switch (kind) {
    case 'number':
    case 'number_array': {
      const n = Number(text)
      return Number.isFinite(n) ? n : INVALID
    }
    case 'boolean':
      if (text === 'true') return true
      if (text === 'false') return false
      return INVALID
    case 'datetime': {
      const d = new Date(text)
      return Number.isNaN(d.getTime()) ? INVALID : d.toISOString()
    }
    default:
      return text
  }
}

function problemFor(kind: string | undefined, value: string): string {
  switch (kind) {
    case 'number':
    case 'number_array':
      return `“${value}” is not a number. Enter digits only, such as 404.`
    case 'datetime':
      return `“${value}” is not a date. Use the date picker, or a date like 2026-09-09 14:30.`
    case 'boolean':
      return 'Choose yes or no.'
    default:
      return `“${value}” cannot be used here.`
  }
}

const METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']

/** PickMany ticks off several values for an "is one of" condition. */
function PickMany({
  choices,
  label,
  value,
  onChange,
}: {
  choices: string[]
  label: (c: string) => string
  value: string
  onChange: (v: string) => void
}) {
  const chosen = value
    .split(',')
    .map((v) => v.trim())
    .filter(Boolean)

  function toggle(c: string) {
    const next = chosen.includes(c) ? chosen.filter((v) => v !== c) : [...chosen, c]
    onChange(next.join(', '))
  }

  return (
    <div className="pick-many" role="group" aria-label="Choose one or more">
      {choices.map((c) => (
        <button
          key={c}
          type="button"
          className="btn btn-sm"
          aria-pressed={chosen.includes(c)}
          onClick={() => toggle(c)}
        >
          {label(c)}
        </button>
      ))}
    </div>
  )
}
