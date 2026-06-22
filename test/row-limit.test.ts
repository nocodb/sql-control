import { Buffer } from 'node:buffer'
import { describe, expect, it } from 'vitest'
import { analyze } from '../src/analyzer/index'
import { handleQuery, type Backend, type ResolvedPolicy } from '../src/proxy/handler'
import type { PermissionModel } from '../src/policy/model'

/**
 * Result-size guard (memory-DoS). A SELECT is capped with a top-level
 * `LIMIT maxRows + 1` — ORDER BY preserved, an existing limit honored/clamped — and
 * a result that still exceeds `maxRows` is refused *loud* (SQLSTATE 54000), never
 * silently truncated.
 */
const model: PermissionModel = { tables: { 'public.t': { select: true } } }
const sqlFor = async (sql: string, maxRows = 1000): Promise<string> => {
  const d = await analyze(sql, { model, context: { ctx: {} }, maxRows })
  return d.allow ? d.sql.replace(/\s+/g, ' ') : `deny`
}

describe('row-limit injection', () => {
  it('adds a top-level LIMIT to an unbounded SELECT', async () => {
    expect(await sqlFor('SELECT * FROM t')).toMatch(/LIMIT 1001$/)
  })
  it('preserves ORDER BY (limit at the query level, not a wrapper)', async () => {
    expect(await sqlFor('SELECT a FROM t ORDER BY a')).toMatch(/ORDER BY a LIMIT 1001$/)
  })
  it('keeps a smaller existing limit and clamps a larger one (no bypass)', async () => {
    expect(await sqlFor('SELECT a FROM t LIMIT 5')).toMatch(/LIMIT 5$/)
    expect(await sqlFor('SELECT a FROM t LIMIT 999999')).toMatch(/LIMIT 1001$/)
  })
  it('caps a set-operation at the top level', async () => {
    expect(await sqlFor('SELECT a FROM t UNION SELECT a FROM t')).toMatch(/LIMIT 1001$/)
  })
  it('does not touch a statement without maxRows configured', async () => {
    const d = await analyze('SELECT * FROM t', { model, context: { ctx: {} } })
    expect(d.allow && d.sql).not.toMatch(/LIMIT/)
  })
})

// Decode the wire bytes enough to read the message-type stream and an error code.
function decode(bytes: Uint8Array): { types: string; errorCode?: string } {
  const buf = Buffer.from(bytes)
  let i = 0
  let types = ''
  let errorCode: string | undefined
  while (i < buf.length) {
    const type = String.fromCharCode(buf[i] ?? 0)
    const len = buf.readInt32BE(i + 1)
    types += type
    if (type === 'E') {
      const body = buf.subarray(i + 5, i + 1 + len)
      let j = 0
      while (j < body.length && body[j] !== 0) {
        const tag = String.fromCharCode(body[j] ?? 0)
        const end = body.indexOf(0, j + 1)
        if (tag === 'C') errorCode = body.subarray(j + 1, end).toString('utf8')
        j = end + 1
      }
    }
    i += 1 + len
  }
  return { types, errorCode }
}

describe('row-limit enforcement at the handler (loud, not silent)', () => {
  const policy: ResolvedPolicy = { model, maxRows: 2 }
  it('refuses an over-cap result with SQLSTATE 54000', async () => {
    // backend returns maxRows+1 rows (the cap+1 the injected LIMIT allows through)
    const backend: Backend = async () => ({ fields: [{ name: 'a' }], rows: [['1'], ['2'], ['3']], tag: 'SELECT 3' })
    const out = decode(await handleQuery('SELECT * FROM t', policy, backend))
    expect(out.types).toBe('EZ') // ErrorResponse + ReadyForQuery, no DataRows
    expect(out.errorCode).toBe('54000')
  })
  it('returns a result that is within the cap', async () => {
    const backend: Backend = async () => ({ fields: [{ name: 'a' }], rows: [['1'], ['2']], tag: 'SELECT 2' })
    const out = decode(await handleQuery('SELECT * FROM t', policy, backend))
    expect(out.types).toBe('TDDCZ') // RowDescription, 2×DataRow, CommandComplete, ReadyForQuery
    expect(out.errorCode).toBeUndefined()
  })
})
