import { Buffer } from 'node:buffer'
import { describe, expect, it } from 'vitest'
import { handleQuery, type Backend, type QueryResult, type ResolvedPolicy } from '../src/proxy/handler'
import { isSqlControlError, SqlState } from '../src/proxy/sqlstate'
import type { PermissionModel } from '../src/policy/model'

/** Decode a backend wire stream into typed messages for assertions. */
interface Message {
  type: string
  body: Buffer
}
function decode(bytes: Uint8Array): Message[] {
  const buf = Buffer.from(bytes)
  const out: Message[] = []
  let i = 0
  while (i < buf.length) {
    const type = String.fromCharCode(buf[i] ?? 0)
    const len = buf.readInt32BE(i + 1)
    out.push({ type, body: buf.subarray(i + 5, i + 1 + len) })
    i += 1 + len
  }
  return out
}
function types(messages: Message[]): string {
  return messages.map((m) => m.type).join('')
}
/** Parse ErrorResponse fields into { code, message }. */
function errorFields(body: Buffer): Record<string, string> {
  const fields: Record<string, string> = {}
  let i = 0
  while (i < body.length && body[i] !== 0) {
    const tag = String.fromCharCode(body[i] ?? 0)
    const end = body.indexOf(0, i + 1)
    fields[tag] = body.subarray(i + 1, end).toString('utf8')
    i = end + 1
  }
  return fields
}
/** Parse a DataRow into its text values. */
function dataRowValues(body: Buffer): (string | null)[] {
  const count = body.readInt16BE(0)
  const values: (string | null)[] = []
  let i = 2
  for (let c = 0; c < count; c++) {
    const len = body.readInt32BE(i)
    i += 4
    if (len === -1) {
      values.push(null)
    } else {
      values.push(body.subarray(i, i + len).toString('utf8'))
      i += len
    }
  }
  return values
}

const readPolicy: ResolvedPolicy = {
  model: { tables: { 'public.users': { select: { columns: ['id', 'email'] } } } },
}

describe('proxy query handler', () => {
  it('rewrites the SQL before it reaches the backend', async () => {
    let received = ''
    const backend: Backend = async (sql) => {
      received = sql
      return { fields: [{ name: 'id' }, { name: 'email' }], rows: [['1', 'a@x']], tag: 'SELECT 1' }
    }

    const messages = decode(await handleQuery('SELECT * FROM users', readPolicy, backend))
    expect(received).toMatch(/users\.id/)
    expect(received).toMatch(/users\.email/)
    expect(received).not.toContain('*')
    expect(types(messages)).toBe('TDCZ') // RowDescription, DataRow, CommandComplete, ReadyForQuery
    expect(dataRowValues(messages[1]!.body)).toEqual(['1', 'a@x'])
  })

  it('refuses a forbidden query without touching the backend', async () => {
    let called = false
    const backend: Backend = async () => {
      called = true
      return { fields: [], rows: [], tag: 'SELECT 0' }
    }

    const messages = decode(await handleQuery('SELECT password FROM users', readPolicy, backend))
    expect(called).toBe(false)
    expect(types(messages)).toBe('EZ')
    const err = errorFields(messages[0]!.body)
    // sql-control's own SQLSTATE class — a client can tell this from a DB error
    expect(err.C).toBe(SqlState.PolicyViolation)
    expect(isSqlControlError(err.C ?? '')).toBe(true)
    expect(err.M).toMatch(/password/)
  })

  it('surfaces a backend error with its real SQLSTATE (not an sql-control code)', async () => {
    const backend: Backend = async () => {
      const e: Error & { code?: string } = new Error('connection reset')
      e.code = '08006' // a genuine Postgres SQLSTATE
      throw e
    }
    const messages = decode(await handleQuery('SELECT id FROM users', readPolicy, backend))
    expect(types(messages)).toBe('EZ')
    const err = errorFields(messages[0]!.body)
    expect(err.C).toBe('08006')
    expect(isSqlControlError(err.C ?? '')).toBe(false)
    expect(err.M).toMatch(/connection reset/)
  })

  it('withholds the backend error MESSAGE when exposeBackendErrors=false, but keeps the SQLSTATE', async () => {
    // A raw NOT NULL violation names a hidden column the client has no rights to —
    // an info leak. With exposeBackendErrors off, the message is withheld while the
    // real SQLSTATE (23502) is preserved so the client can still classify the error.
    const backend: Backend = async () => {
      const e: Error & { code?: string } = new Error(
        'null value in column "internal_secret" of relation "orders" violates not-null constraint',
      )
      e.code = '23502' // not_null_violation
      throw e
    }
    const scrubbed: ResolvedPolicy = { ...readPolicy, exposeBackendErrors: false }
    const err = errorFields(decode(await handleQuery('SELECT id FROM users', scrubbed, backend))[0]!.body)
    expect(err.C).toBe('23502') // SQLSTATE class still surfaced
    expect(err.M).not.toContain('internal_secret') // hidden column name NOT leaked
    expect(err.M).toMatch(/withheld/)
    // Default (exposeBackendErrors unset) still forwards the full message.
    const exposed = errorFields(decode(await handleQuery('SELECT id FROM users', readPolicy, backend))[0]!.body)
    expect(exposed.M).toContain('internal_secret')
  })

  it('omits RowDescription for a command with no result set', async () => {
    const writePolicy: ResolvedPolicy = {
      model: { tables: { 'public.t': { update: { columns: ['x'] } } } },
    }
    const backend: Backend = async () => ({ fields: [], rows: [], tag: 'UPDATE 1' })
    const messages = decode(await handleQuery('UPDATE t SET x = 1', writePolicy, backend))
    expect(types(messages)).toBe('CZ')
    expect(messages[0]!.body.toString('utf8')).toContain('UPDATE 1')
  })
})
