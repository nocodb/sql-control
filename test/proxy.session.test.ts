import { Buffer } from 'node:buffer'
import { describe, expect, it } from 'vitest'
import { ProxySession } from '../src/proxy/session'
import type { Backend, QueryResult, ResolvedPolicy } from '../src/proxy/handler'
import { SqlState } from '../src/proxy/sqlstate'

/**
 * Extended-protocol (Parse/Bind/Describe/Execute/Sync) coverage, driving
 * {@link ProxySession} directly with hand-built frontend frames. Asserts the
 * named-prepared-statement flow, authorization-at-Parse with skip-until-Sync, and
 * that malformed frames produce a protocol ErrorResponse rather than throwing.
 */

// ---- frontend frame encoders -------------------------------------------------
const i16 = (n: number): Buffer => {
  const b = Buffer.alloc(2)
  b.writeInt16BE(n)
  return b
}
const i32 = (n: number): Buffer => {
  const b = Buffer.alloc(4)
  b.writeInt32BE(n)
  return b
}
const cstr = (s: string): Buffer => Buffer.concat([Buffer.from(s, 'utf8'), Buffer.from([0])])
const frame = (type: string, body: Buffer): Buffer =>
  Buffer.concat([Buffer.from(type, 'ascii'), i32(body.length + 4), body])

const parseMsg = (name: string, sql: string): Buffer =>
  frame('P', Buffer.concat([cstr(name), cstr(sql), i16(0)]))
const bindMsg = (portal: string, stmt: string, params: (string | null)[]): Buffer => {
  const parts = [cstr(portal), cstr(stmt), i16(0), i16(params.length)]
  for (const p of params) {
    parts.push(p === null ? i32(-1) : Buffer.concat([i32(Buffer.byteLength(p)), Buffer.from(p, 'utf8')]))
  }
  parts.push(i16(0)) // result column formats
  return frame('B', Buffer.concat(parts))
}
const executeMsg = (portal: string): Buffer => frame('E', Buffer.concat([cstr(portal), i32(0)]))
const syncMsg = (): Buffer => frame('S', Buffer.alloc(0))
const closeMsg = (kind: 'S' | 'P', name: string): Buffer =>
  frame('C', Buffer.concat([Buffer.from(kind, 'ascii'), cstr(name)]))

// ---- backend message decoders ------------------------------------------------
interface Message {
  type: string
  body: Buffer
}
function decode(bytes: Uint8Array | undefined): Message[] {
  const buf = Buffer.from(bytes ?? new Uint8Array(0))
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
const types = (messages: Message[]): string => messages.map((m) => m.type).join('')
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

const policy: ResolvedPolicy = {
  model: { tables: { 'public.users': { select: { columns: ['id', 'email'] } } } },
}
const okBackend: Backend = async () => ({ fields: [], rows: [], tag: 'SELECT 0' })

/** Drain a session reply — a buffered Uint8Array or a streaming AsyncIterable. */
async function reply(
  p: Promise<Uint8Array | AsyncIterable<Uint8Array> | undefined>,
): Promise<Uint8Array | undefined> {
  const r = await p
  if (r === undefined || r instanceof Uint8Array) return r
  const chunks: Uint8Array[] = []
  for await (const c of r) chunks.push(c)
  return Buffer.concat(chunks)
}
const session = (backend: Backend, p: ResolvedPolicy | null = policy) => {
  const s = new ProxySession(() => p, backend)
  return { handle: (msg: Uint8Array) => reply(s.handle(msg)) }
}

describe('proxy extended protocol (ProxySession)', () => {
  it('named prepared statement: Parse → Bind → Execute runs the rewritten SQL with params', async () => {
    let received: { sql?: string; params?: readonly (string | null)[] } = {}
    const backend: Backend = async (sql, params) => {
      received = { sql, params }
      return { fields: [{ name: 'id' }], rows: [['1']], tag: 'SELECT 1' }
    }
    const s = session(backend)
    expect(types(decode(await s.handle(parseMsg('s', 'SELECT * FROM users WHERE id = $1'))))).toBe('1')
    expect(types(decode(await s.handle(bindMsg('', 's', ['7']))))).toBe('2')
    const exec = decode(await s.handle(executeMsg('')))
    expect(types(exec)).toBe('TDC') // RowDescription, DataRow, CommandComplete
    expect(received.sql).toMatch(/users\.id/) // `*` was expanded before reaching the backend
    expect(received.sql).not.toContain('*')
    expect(received.params).toEqual(['7'])
  })

  it('refuses the legacy fast-path FunctionCall ("F") without executing it (analyzer bypass)', async () => {
    let called = false
    const backend: Backend = async () => {
      called = true
      return { fields: [], rows: [], tag: 'SELECT 0' }
    }
    const s = session(backend)
    // 'F' body: function OID, arg-format-count, arg-count, result-format. This is the
    // legacy fast-path that invokes a function by OID with NO SQL — it would bypass
    // authorization, RLS and the function denylist entirely. The proxy refuses it
    // outright (body irrelevant); here it "calls" the function at OID 16384.
    const fnCall = frame('F', Buffer.concat([i32(16384), i16(0), i16(0), i16(0)]))
    const msgs = decode(await s.handle(fnCall))
    expect(types(msgs)).toBe('EZ') // ErrorResponse + ReadyForQuery
    expect(errorFields(msgs[0]?.body ?? Buffer.alloc(0)).C).toBe(SqlState.PolicyViolation) // SC001 — our refusal
    expect(called).toBe(false) // the function was NEVER executed against the backend
  })

  it('truncates a simple Query at its NUL terminator — post-NUL bytes are never analyzed or forwarded', async () => {
    // A client could append SQL after the cstring NUL hoping the proxy forwards the
    // raw bytes. It doesn't: onQuery reads ONE cstring (stops at the NUL), and the
    // backend gets the re-deparsed AST — not the original bytes — so the injected
    // `; DROP TABLE users` after the terminator never reaches analysis or the backend.
    let backendSql: string | undefined
    const backend: Backend = async (sql) => {
      backendSql = sql
      return { fields: [], rows: [], tag: 'SELECT 0' }
    }
    const s = session(backend)
    const body = Buffer.concat([
      Buffer.from('SELECT id FROM users', 'utf8'),
      Buffer.from([0]), // cstring terminator
      Buffer.from('; DROP TABLE users', 'utf8'), // smuggled bytes after the NUL
    ])
    const msgs = decode(await s.handle(frame('Q', body)))
    expect(types(msgs)).toBe('CZ') // CommandComplete + ReadyForQuery — only the SELECT ran
    expect(backendSql).toBe('SELECT id FROM public.users') // re-deparsed AST, post-NUL bytes dropped
    expect(backendSql).not.toContain('DROP')
  })

  it('authorizes at Parse: a forbidden statement is refused with the SC SQLSTATE and skips until Sync', async () => {
    let called = false
    const backend: Backend = async () => {
      called = true
      return okBackend('', undefined)
    }
    const s = session(backend)
    const parse = decode(await s.handle(parseMsg('s', 'SELECT password FROM users')))
    expect(parse[0]?.type).toBe('E')
    expect(errorFields(parse[0]!.body).C).toBe(SqlState.PolicyViolation)
    // everything until Sync is ignored (no BindComplete, no backend call)
    expect((await s.handle(bindMsg('', 's', [])))?.length ?? 0).toBe(0)
    expect((await s.handle(executeMsg('')))?.length ?? 0).toBe(0)
    expect(called).toBe(false)
    expect(types(decode(await s.handle(syncMsg())))).toBe('Z') // ReadyForQuery
  })

  it('a malformed Bind (param count overruns the buffer) returns a protocol error, not a throw', async () => {
    const s = session(okBackend)
    await s.handle(parseMsg('s', 'SELECT id FROM users'))
    // claims 2 parameters but carries no parameter bytes
    const malformed = frame('B', Buffer.concat([cstr(''), cstr('s'), i16(0), i16(2)]))
    const reply = decode(await s.handle(malformed)) // must resolve, not throw
    expect(reply[0]?.type).toBe('E')
    expect(errorFields(reply[0]!.body).C).toBe('08P01') // protocol_violation
  })

  it('Bind to an unknown statement → 26000; Execute of an unknown portal → 34000', async () => {
    const s = session(okBackend)
    expect(errorFields(decode(await s.handle(bindMsg('', 'nope', [])))[0]!.body).C).toBe('26000')
    await s.handle(syncMsg())
    expect(errorFields(decode(await s.handle(executeMsg('ghost')))[0]!.body).C).toBe('34000')
  })

  it('rejects an extended-protocol message before authentication', async () => {
    const s = session(okBackend, null)
    const reply = decode(await s.handle(parseMsg('s', 'SELECT id FROM users')))
    expect(errorFields(reply[0]!.body).C).toBe(SqlState.NotAuthenticated)
  })

  it('Close frees the prepared statement and portal (subsequent use reports them gone)', async () => {
    const s = session(okBackend)
    await s.handle(parseMsg('st', 'SELECT id FROM users'))
    await s.handle(bindMsg('po', 'st', []))
    expect(types(decode(await s.handle(closeMsg('P', 'po'))))).toBe('3') // CloseComplete
    expect(types(decode(await s.handle(closeMsg('S', 'st'))))).toBe('3')
    // the closed portal is gone → Execute → 34000
    expect(errorFields(decode(await s.handle(executeMsg('po')))[0]!.body).C).toBe('34000')
    await s.handle(syncMsg())
    // the closed statement is gone → Bind → 26000
    expect(errorFields(decode(await s.handle(bindMsg('po2', 'st', [])))[0]!.body).C).toBe('26000')
  })

  it('a Parse during the post-error skip window is ignored until Sync', async () => {
    const s = session(okBackend)
    // a forbidden Parse trips skip mode
    expect(decode(await s.handle(parseMsg('a', 'SELECT password FROM users')))[0]?.type).toBe('E')
    // a subsequent (even valid) Parse is ignored — no ParseComplete, not stored
    expect((await s.handle(parseMsg('b', 'SELECT id FROM users')))?.length ?? 0).toBe(0)
    // Sync clears the skip; Parse works again
    await s.handle(syncMsg())
    expect(types(decode(await s.handle(parseMsg('b', 'SELECT id FROM users'))))).toBe('1')
  })
})
