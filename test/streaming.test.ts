import { Buffer } from 'node:buffer'
import { describe, expect, it } from 'vitest'
import { ProxySession } from '../src/proxy/session'
import { streamQuery, type Backend, type ResolvedPolicy, type StreamBackend } from '../src/proxy/handler'

/**
 * Streaming proxy: when a StreamBackend is configured, a simple query yields wire
 * chunks (RowDescription, a DataRow per row *as it arrives*, CommandComplete,
 * ReadyForQuery) instead of buffering. These tests prove (a) the message sequence,
 * (b) rows are pulled LAZILY — stopping consumption stops the backend (flat memory),
 * and (c) the maxRows cap stops the stream with a loud 54000.
 */
const cstr = (s: string): Buffer => Buffer.concat([Buffer.from(s, 'utf8'), Buffer.from([0])])
const queryMsg = (sql: string): Uint8Array => {
  const body = cstr(sql)
  return Buffer.concat([Buffer.from('Q'), (() => { const b = Buffer.alloc(4); b.writeInt32BE(body.length + 4); return b })(), body])
}
const policy = (maxRows?: number): ResolvedPolicy => ({
  model: { tables: { 'public.t': { select: true } } },
  maxRows,
})
const bufferedBackend: Backend = async () => ({ fields: [], rows: [], tag: 'SELECT 0' })

/** A streaming backend that yields `n` rows lazily, counting how many were pulled. */
function lazyBackend(n: number): { backend: StreamBackend; pulled: () => number } {
  let pulled = 0
  const backend: StreamBackend = async () => ({
    fields: [{ name: 'id' }],
    rows: (async function* () {
      for (let i = 0; i < n; i++) {
        pulled++
        yield [String(i)]
      }
    })(),
    completed: () => `SELECT ${n}`,
  })
  return { backend, pulled: () => pulled }
}

/** Decode wire chunks → the message-type string and any error code. */
function typesOf(chunks: Uint8Array[]): { types: string; errorCode?: string; rows: number } {
  const buf = Buffer.concat(chunks)
  let i = 0
  let types = ''
  let rows = 0
  let errorCode: string | undefined
  while (i < buf.length) {
    const type = String.fromCharCode(buf[i] ?? 0)
    const len = buf.readInt32BE(i + 1)
    types += type
    if (type === 'D') rows++
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
  return { types, errorCode, rows }
}

async function drain(it: AsyncIterable<Uint8Array>): Promise<Uint8Array[]> {
  const chunks: Uint8Array[] = []
  for await (const c of it) chunks.push(c)
  return chunks
}

describe('streaming simple-query path', () => {
  it('emits RowDescription, a DataRow per row, then CommandComplete + ReadyForQuery', async () => {
    const out = typesOf(await drain(streamQuery('SELECT * FROM t', policy(), lazyBackend(4).backend)))
    expect(out.types).toBe('TDDDDCZ') // 1 RowDescription, 4 DataRow, CommandComplete, ReadyForQuery
    expect(out.rows).toBe(4)
    expect(out.errorCode).toBeUndefined()
  })

  it('pulls rows LAZILY — abandoning the stream stops the backend (flat memory)', async () => {
    const { backend, pulled } = lazyBackend(1_000_000)
    const it = streamQuery('SELECT * FROM t', policy(), backend)[Symbol.asyncIterator]()
    // Consume just the first few chunks (RowDescription + 2 DataRows), then stop.
    await it.next() // RowDescription (no row pulled yet)
    await it.next() // DataRow 0 → pulls row 0
    await it.next() // DataRow 1 → pulls row 1
    await it.return?.(undefined) // abandon — generator's finally runs, backend stops
    // Only the rows we consumed were ever materialized — not the million.
    expect(pulled()).toBeLessThanOrEqual(3)
  })

  it('refuses an over-cap result LOUD (54000) after streaming up to maxRows', async () => {
    const out = typesOf(await drain(streamQuery('SELECT * FROM t', policy(2), lazyBackend(100).backend)))
    expect(out.rows).toBe(2) // streamed up to the cap
    expect(out.types).toBe('TDDEZ') // RowDescription, 2×DataRow, ErrorResponse, ReadyForQuery
    expect(out.errorCode).toBe('54000')
  })

  it('a refused statement streams just the error (no backend call)', async () => {
    let called = false
    const backend: StreamBackend = async () => { called = true; return { fields: [], rows: (async function* () {})(), completed: () => '' } }
    const restricted: ResolvedPolicy = { model: { tables: { 'public.t': { select: { columns: ['id'] } } } } }
    const out = typesOf(await drain(streamQuery('SELECT secret FROM t', restricted, backend)))
    expect(out.types).toBe('EZ')
    expect(called).toBe(false)
  })
})

describe('ProxySession wires the streaming backend for simple queries', () => {
  it('routes a Query message through the streaming path when a streamBackend is set', async () => {
    const { backend } = lazyBackend(3)
    const session = new ProxySession(() => policy(), bufferedBackend, backend)
    const res = await session.handle(queryMsg('SELECT * FROM t'))
    expect(res).not.toBeInstanceOf(Uint8Array) // it's an AsyncIterable (streaming), not one buffer
    const out = typesOf(await drain(res as AsyncIterable<Uint8Array>))
    expect(out.types).toBe('TDDDCZ')
  })

  it('falls back to buffering when no streamBackend is configured', async () => {
    const session = new ProxySession(() => policy(), bufferedBackend) // no stream backend
    const res = await session.handle(queryMsg('SELECT * FROM t'))
    expect(res).toBeInstanceOf(Uint8Array) // buffered: one byte buffer
  })
})
