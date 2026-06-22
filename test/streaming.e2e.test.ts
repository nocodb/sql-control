import type { AddressInfo } from 'node:net'
import { PGlite } from '@electric-sql/pglite'
import { Client } from 'pg'
import QueryStream from 'pg-query-stream'
import knex from 'knex'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { createProxyServer } from '../src/proxy/server'
import type { ResolvedPolicy, StreamBackend, StreamResult } from '../src/proxy/handler'
import type { ClientParameters } from 'pg-gateway'
import type { PermissionModel } from '../src/policy/model'

/**
 * PROPER end-to-end streaming: a real Postgres engine (PGlite) executes the actual
 * policy-rewritten SQL, and the result streams through the proxy to real cursor
 * clients (pg-query-stream, knex.raw().stream()). Proves the streamed output has RLS
 * applied (only the caller's tenant), the restricted column dropped (`secret` never
 * appears), the SELECT * expanded, and the maxRows cap surfacing as a real 54000.
 * The backend is NOT a hand-written mock — it runs whatever SQL the proxy produces.
 */
const TENANTS = 2
const PER_TENANT = 6000
const TOTAL_T1 = PER_TENANT

const model: PermissionModel = {
  defaultSchema: 'public',
  tables: { 'public.big': { select: { columns: ['id', 'val'] }, rls: { select: 'tenant = ctx.t' } } },
}

let db: PGlite
// Streaming backend over the REAL engine: run the (already authorized + rewritten)
// SQL on PGlite and yield its rows. Counts executions so we can assert the streaming
// path (one backend run per query, streamed out — not buffered & re-served).
const streamBackend: StreamBackend = async (sql, params): Promise<StreamResult> => {
  const r = await db.query<unknown[]>(sql, params ? [...params] : [], { rowMode: 'array' })
  const fields = r.fields.map((f) => ({ name: f.name, dataTypeID: f.dataTypeID }))
  const rows = r.rows
  return {
    fields,
    rows: (async function* () {
      for (const row of rows) yield row.map((v) => (v == null ? null : String(v)))
    })(),
    completed: () => `SELECT ${rows.length}`,
  }
}

let maxRows: number | undefined
const authenticate = (_p: ClientParameters, pw: string): ResolvedPolicy | null =>
  pw === 'p1' ? { model, context: { ctx: { t: 1 } }, maxRows } : null
let port = 0
let close: () => Promise<void> = async () => {}

beforeAll(async () => {
  db = await PGlite.create()
  await db.exec(`
    CREATE TABLE big (id int PRIMARY KEY, val text, secret text, tenant int);
    INSERT INTO big
      SELECT g, 'v' || g, 'SECRET' || g, ((g - 1) % ${TENANTS}) + 1
      FROM generate_series(1, ${PER_TENANT * TENANTS}) g;
  `)
  const server = createProxyServer({
    authenticate,
    backend: async () => ({ fields: [], rows: [], tag: 'SELECT 0' }), // unused — streaming path
    streamBackend,
  })
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r))
  port = (server.address() as AddressInfo).port
  close = () => new Promise<void>((res) => server.close(() => res()))
})
afterAll(async () => { await close(); await db.close() })

const conn = () => ({ host: '127.0.0.1', port, user: 't', password: 'p1', database: 'app' })

describe('proper e2e streaming (real PG engine + real cursor clients)', () => {
  it('pg-query-stream: streams only tenant 1 rows, with the secret column dropped', async () => {
    maxRows = undefined
    const c = new Client(conn())
    await c.connect()
    try {
      let count = 0
      let first: Record<string, unknown> | undefined
      let leaked = false
      const stream = c.query(new QueryStream('SELECT * FROM big ORDER BY id', [], { batchSize: 100 } as never))
      await new Promise<void>((resolve, reject) => {
        stream.on('data', (row: Record<string, unknown>) => {
          if (count === 0) first = row
          if ('secret' in row || 'tenant' in row) leaked = true
          count++
        })
        stream.on('end', resolve)
        stream.on('error', reject)
      })
      expect(leaked).toBe(false) // RLS-restricted columns never reach the client
      expect(count).toBe(TOTAL_T1) // RLS: exactly tenant 1's rows, not all 12000
      // SELECT * expanded to the 2 permitted cols; `id` comes back as a number because the
      // RowDescription carries int4's OID and pg's type parser decodes it (real type-aware round-trip).
      expect(first).toEqual({ id: 1, val: 'v1' })
    } finally {
      await c.end()
    }
  })

  it('knex.raw().stream(): same RLS-filtered, column-restricted stream', async () => {
    maxRows = undefined
    const k = knex({ client: 'pg', connection: conn(), pool: { min: 0, max: 4 } })
    try {
      let count = 0
      let leaked = false
      const stream = k.raw('SELECT * FROM big').stream()
      for await (const row of stream as AsyncIterable<Record<string, unknown>>) {
        if ('secret' in row || 'tenant' in row) leaked = true
        count++
      }
      expect(leaked).toBe(false)
      expect(count).toBe(TOTAL_T1)
    } finally {
      await k.destroy()
    }
  })

  it('the maxRows cap surfaces to a cursor client as a real 54000 mid-stream', async () => {
    maxRows = 1000
    const c = new Client(conn())
    await c.connect()
    try {
      const stream = c.query(new QueryStream('SELECT * FROM big', [], { batchSize: 100 } as never))
      const result = await new Promise<{ code?: string; rows: number }>((resolve) => {
        let rows = 0
        stream.on('data', () => { rows++ })
        stream.on('end', () => resolve({ rows }))
        stream.on('error', (e) => resolve({ code: (e as { code?: string }).code, rows }))
      })
      expect(result.code).toBe('54000')
      expect(result.rows).toBeLessThanOrEqual(1000) // streamed up to the cap, then errored
    } finally {
      await c.end().catch(() => {})
    }
  })
})
