/**
 * E2E for the streaming backend: with `streamBackend` configured, simple queries
 * stream row-by-row to the client. This proves a REAL `pg` driver parses the
 * streamed wire output correctly (same RowDescription→DataRow*→CommandComplete
 * sequence as the buffered path), that the RLS/`*` rewrite still applies, and that
 * `maxRows` still caps mid-stream. Backend: PGlite (rows wrapped in an async
 * generator to exercise the proxy's streaming path).
 */
import type { AddressInfo } from 'node:net'
import { PGlite } from '@electric-sql/pglite'
import { Client } from 'pg'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import type { ClientParameters } from 'pg-gateway'
import { createProxyServer } from '../src/proxy/server'
import type { ResolvedPolicy, StreamBackend } from '../src/proxy/handler'
import type { PermissionModel } from '../src/policy/model'
import { backendFromQuery, SEED_SQL } from './helpers/pg-backend'

/** A streaming backend over PGlite — yields each row lazily (stands in for a
 *  server-side cursor), so the proxy forwards a DataRow at a time. */
function pgliteStream(db: PGlite): StreamBackend {
  return async (sql, params) => {
    const r = await db.query<unknown[]>(sql, params ? [...params] : undefined, { rowMode: 'array' })
    async function* rows() {
      for (const row of r.rows) yield row.map((v) => (v === null ? null : String(v)))
    }
    return {
      fields: r.fields.map((f) => ({ name: f.name, dataTypeID: f.dataTypeID })),
      rows: rows(),
      completed: () => `SELECT ${r.rows.length}`,
    }
  }
}

const plain: PermissionModel = { tables: { 'public.users': { select: { columns: ['id', 'email'] } } } }
const rlsModel: PermissionModel = {
  tables: { 'public.users': { select: { columns: ['id', 'email'] }, rls: { select: 'tenant_id = ctx.t' } } },
}

let db: PGlite
let server: ReturnType<typeof createProxyServer>
let port = 0
// password selects the policy: 'plain', 'rls', or 'cap2' (maxRows 2)
const authenticate = (_p: ClientParameters, password: string): ResolvedPolicy | null => {
  if (password === 'plain') return { model: plain }
  if (password === 'rls') return { model: rlsModel, context: { ctx: { t: 1 } } }
  if (password === 'cap2') return { model: plain, maxRows: 2 }
  return null
}

beforeAll(async () => {
  db = await PGlite.create()
  await db.exec(SEED_SQL) // users: 3 rows (tenant 1,1,2), with a password column
  server = createProxyServer({
    authenticate,
    backend: backendFromQuery((sql, p) => db.query<unknown[]>(sql, p, { rowMode: 'array' })), // fallback / extended protocol
    streamBackend: pgliteStream(db),
  })
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r))
  port = (server.address() as AddressInfo).port
})
afterAll(async () => {
  await new Promise<void>((res) => server.close(() => res()))
  await db.close()
})

const connect = (password: string) =>
  new Client({ host: '127.0.0.1', port, user: 'u', password, database: 'app' })

describe('e2e: streaming backend, driven by a real pg client', () => {
  it('streams rows the driver parses correctly, with the `*`/column rewrite applied', async () => {
    const c = connect('plain')
    await c.connect()
    try {
      const r = await c.query('SELECT * FROM users ORDER BY id')
      // 3 rows, only id+email (password dropped by the rewrite), streamed correctly
      expect(r.rows).toEqual([
        { id: 1, email: 'a@x.com' },
        { id: 2, email: 'b@y.com' },
        { id: 3, email: 'c@z.com' },
      ])
    } finally {
      await c.end()
    }
  })

  it('applies the RLS rewrite on the streamed query (only matching rows)', async () => {
    const c = connect('rls')
    await c.connect()
    try {
      const r = await c.query('SELECT * FROM users ORDER BY id')
      expect(r.rows).toEqual([
        { id: 1, email: 'a@x.com' },
        { id: 2, email: 'b@y.com' },
      ]) // tenant 1 only; row 3 (tenant 2) filtered out
    } finally {
      await c.end()
    }
  })

  it('`maxRows` still caps a streamed result (over-cap is refused, not delivered)', async () => {
    const c = connect('cap2') // maxRows: 2, but users has 3 rows
    await c.connect()
    try {
      await expect(c.query('SELECT * FROM users')).rejects.toThrow(/limit/i)
    } finally {
      await c.end()
    }
  })

  it('a streamed result at/under the cap succeeds', async () => {
    const c = connect('cap2')
    await c.connect()
    try {
      const r = await c.query('SELECT id, email FROM users WHERE id = 1')
      expect(r.rows).toEqual([{ id: 1, email: 'a@x.com' }])
    } finally {
      await c.end()
    }
  })
})
