import type { AddressInfo } from 'node:net'
import { Pool } from 'pg'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import knex from 'knex'
import postgres from 'postgres'
import { drizzle as drizzlePg } from 'drizzle-orm/node-postgres'
import { drizzle as drizzlePostgres } from 'drizzle-orm/postgres-js'
import { sql as dsql } from 'drizzle-orm'
import { createProxyServer } from '../src/proxy/server'
import type { Backend, ResolvedPolicy } from '../src/proxy/handler'
import type { ClientParameters } from 'pg-gateway'
import type { PermissionModel } from '../src/policy/model'

/**
 * Real driver compatibility: each common Postgres driver connects to the proxy and
 * runs a read query. Asserts (a) it connects + returns rows (compatibility) and
 * (b) RLS is enforced *through the driver* — tenant 1 sees alice(1)+carol(3), never
 * bob(2). `introspection: { enabled: true }` is the only config needed; it
 * auto-allows the pg_type/pg_range catalogs postgres.js fetches on connect.
 */
const BACKEND = { host: '127.0.0.1', port: 5432, database: 'sqlcontrol_test', user: 'sqlcontrol_ro', password: 'ro_pw' }
const model: PermissionModel = {
  defaultSchema: 'public',
  tables: { 'public.users': { select: { columns: ['id', 'email'] }, rls: { select: 'tenant_id = ctx.tenant' } } },
  introspection: { enabled: true },
}
const policy: ResolvedPolicy = { model, context: { ctx: { tenant: 1 } } }

const pool = new Pool({ ...BACKEND, max: 6 })
const backend: Backend = async (text, params) => {
  const r = await pool.query({ text, values: params ? [...params] : undefined, rowMode: 'array' })
  return {
    fields: r.fields.map((f) => ({ name: f.name, dataTypeID: f.dataTypeID })),
    rows: r.rows.map((row: unknown[]) => row.map((v) => (v === null ? null : String(v)))),
    tag: `${r.command}${r.rowCount != null ? ` ${r.rowCount}` : ''}`,
  }
}
const authenticate = (_p: ClientParameters, password: string): ResolvedPolicy | null =>
  password === 'p1' ? policy : null
const server = createProxyServer({ authenticate, backend })
let port = 0
let pgUp = true
const conn = () => ({ host: '127.0.0.1', port, user: 'tenant', password: 'p1', database: 'app' })

beforeAll(async () => {
  try { await pool.query('SELECT 1') } catch { pgUp = false; return }
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r))
  port = (server.address() as AddressInfo).port
})
afterAll(async () => {
  await new Promise<void>((r) => server.close(() => r()))
  await pool.end().catch(() => {})
})

/** Pull email values out of whatever row shape a driver returns, and assert RLS. */
function assertTenant1(rows: unknown): void {
  const arr = Array.isArray(rows) ? rows : ((rows as { rows?: unknown[] }).rows ?? [])
  const emails = (arr as Array<Record<string, unknown>>).map((r) => String(r.email)).sort()
  expect(emails).toEqual(['alice@x', 'carol@z']) // bob@y (tenant 2) filtered by RLS
}
const Q = 'SELECT id, email FROM users ORDER BY id'

describe('driver compatibility (read + RLS through each driver)', () => {
  it('node-postgres: simple, parameterized, named-prepared', async () => {
    if (!pgUp) return
    const { Client } = await import('pg')
    const c = new Client(conn()); await c.connect()
    try {
      assertTenant1((await c.query(Q)).rows)
      expect((await c.query('SELECT id, email FROM users WHERE id = $1', [1])).rows[0]).toMatchObject({ email: 'alice@x' })
      expect((await c.query({ name: 'pm', text: 'SELECT id, email FROM users WHERE id = $1', values: [1] })).rows[0]).toMatchObject({ email: 'alice@x' })
    } finally { await c.end() }
  })

  it('knex (raw + query builder)', async () => {
    if (!pgUp) return
    const k = knex({ client: 'pg', connection: conn(), pool: { min: 0, max: 2 } })
    try {
      assertTenant1((await k.raw(Q)).rows)
      assertTenant1(await k('users').select('id', 'email').orderBy('id'))
    } finally { await k.destroy() }
  })

  it('drizzle (node-postgres)', async () => {
    if (!pgUp) return
    const p = new Pool({ ...conn(), max: 2 }); const db = drizzlePg(p)
    try { assertTenant1((await db.execute(dsql.raw(Q))).rows) } finally { await p.end() }
  })

  it('postgres.js (prepared + prepare:false)', async () => {
    if (!pgUp) return
    const a = postgres({ ...conn(), max: 2 })
    const b = postgres({ ...conn(), max: 2, prepare: false })
    try { assertTenant1(await a.unsafe(Q)); assertTenant1(await b.unsafe(Q)) } finally { await a.end(); await b.end() }
  })

  it('drizzle (postgres.js)', async () => {
    if (!pgUp) return
    const s = postgres({ ...conn(), max: 2 }); const db = drizzlePostgres(s)
    try { assertTenant1(await db.execute(dsql.raw(Q))) } finally { await s.end() }
  })
})
