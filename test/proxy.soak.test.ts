/**
 * Soak / load test: sustained concurrency, connection churn, and bounded memory
 * through the proxy (PGlite backend, real `pg` clients). The headline assertion is
 * tenant ISOLATION under concurrency — each connection has its own policy closure,
 * so many connections as different tenants must never see each other's rows.
 *
 * CI runs a modest load; crank it with SOAK=1 (and `node --expose-gc` for the
 * memory check to be meaningful).
 */
import type { AddressInfo } from 'node:net'
import { PGlite } from '@electric-sql/pglite'
import { Client } from 'pg'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import type { ClientParameters } from 'pg-gateway'
import { createProxyServer } from '../src/proxy/server'
import type { ResolvedPolicy } from '../src/proxy/handler'
import type { PermissionModel } from '../src/policy/model'
import { backendFromQuery } from '../test/helpers/pg-backend'

const SOAK = process.env.SOAK === '1'
const TENANTS = 10
const CONCURRENCY = SOAK ? 100 : 30
const ROUNDS = SOAK ? 40 : 4
const CHURN = SOAK ? 2000 : 150

// each tenant only sees their own rows (RLS), keyed by ctx.uid
const model: PermissionModel = {
  tables: { 'public.data': { select: true, rls: { select: 'owner_id = ctx.uid' } } },
}

let db: PGlite
let server: ReturnType<typeof createProxyServer>
let port = 0

beforeAll(async () => {
  db = await PGlite.create()
  await db.exec('CREATE TABLE data (id int PRIMARY KEY, owner_id int, payload text)')
  // 5 rows per tenant
  const rows: string[] = []
  let id = 1
  for (let t = 1; t <= TENANTS; t++) for (let k = 0; k < 5; k++) rows.push(`(${id++}, ${t}, 'p${t}-${k}')`)
  await db.exec(`INSERT INTO data VALUES ${rows.join(', ')}`)

  const authenticate = (params: ClientParameters, password: string): ResolvedPolicy | null => {
    const uid = Number(password) // demo: password is the tenant id
    if (!Number.isInteger(uid) || uid < 1 || uid > TENANTS) return null
    return { model, context: { ctx: { uid } } }
  }
  const backend = backendFromQuery((sql, p) => db.query<unknown[]>(sql, p, { rowMode: 'array' }))
  server = createProxyServer({ authenticate, backend })
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r))
  port = (server.address() as AddressInfo).port
})
afterAll(async () => {
  await new Promise<void>((res) => server.close(() => res()))
  await db.close()
})

/** Connect as `tenant`, run the query, return its rows. */
async function queryAs(tenant: number): Promise<Array<{ owner_id: number }>> {
  const c = new Client({ host: '127.0.0.1', port, user: `t${tenant}`, password: String(tenant), database: 'app' })
  await c.connect()
  try {
    const r = await c.query('SELECT id, owner_id, payload FROM data')
    return r.rows
  } finally {
    await c.end()
  }
}

describe('soak: concurrency, isolation, churn, memory', () => {
  it(`isolates tenants under ${CONCURRENCY}×${ROUNDS} concurrent connections (no crosstalk)`, async () => {
    let checked = 0
    for (let round = 0; round < ROUNDS; round++) {
      const results = await Promise.all(
        Array.from({ length: CONCURRENCY }, (_, i) => {
          const tenant = (i % TENANTS) + 1
          return queryAs(tenant).then((rows) => ({ tenant, rows }))
        }),
      )
      for (const { tenant, rows } of results) {
        expect(rows.length).toBe(5) // exactly this tenant's rows
        expect(rows.every((row) => row.owner_id === tenant)).toBe(true) // no other tenant leaked in
        checked++
      }
    }
    expect(checked).toBe(CONCURRENCY * ROUNDS)
  }, SOAK ? 120_000 : 30_000)

  it(`survives ${CHURN} rapid connect/disconnect cycles and stays responsive`, async () => {
    const batch = 25
    for (let done = 0; done < CHURN; done += batch) {
      await Promise.all(
        Array.from({ length: Math.min(batch, CHURN - done) }, () => {
          const t = ((done % TENANTS) + 1)
          // connect, do nothing heavy, disconnect — churn server-side per-conn state
          const c = new Client({ host: '127.0.0.1', port, user: `t${t}`, password: String(t), database: 'app' })
          return c.connect().then(() => c.end())
        }),
      )
    }
    // still works after the churn
    const after = await queryAs(3)
    expect(after.length).toBe(5)
    expect(after.every((r) => r.owner_id === 3)).toBe(true)
  }, SOAK ? 120_000 : 30_000)

  it('memory stays bounded across sustained queries', async () => {
    const gc = (globalThis as { gc?: () => void }).gc
    gc?.()
    const before = process.memoryUsage().heapUsed
    const iterations = SOAK ? 4000 : 400
    for (let i = 0; i < iterations; i++) {
      const rows = await queryAs((i % TENANTS) + 1)
      expect(rows.length).toBe(5)
    }
    gc?.()
    const grew = process.memoryUsage().heapUsed - before
    // a leak would balloon the heap; a generous bound catches it without flaking on GC noise
    if (gc) expect(grew).toBeLessThan(80 * 1024 * 1024)
  }, SOAK ? 180_000 : 40_000)
})
