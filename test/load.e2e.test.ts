import type { AddressInfo } from 'node:net'
import { Pool } from 'pg'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { createProxyServer } from '../src/proxy/server'
import type { Backend, ResolvedPolicy } from '../src/proxy/handler'
import type { ClientParameters } from 'pg-gateway'
import type { PermissionModel } from '../src/policy/model'

/**
 * Load / concurrency smoke test: many client connections hammer the proxy with
 * mixed read queries (simple, parameterized, RLS-filtered) in parallel. Asserts
 * every response is correct under contention (no cross-talk between connections,
 * no dropped/garbled rows) and reports throughput/latency. Two tenants run
 * concurrently to catch any per-connection policy/state bleed.
 */
const BACKEND = { host: '127.0.0.1', port: 5432, database: 'sqlcontrol_test', user: 'sqlcontrol_ro', password: 'ro_pw' }
const modelFor = (tenant: number): ResolvedPolicy => ({
  model: {
    defaultSchema: 'public',
    tables: { 'public.users': { select: { columns: ['id', 'email'] }, rls: { select: 'tenant_id = ctx.tenant' } } },
  } satisfies PermissionModel,
  context: { ctx: { tenant } },
})

const backendPool = new Pool({ ...BACKEND, max: 12 })
const backend: Backend = async (text, params) => {
  const r = await backendPool.query({ text, values: params ? [...params] : undefined, rowMode: 'array' })
  return {
    fields: r.fields.map((f) => ({ name: f.name, dataTypeID: f.dataTypeID })),
    rows: r.rows.map((row: unknown[]) => row.map((v) => (v === null ? null : String(v)))),
    tag: `${r.command}${r.rowCount != null ? ` ${r.rowCount}` : ''}`,
  }
}
const authenticate = (_p: ClientParameters, password: string): ResolvedPolicy | null =>
  password === 'p1' ? modelFor(1) : password === 'p2' ? modelFor(2) : null
const server = createProxyServer({ authenticate, backend })
let port = 0
let pgUp = true

beforeAll(async () => {
  try { await backendPool.query('SELECT 1') } catch { pgUp = false; return }
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r))
  port = (server.address() as AddressInfo).port
})
afterAll(async () => {
  await new Promise<void>((r) => server.close(() => r()))
  await backendPool.end().catch(() => {})
})

describe('proxy under concurrent load', () => {
  it('serves 1000 mixed queries across two tenants correctly', async () => {
    if (!pgUp) return
    // Two client pools through the proxy — one per tenant — so per-connection
    // policy isolation is exercised under contention.
    const p1 = new Pool({ host: '127.0.0.1', port, user: 't1', password: 'p1', database: 'app', max: 16 })
    const p2 = new Pool({ host: '127.0.0.1', port, user: 't2', password: 'p2', database: 'app', max: 16 })
    const N = 500 // per tenant → 1000 total
    let errors = 0
    const latencies: number[] = []

    const oneQuery = async (pool: Pool, tenant: number, i: number): Promise<void> => {
      const start = performance.now()
      try {
        // alternate simple / parameterized / star (RLS + column restriction)
        const res =
          i % 3 === 0 ? await pool.query('SELECT id, email FROM users ORDER BY id')
          : i % 3 === 1 ? await pool.query('SELECT id, email FROM users WHERE id = $1', [tenant])
          : await pool.query('SELECT * FROM users')
        // RLS: tenant 1 sees ids {1,3}; tenant 2 sees {2}. Never the other tenant's rows.
        const ids = res.rows.map((r) => Number(r.id)).sort()
        const expected = tenant === 1 ? [1, 3] : [2]
        if (i % 3 === 1) {
          if (!(ids.length === 1 && ids[0] === tenant)) errors++
        } else if (JSON.stringify(ids) !== JSON.stringify(expected)) {
          errors++
        }
        // column restriction: password never present even via `*`
        if (res.fields.some((f) => f.name === 'password')) errors++
      } catch {
        errors++
      } finally {
        latencies.push(performance.now() - start)
      }
    }

    const t0 = performance.now()
    const tasks: Promise<void>[] = []
    for (let i = 0; i < N; i++) {
      tasks.push(oneQuery(p1, 1, i))
      tasks.push(oneQuery(p2, 2, i))
    }
    await Promise.all(tasks)
    const elapsed = performance.now() - t0

    await p1.end(); await p2.end()

    latencies.sort((a, b) => a - b)
    const p50 = latencies[Math.floor(latencies.length * 0.5)] ?? 0
    const p95 = latencies[Math.floor(latencies.length * 0.95)] ?? 0
    const qps = Math.round((latencies.length / elapsed) * 1000)
    // eslint-disable-next-line no-console
    console.log(`[load] ${latencies.length} queries in ${Math.round(elapsed)}ms — ${qps} q/s, p50=${p50.toFixed(1)}ms p95=${p95.toFixed(1)}ms, errors=${errors}`)

    expect(errors).toBe(0)
    expect(latencies.length).toBe(2 * N)
  }, 60000)
})
