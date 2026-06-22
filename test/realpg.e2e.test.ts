import type { AddressInfo } from 'node:net'
import { Client, Pool } from 'pg'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import type { Backend, ResolvedPolicy } from '../src/proxy/handler'
import { createProxyServer } from '../src/proxy/server'
import type { ClientParameters } from 'pg-gateway'
import type { PermissionModel } from '../src/policy/model'

/**
 * Real end-to-end: a `pg` client speaks to the sql-control proxy, which runs the
 * authorized/rewritten SQL against an actual Postgres (the test DB created by the
 * surrounding setup) as a least-privileged role. This exercises the whole path
 * against real data — RLS row filtering, `*` column restriction, policy refusals,
 * and the least-privileged backend as the defense-in-depth backstop.
 *
 * Requires the local Postgres + `sqlcontrol_test` DB + `sqlcontrol_ro` role.
 */
const BACKEND = {
  host: '127.0.0.1',
  port: 5432,
  database: 'sqlcontrol_test',
  user: 'sqlcontrol_ro',
  password: 'ro_pw',
}

function modelForTenant(tenant: number): ResolvedPolicy {
  const model: PermissionModel = {
    defaultSchema: 'public',
    tables: {
      'public.users': {
        select: { columns: ['id', 'email'] },
        update: { columns: ['email'] },
        rls: { select: 'tenant_id = ctx.tenant', update: 'tenant_id = ctx.tenant' },
      },
      'public.orders': { select: true, rls: { select: 'tenant_id = ctx.tenant' } },
    },
  }
  return { model, context: { ctx: { tenant } } }
}

const pool = new Pool({ ...BACKEND, max: 4 })
const backend: Backend = async (sql, params) => {
  const r = await pool.query({
    text: sql,
    values: params ? [...params] : undefined,
    rowMode: 'array',
  })
  return {
    fields: r.fields.map((f) => ({ name: f.name, dataTypeID: f.dataTypeID })),
    rows: r.rows.map((row: unknown[]) => row.map((v) => (v === null ? null : String(v)))),
    tag: `${r.command}${r.rowCount != null ? ` ${r.rowCount}` : ''}`,
  }
}

const authenticate = (params: ClientParameters, password: string): ResolvedPolicy | null => {
  if (password === 'p1') return modelForTenant(1)
  if (password === 'p2') return modelForTenant(2)
  return null
}

const server = createProxyServer({ authenticate, backend })
let port = 0
let pgUp = true

beforeAll(async () => {
  try {
    await pool.query('SELECT 1')
  } catch {
    pgUp = false
    return
  }
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
  port = (server.address() as AddressInfo).port
})
afterAll(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()))
  await pool.end().catch(() => {})
})

async function connect(password: string): Promise<Client> {
  const client = new Client({ host: '127.0.0.1', port, user: 'tenant', password, database: 'app' })
  await client.connect()
  return client
}

describe('real Postgres end-to-end', () => {
  it('RLS filters to the tenant AND `*` drops the password column', async () => {
    if (!pgUp) return
    const client = await connect('p1')
    try {
      const res = await client.query('SELECT * FROM users ORDER BY id')
      // tenant 1 = alice(1), carol(3); bob(2) is tenant 2 and must not appear
      expect(res.rows).toEqual([
        { id: 1, email: 'alice@x' },
        { id: 3, email: 'carol@z' },
      ])
      // password column never reaches the client
      expect(res.fields.map((f) => f.name)).toEqual(['id', 'email'])
    } finally {
      await client.end()
    }
  })

  it('a different tenant sees only its own rows', async () => {
    if (!pgUp) return
    const client = await connect('p2')
    try {
      const res = await client.query('SELECT id, email FROM users ORDER BY id')
      expect(res.rows).toEqual([{ id: 2, email: 'bob@y' }])
    } finally {
      await client.end()
    }
  })

  it('refuses a forbidden column with the sql-control SQLSTATE', async () => {
    if (!pgUp) return
    const client = await connect('p1')
    try {
      await client.query('SELECT password FROM users')
      throw new Error('should have been refused')
    } catch (err) {
      expect((err as { code?: string }).code).toBe('SC001')
      expect((err as Error).message).toMatch(/password/)
    } finally {
      await client.end()
    }
  })

  it('refuses a table not in the policy (and the role could not read it anyway)', async () => {
    if (!pgUp) return
    const client = await connect('p1')
    try {
      await expect(client.query('SELECT * FROM secret_internal')).rejects.toMatchObject({
        code: 'SC001',
      })
    } finally {
      await client.end()
    }
  })

  it('RLS on UPDATE prevents touching another tenant’s row (real row count)', async () => {
    if (!pgUp) return
    const client = await connect('p1')
    try {
      // tenant 1 tries to update bob (id=2, tenant 2): allowed by column policy,
      // but the USING filter means 0 rows actually match.
      const res = await client.query("UPDATE users SET email = 'hacked@x' WHERE id = 2")
      expect(res.rowCount).toBe(0)
      // and bob is untouched
      const check = await pool.query("SELECT email FROM public.users WHERE id = 2")
      expect(check.rows[0].email).toBe('bob@y')
    } finally {
      await client.end()
    }
  })

  it('parameterized query works end-to-end with RLS', async () => {
    if (!pgUp) return
    const client = await connect('p1')
    try {
      const res = await client.query('SELECT id, email FROM users WHERE id = $1', [1])
      expect(res.rows).toEqual([{ id: 1, email: 'alice@x' }])
      // tenant 1 asking for tenant 2's id returns nothing (RLS)
      const none = await client.query('SELECT id, email FROM users WHERE id = $1', [2])
      expect(none.rows).toEqual([])
    } finally {
      await client.end()
    }
  })
})
