/**
 * One end-to-end suite, run against any real Postgres backend (PGlite in-process,
 * or a node-pg Pool to a real server). Each backend supplies an {@link E2eEnv};
 * the assertions below drive the proxy over TCP with the real `pg` client.
 */
import type { AddressInfo } from 'node:net'
import { Client } from 'pg'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import type { ClientParameters } from 'pg-gateway'
import { createProxyServer } from '../../src/proxy/server'
import type { Backend, ResolvedPolicy } from '../../src/proxy/handler'
import type { PermissionModel } from '../../src/policy/model'

export interface E2eEnv {
  backend: Backend
  /** Run DDL / seed directly against the real database (bypassing the proxy). */
  exec(sql: string): Promise<void>
  /** Direct query for verification (single scalar of the first row/col). */
  scalar(sql: string): Promise<unknown>
  close(): Promise<void>
}

const model: PermissionModel = {
  defaultSchema: 'public',
  tables: {
    'public.users': {
      select: { columns: ['id', 'email'] }, // password hidden
      update: { columns: ['email'] },
      rls: { select: 'tenant_id = ctx.tenant', update: 'tenant_id = ctx.tenant' },
    },
    'public.notes': {
      select: true,
      insert: { columns: ['id', 'body', 'tenant_id'] },
      update: { columns: ['body', 'tenant_id'] },
      rls: { insert: 'tenant_id = ctx.tenant' }, // WITH CHECK: no cross-tenant writes
    },
    // public.secrets intentionally absent → invisible
  },
  introspection: { enabled: true },
}

export function defineE2eSuite(label: string, makeEnv: () => Promise<E2eEnv>, skip = false): void {
  const suite = skip ? describe.skip : describe
  suite(`e2e (${label}): real Postgres behind the proxy`, () => {
    let env: E2eEnv
    let server: ReturnType<typeof createProxyServer>
    let port = 0

    beforeAll(async () => {
      env = await makeEnv()
      const authenticate = (_p: ClientParameters, password: string): ResolvedPolicy | null =>
        password === 'secret' ? { model, context: { ctx: { tenant: 1 } } } : null
      server = createProxyServer({ authenticate, backend: env.backend })
      await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
      port = (server.address() as AddressInfo).port
    })
    afterAll(async () => {
      if (server) await new Promise<void>((res, rej) => server.close((e) => (e ? rej(e) : res())))
      if (env) await env.close()
    })

    const withClient = async <T>(fn: (c: Client) => Promise<T>): Promise<T> => {
      const client = new Client({ host: '127.0.0.1', port, user: 't1', password: 'secret', database: 'app' })
      await client.connect()
      try {
        return await fn(client)
      } finally {
        await client.end()
      }
    }

    it('expands `*` to permitted columns AND applies RLS — verified on real PG', async () => {
      const rows = await withClient((c) => c.query('SELECT * FROM users').then((r) => r.rows))
      expect(rows).toEqual([
        { id: 1, email: 'a@x.com' },
        { id: 2, email: 'b@y.com' },
      ])
    })

    it('refuses a forbidden column without touching the database', async () => {
      await withClient((c) => expect(c.query('SELECT password FROM users')).rejects.toThrow(/password/))
    })

    it('refuses an invisible relation', async () => {
      await withClient((c) => expect(c.query('SELECT * FROM secrets')).rejects.toThrow(/secrets/))
    })

    it('runs a parameterized (extended-protocol) query with RLS applied', async () => {
      const rows = await withClient((c) =>
        c.query('SELECT id, email FROM users WHERE id = $1', [1]).then((r) => r.rows),
      )
      expect(rows).toEqual([{ id: 1, email: 'a@x.com' }])
    })

    it('RLS hides another tenant even when its id is requested explicitly', async () => {
      const rows = await withClient((c) =>
        c.query('SELECT id, email FROM users WHERE id = $1', [3]).then((r) => r.rows),
      )
      expect(rows).toEqual([])
    })

    it('UPDATE ... RETURNING is gated and RLS-scoped, executes on real PG', async () => {
      const r = await withClient((c) =>
        c.query('UPDATE users SET email = $1 WHERE id = $2 RETURNING id, email', ['z@x.com', 1]),
      )
      expect(r.rows).toEqual([{ id: 1, email: 'z@x.com' }])
      const r2 = await withClient((c) =>
        c.query('UPDATE users SET email = $1 WHERE id = $2 RETURNING id', ['hax', 3]),
      )
      expect(r2.rows).toEqual([]) // RLS: cross-tenant row not touched
      expect(await env.scalar("SELECT email FROM users WHERE id = 3")).toBe('c@z.com')
      await env.exec("UPDATE users SET email = 'a@x.com' WHERE id = 1") // restore for later tests
    })

    it('introspection is row-filtered: the hidden table never appears', async () => {
      const names = await withClient((c) =>
        c
          .query("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' ORDER BY table_name")
          .then((r) => r.rows.map((x) => x.table_name)),
      )
      expect(names).toContain('users')
      expect(names).toContain('notes')
      expect(names).not.toContain('secrets')
    })

    it('a named prepared statement (Describe-before-Execute) works and reuses across executions', async () => {
      await withClient(async (c) => {
        const q = { name: 'by_id', text: 'SELECT id, email FROM users WHERE id = $1' }
        const a = await c.query({ ...q, values: [1] })
        const b = await c.query({ ...q, values: [2] })
        expect(a.rows).toEqual([{ id: 1, email: 'a@x.com' }])
        expect(b.rows).toEqual([{ id: 2, email: 'b@y.com' }])
      })
    })

    it('INSERT WITH CHECK: a row stamped for the tenant is inserted', async () => {
      const r = await withClient((c) =>
        c.query("INSERT INTO notes (id, body, tenant_id) VALUES (10, 'mine', 1)"),
      )
      expect(r.rowCount).toBe(1)
      expect(await env.scalar('SELECT body FROM notes WHERE id = 10')).toBe('mine')
    })

    it('INSERT WITH CHECK: a row stamped for another tenant is dropped (cross-tenant write blocked)', async () => {
      const r = await withClient((c) =>
        c.query("INSERT INTO notes (id, body, tenant_id) VALUES (11, 'evil', 2)"),
      )
      expect(r.rowCount).toBe(0)
      expect(await env.scalar('SELECT count(*)::int FROM notes WHERE id = 11')).toBe(0)
    })

    it('INSERT ... SELECT WITH CHECK: only the tenant-matching rows are inserted', async () => {
      await withClient((c) =>
        c.query("INSERT INTO notes (id, body, tenant_id) SELECT 12, 'a', 1 UNION ALL SELECT 13, 'b', 2"),
      )
      expect(await env.scalar('SELECT count(*)::int FROM notes WHERE id IN (12, 13)')).toBe(1)
      expect(await env.scalar('SELECT tenant_id FROM notes WHERE id = 12')).toBe(1)
    })

    it('UPDATE WITH CHECK: moving a row to another tenant is a no-op', async () => {
      const r = await withClient((c) => c.query('UPDATE notes SET tenant_id = 2 WHERE id = 10'))
      expect(r.rowCount).toBe(0)
      expect(await env.scalar('SELECT tenant_id FROM notes WHERE id = 10')).toBe(1)
    })

    it('UPDATE WITH CHECK: an in-tenant update still works', async () => {
      const r = await withClient((c) => c.query("UPDATE notes SET body = 'updated' WHERE id = 10"))
      expect(r.rowCount).toBe(1)
      expect(await env.scalar('SELECT body FROM notes WHERE id = 10')).toBe('updated')
    })

    it('ON CONFLICT DO UPDATE is WITH-CHECK protected: cannot move a row to another tenant', async () => {
      await withClient((c) =>
        c.query(
          "INSERT INTO notes (id, body, tenant_id) VALUES (1, 'x', 1) ON CONFLICT (id) DO UPDATE SET tenant_id = 2",
        ),
      )
      expect(await env.scalar('SELECT tenant_id FROM notes WHERE id = 1')).toBe(1) // unchanged
    })

    it('INSERT ... SELECT from a table is WITH-CHECK filtered (cross-tenant copy blocked)', async () => {
      // copy an existing note but stamp it for the tenant → inserted
      await withClient((c) =>
        c.query("INSERT INTO notes (id, body, tenant_id) SELECT id + 100, body, 1 FROM notes WHERE id = 1"),
      )
      expect(await env.scalar('SELECT count(*)::int FROM notes WHERE id = 101')).toBe(1)
      // same copy but stamped for another tenant → dropped by the check
      const r = await withClient((c) =>
        c.query("INSERT INTO notes (id, body, tenant_id) SELECT id + 200, body, 2 FROM notes WHERE id = 1"),
      )
      expect(r.rowCount).toBe(0)
      expect(await env.scalar('SELECT count(*)::int FROM notes WHERE id = 201')).toBe(0)
    })

    it('handles many concurrent connections without crosstalk or crash', async () => {
      const results = await Promise.all(
        Array.from({ length: 40 }, (_, i) =>
          withClient((c) =>
            c.query('SELECT id, email FROM users WHERE id = $1', [(i % 2) + 1]).then((r) => r.rows[0]),
          ),
        ),
      )
      results.forEach((row, i) => {
        expect(row).toEqual(i % 2 === 0 ? { id: 1, email: 'a@x.com' } : { id: 2, email: 'b@y.com' })
      })
    })
  })
}
