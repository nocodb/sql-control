/**
 * A runnable CRM example (HubSpot-ish): one org, four users, an org chart, and
 * role-based access enforced entirely by sql-control. Each user connects to the
 * proxy with their OWN credentials; the proxy maps the connection to a policy and
 * rewrites every query so the user only ever sees/touches what their role permits.
 *
 *   org chart            roles & what they may see
 *   ─────────            ─────────────────────────
 *   admin                everything, every column
 *   maya  (manager)      deals of her whole team (herself + her reports), incl. commission
 *   ├─ rita (rep)        only HER OWN deals, and NOT the commission column
 *   └─ rob  (rep)        only HIS OWN deals, and NOT the commission column
 *   nobody but admin sees users.password_hash
 *
 * Run it:  npx vitest run examples/crm.test.ts   (output written to /tmp/crm-demo.txt)
 *
 * This file doubles as an integration test: every `it` asserts a security property,
 * so if the boundary ever regresses, it fails.
 */
import { writeFileSync } from 'node:fs'
import type { AddressInfo } from 'node:net'
import { PGlite } from '@electric-sql/pglite'
import { Client } from 'pg'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import type { ClientParameters } from 'pg-gateway'
import { analyze } from '../src/analyzer/index'
import { createProxyServer } from '../src/proxy/server'
import type { ResolvedPolicy } from '../src/proxy/handler'
import { MemoryCatalog } from '../src/schema/memory-catalog'
import type { PermissionModel } from '../src/policy/model'
import { backendFromQuery } from '../test/helpers/pg-backend'

// ── 1. The database schema + seed data (lives in the real Postgres) ────────────
const SCHEMA = `
  CREATE SCHEMA crm;
  CREATE TABLE crm.users (
    id int PRIMARY KEY, username text, full_name text, role text,
    manager_id int, password_hash text
  );
  CREATE TABLE crm.deals (
    id int PRIMARY KEY, title text, amount numeric, stage text,
    owner_id int, commission numeric
  );
  INSERT INTO crm.users VALUES
    (1, 'admin', 'Ada Admin',   'admin',   NULL, 'x-admin'),
    (2, 'maya',  'Maya Manager','manager', NULL, 'x-maya'),
    (3, 'rita',  'Rita Rep',    'rep',     2,    'x-rita'),
    (4, 'rob',   'Rob Rep',     'rep',     2,    'x-rob');
  INSERT INTO crm.deals VALUES
    (10, 'Acme',     5000,  'won',  3, 500),
    (11, 'Globex',   8000,  'open', 3, 800),
    (12, 'Initech',  3000,  'open', 4, 300),
    (13, 'Umbrella', 12000, 'won',  4, 1200);
`

// ── 2. The catalog: the SHAPE of the schema (columns), for `*`-expansion etc. ──
// In production you'd call loadCatalog(query) to introspect this from the live DB.
const catalog = new MemoryCatalog({
  tables: {
    'crm.users': ['id', 'username', 'full_name', 'role', 'manager_id', 'password_hash'],
    'crm.deals': ['id', 'title', 'amount', 'stage', 'owner_id', 'commission'],
  },
})

// ── 3. The policies: one PermissionModel per role ─────────────────────────────
// `ctx.uid` is the logged-in user's id; RLS predicates reference it.
function policyFor(role: string, uid: number): ResolvedPolicy {
  const ctx = { ctx: { uid } }

  if (role === 'admin') {
    const model: PermissionModel = {
      defaultSchema: 'crm',
      tables: {
        'crm.users': { select: true, update: { columns: ['full_name', 'role', 'manager_id'] } },
        'crm.deals': { select: true, update: { columns: ['title', 'amount', 'stage', 'commission'] } },
      },
    }
    return { model, catalog, context: ctx }
  }

  if (role === 'manager') {
    const model: PermissionModel = {
      defaultSchema: 'crm',
      tables: {
        // a directory of users — but never the password hash
        'crm.users': { select: { columns: ['id', 'username', 'full_name', 'role', 'manager_id'] } },
        // her team's deals (herself + her direct reports), commission visible
        'crm.deals': {
          select: { columns: ['id', 'title', 'amount', 'stage', 'owner_id', 'commission'] },
          update: { columns: ['title', 'amount', 'stage'] },
          rls: {
            select: 'owner_id IN (SELECT id FROM crm.users WHERE manager_id = ctx.uid OR id = ctx.uid)',
            update: 'owner_id IN (SELECT id FROM crm.users WHERE manager_id = ctx.uid OR id = ctx.uid)',
          },
        },
      },
    }
    return { model, catalog, context: ctx }
  }

  // rep: only their OWN deals, NO commission column; directory without password
  const model: PermissionModel = {
    defaultSchema: 'crm',
    tables: {
      'crm.users': { select: { columns: ['id', 'username', 'full_name', 'role'] } },
      'crm.deals': {
        select: { columns: ['id', 'title', 'amount', 'stage', 'owner_id'] }, // commission hidden
        update: { columns: ['amount', 'stage'] },
        rls: { select: 'owner_id = ctx.uid', update: 'owner_id = ctx.uid' },
      },
    },
  }
  return { model, catalog, context: ctx }
}

// ── 4. Who can log in (password == username for the demo) ──────────────────────
const directory: Record<string, { id: number; role: string }> = {
  admin: { id: 1, role: 'admin' },
  maya: { id: 2, role: 'manager' },
  rita: { id: 3, role: 'rep' },
  rob: { id: 4, role: 'rep' },
}

let db: PGlite
let server: ReturnType<typeof createProxyServer>
let port = 0
const log: string[] = []

beforeAll(async () => {
  db = await PGlite.create()
  await db.exec(SCHEMA)

  // The proxy authenticates each connection and maps it to that user's policy.
  const authenticate = (params: ClientParameters, password: string): ResolvedPolicy | null => {
    const user = directory[params.user ?? '']
    if (!user || password !== params.user) return null // demo: password == username
    return policyFor(user.role, user.id)
  }
  const backend = backendFromQuery((sql, p) => db.query<unknown[]>(sql, p, { rowMode: 'array' }))
  server = createProxyServer({ authenticate, backend })
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r))
  port = (server.address() as AddressInfo).port
})

afterAll(async () => {
  await new Promise<void>((res) => server.close(() => res()))
  await db.close()
  writeFileSync('/tmp/crm-demo.txt', log.join('\n') + '\n')
})

/** Connect to the proxy AS a given user and run a query. */
async function asUser<T>(username: string, fn: (c: Client) => Promise<T>): Promise<T> {
  const client = new Client({ host: '127.0.0.1', port, user: username, password: username, database: 'crm' })
  await client.connect()
  try {
    return await fn(client)
  } finally {
    await client.end()
  }
}

function note(s: string): void {
  log.push(s)
}

describe('CRM example: role-based access through the proxy', () => {
  it('the SAME query returns different rows/columns per role', async () => {
    const rita = await asUser('rita', (c) => c.query('SELECT * FROM deals ORDER BY id').then((r) => r.rows))
    const rob = await asUser('rob', (c) => c.query('SELECT * FROM deals ORDER BY id').then((r) => r.rows))
    const maya = await asUser('maya', (c) => c.query('SELECT * FROM deals ORDER BY id').then((r) => r.rows))
    const admin = await asUser('admin', (c) => c.query('SELECT * FROM deals ORDER BY id').then((r) => r.rows))

    note('=== SELECT * FROM deals  (same query, four different users) ===')
    note(`rita (rep):  ${rita.length} rows  ${JSON.stringify(rita)}`)
    note(`rob  (rep):  ${rob.length} rows  ${JSON.stringify(rob)}`)
    note(`maya (mgr):  ${maya.length} rows  ${JSON.stringify(maya)}`)
    note(`admin:       ${admin.length} rows`)

    // rep sees ONLY their own deals, and the commission column is gone
    expect(rita.map((d) => d.id)).toEqual([10, 11])
    expect(rita.every((d) => !('commission' in d))).toBe(true)
    expect(rob.map((d) => d.id)).toEqual([12, 13])
    // manager sees the whole team's deals, WITH commission
    expect(maya.map((d) => d.id)).toEqual([10, 11, 12, 13])
    expect(maya.every((d) => 'commission' in d)).toBe(true)
    // admin sees everything
    expect(admin.map((d) => d.id)).toEqual([10, 11, 12, 13])
  })

  it('a rep is refused a column they may not read', async () => {
    note('\n=== rita asks for a forbidden column ===')
    await asUser('rita', async (c) => {
      await expect(c.query('SELECT commission FROM deals')).rejects.toThrow(/commission/)
      note('rita: SELECT commission FROM deals  ->  REFUSED (commission of crm.deals not readable)')
    })
  })

  it('nobody but admin can read password hashes', async () => {
    note('\n=== password hashes are hidden from non-admins ===')
    await asUser('rita', async (c) => {
      await expect(c.query('SELECT password_hash FROM users')).rejects.toThrow(/password_hash/)
      note('rita:  SELECT password_hash FROM users  ->  REFUSED')
    })
    await asUser('maya', async (c) => {
      await expect(c.query('SELECT password_hash FROM users')).rejects.toThrow(/password_hash/)
      note('maya:  SELECT password_hash FROM users  ->  REFUSED')
    })
    const adminCan = await asUser('admin', (c) => c.query('SELECT id, password_hash FROM users').then((r) => r.rowCount))
    note(`admin: SELECT password_hash FROM users  ->  OK (${adminCan} rows)`)
    expect(adminCan).toBe(4)
  })

  it('RLS protects writes too: a rep cannot modify a teammate’s deal', async () => {
    note('\n=== rita tries to edit rob’s deal (id 12) vs her own (id 10) ===')
    const other = await asUser('rita', (c) => c.query("UPDATE deals SET stage = 'won' WHERE id = 12"))
    const mine = await asUser('rita', (c) => c.query("UPDATE deals SET stage = 'closed' WHERE id = 10"))
    note(`rita UPDATE rob's deal 12  ->  ${other.rowCount} rows changed (blocked by RLS)`)
    note(`rita UPDATE her deal 10    ->  ${mine.rowCount} rows changed`)
    expect(other.rowCount).toBe(0) // RLS scoped it to her rows → no-op
    expect(mine.rowCount).toBe(1)
    // prove rob's deal is untouched in the real DB
    const stage12 = await db.query<unknown[]>('SELECT stage FROM crm.deals WHERE id = 12', [], { rowMode: 'array' })
    expect(stage12.rows[0]?.[0]).toBe('open')
  })

  it('shows what the proxy actually forwards to Postgres for a rep', async () => {
    // analyze() directly, to print the rewritten SQL the rep's `SELECT *` becomes
    const d = await analyze('SELECT * FROM deals', policyFor('rep', 3))
    note('\n=== what the proxy forwards for rita’s "SELECT * FROM deals" ===')
    if (d.allow) note(d.sql.replace(/\s+/g, ' '))
    expect(d.allow).toBe(true)
    if (d.allow) {
      expect(d.sql).not.toContain('commission') // column dropped
      expect(d.sql).toMatch(/owner_id = 3/) // RLS pinned to rita
    }
  })
})
