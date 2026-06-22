/**
 * Locking semantics of the RLS rewrite, on a REAL Postgres (needs true concurrent
 * transactions + FOR UPDATE NOWAIT, which PGlite's single in-process instance
 * can't model — so this is gated on SQLCONTROL_TEST_PG and skipped otherwise).
 *
 * The analyzer wraps an RLS relation as `(SELECT * FROM t WHERE pred OFFSET 0) AS
 * t`. The open question was whether `SELECT ... FOR UPDATE` over that subquery
 * still takes a real row lock on the base table (or silently no-ops, which would
 * break an app's concurrency control). It does: Postgres propagates the lock
 * through the OFFSET-0 fence to the base row.
 */
import { Client } from 'pg'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { analyze } from '../src/analyzer/index'
import { MemoryCatalog } from '../src/schema/memory-catalog'
import type { PermissionModel } from '../src/policy/model'

const url = process.env.SQLCONTROL_TEST_PG

describe.skipIf(url === undefined)('real PG: FOR UPDATE locks through the RLS wrap', () => {
  let setup: Client
  beforeAll(async () => {
    setup = new Client({ connectionString: url })
    await setup.connect()
    await setup.query('DROP TABLE IF EXISTS lock_users')
    await setup.query('CREATE TABLE lock_users (id int PRIMARY KEY, email text, tenant_id int)')
    await setup.query("INSERT INTO lock_users VALUES (1, 'a', 1), (2, 'b', 2)")
  })
  afterAll(async () => {
    await setup.query('DROP TABLE IF EXISTS lock_users')
    await setup.end()
  })

  /** Whether `lockSql` run in one tx holds a lock on lock_users row 1 (a second
   *  tx's NOWAIT lock on that row then fails). */
  async function lockHeld(lockSql: string): Promise<boolean> {
    const a = new Client({ connectionString: url })
    const b = new Client({ connectionString: url })
    await a.connect()
    await b.connect()
    try {
      await a.query('BEGIN')
      await a.query(lockSql)
      await b.query('BEGIN')
      try {
        await b.query('SELECT * FROM lock_users WHERE id = 1 FOR UPDATE NOWAIT')
        return false // B got the lock → A did not hold it
      } catch {
        return true // B could not lock → A holds it
      } finally {
        await b.query('ROLLBACK')
      }
    } finally {
      await a.query('ROLLBACK')
      await a.end()
      await b.end()
    }
  }

  it('the rewritten FOR UPDATE locks the base row (lock survives the OFFSET-0 wrap)', async () => {
    // model targets `lock_users` via an aliased reference so the catalog resolves it
    const m: PermissionModel = {
      tables: { 'public.lock_users': { select: true, rls: { select: 'tenant_id = ctx.t' } } },
    }
    const cat = new MemoryCatalog({ tables: { 'public.lock_users': ['id', 'email', 'tenant_id'] } })
    const d = await analyze('SELECT id FROM lock_users WHERE id = 1 FOR UPDATE', {
      model: m,
      catalog: cat,
      context: { ctx: { t: 1 } },
    })
    expect(d.allow).toBe(true)
    if (!d.allow) return
    expect(d.sql.replace(/\s+/g, ' ')).toMatch(/OFFSET 0 \) AS lock_users WHERE id = 1 FOR UPDATE/)
    // sanity: a plain (non-locking) query holds nothing; the rewritten FOR UPDATE does
    expect(await lockHeld('SELECT id FROM lock_users WHERE id = 1')).toBe(false)
    expect(await lockHeld(d.sql)).toBe(true)
  })
})
