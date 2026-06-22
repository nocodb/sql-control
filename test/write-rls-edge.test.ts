import { describe, expect, it } from 'vitest'
import { parse } from 'pgsql-parser'
import { analyze } from '../src/analyzer/index'
import { ViolationCode } from '../src/analyzer/errors'
import { MemoryCatalog } from '../src/schema/memory-catalog'
import type { PermissionModel } from '../src/policy/model'

/**
 * Write-path RLS edge cases (UPDATE...FROM, DELETE...USING, data-modifying CTEs,
 * subqueries in SET) and injection-safety of context values. The first group
 * proves read relations of a write get RLS-wrapped and their columns gated; the
 * second proves a hostile `ctx.*` value can only ever become an escaped literal.
 */
const catalog = new MemoryCatalog({
  tables: {
    'public.accounts': ['id', 'tenant', 'balance'],
    'public.ledger': ['id', 'tenant', 'amt', 'secret'],
  },
})
const model: PermissionModel = {
  tables: {
    'public.accounts': {
      select: true,
      update: { columns: ['balance', 'tenant'] },
      delete: true,
      rls: { select: 'tenant = ctx.t', update: 'tenant = ctx.t', delete: 'tenant = ctx.t', insert: 'tenant = ctx.t' },
    },
    'public.ledger': { select: { columns: ['id', 'tenant', 'amt'] }, rls: { select: 'tenant = ctx.t' } },
  },
}
const run = (sql: string) => analyze(sql, { model, catalog, context: { ctx: { t: 1 } } })
const injections = (sql: string) => (sql.match(/tenant = 1/g) ?? []).length

describe('UPDATE...FROM / DELETE...USING wrap the read relation and gate its columns', () => {
  it('UPDATE...FROM wraps the source relation with RLS', async () => {
    const d = await run('UPDATE accounts SET balance = l.amt FROM ledger l WHERE l.id = accounts.id')
    expect(d.allow).toBe(true)
    if (d.allow) {
      expect(d.sql).toMatch(/FROM \( SELECT \* FROM public\.ledger WHERE tenant = 1 OFFSET 0 \)/)
      expect(injections(d.sql)).toBeGreaterThanOrEqual(3) // target USING + check + source wrap
    }
  })
  it('DELETE...USING wraps the read relation with RLS', async () => {
    const d = await run('DELETE FROM accounts USING ledger l WHERE l.id = accounts.id')
    expect(d.allow).toBe(true)
    if (d.allow) expect(d.sql).toMatch(/USING \( SELECT \* FROM public\.ledger WHERE tenant = 1 OFFSET 0 \)/)
  })
  it('denies a forbidden column read through FROM / USING', async () => {
    expect((await run('UPDATE accounts SET balance = l.secret FROM ledger l WHERE l.id = accounts.id')).allow).toBe(false)
    expect((await run("DELETE FROM accounts USING ledger l WHERE l.secret = 'x'")).allow).toBe(false)
  })
  it('UPDATE...FROM new-row check references the source value', async () => {
    const d = await run('UPDATE accounts SET tenant = l.tenant FROM ledger l WHERE l.id = accounts.id')
    expect(d.allow).toBe(true)
    if (d.allow) expect(d.sql).toContain('l.tenant = 1') // WITH CHECK on the new tenant
  })
})

describe('data-modifying CTE writes are RLS-filtered', () => {
  it('UPDATE in a CTE gets the USING filter', async () => {
    const d = await run('WITH x AS (UPDATE accounts SET balance = 0 WHERE id = 5 RETURNING id) SELECT * FROM x')
    expect(d.allow).toBe(true)
    if (d.allow) expect(injections(d.sql)).toBeGreaterThanOrEqual(2)
  })
  it('DELETE in a CTE gets the USING filter', async () => {
    const d = await run('WITH x AS (DELETE FROM accounts WHERE id = 5 RETURNING id) SELECT * FROM x')
    expect(d.allow).toBe(true)
    if (d.allow) expect(d.sql).toContain('accounts.tenant = 1')
  })
})

describe('subquery in a SET value is gated and RLS-wrapped', () => {
  it('denies a forbidden column read in a SET subquery', async () => {
    expect((await run("UPDATE accounts SET balance = (SELECT secret FROM ledger LIMIT 1) WHERE id = 5")).allow).toBe(false)
  })
  it('wraps an allowed SET subquery source with RLS', async () => {
    const d = await run("UPDATE accounts SET balance = (SELECT amt FROM ledger LIMIT 1) WHERE id = 5")
    expect(d.allow).toBe(true)
    if (d.allow) expect(d.sql).toMatch(/SELECT amt FROM \( SELECT \* FROM public\.ledger WHERE tenant = 1 OFFSET 0 \)/)
  })
})

describe('FOR UPDATE OF target stays unqualified after schema-qualification', () => {
  // qualifyRelations must NOT schema-qualify a lock target — Postgres rejects
  // `FOR UPDATE OF public.u` ("must specify unqualified relation names").
  const m: PermissionModel = { tables: { 'public.users': { select: { columns: ['id', 'email'] } }, 'public.orders': { select: true } } }
  const lock = (sql: string) => analyze(sql, { model: m, context: { ctx: {} } })

  it('keeps the lock-target alias unqualified while qualifying the FROM relation', async () => {
    const d = await lock('SELECT id FROM users u FOR UPDATE OF u')
    expect(d.allow).toBe(true)
    if (d.allow) {
      expect(d.sql).toContain('FROM public.users') // FROM still qualified
      expect(d.sql).toMatch(/FOR UPDATE OF u$/) // lock target NOT qualified
      expect(d.sql).not.toContain('OF public.u')
    }
  })
  it('keeps an unqualified table lock target', async () => {
    const d = await lock('SELECT id FROM users FOR UPDATE OF users')
    expect(d.allow).toBe(true)
    if (d.allow) expect(d.sql).toMatch(/FOR UPDATE OF users$/)
  })
  it('handles multiple lock targets and FOR SHARE', async () => {
    const d = await lock('SELECT u.id FROM users u JOIN orders o ON o.id = u.id FOR UPDATE OF u, o')
    expect(d.allow).toBe(true)
    if (d.allow) expect(d.sql).toContain('FOR UPDATE OF u, o')
    const s = await lock('SELECT email FROM users u FOR SHARE OF u')
    expect(s.allow).toBe(true)
    if (s.allow) expect(s.sql).toMatch(/FOR SHARE OF u$/)
  })
})

describe('context values are escaped — never SQL injection', () => {
  const m: PermissionModel = { tables: { 'public.t': { select: { columns: ['id'] }, rls: { select: 'name = ctx.n' } } } }
  const withCtx = (n: string | number | boolean | null) =>
    analyze('SELECT id FROM t', { model: m, context: { ctx: { n } } })

  const HOSTILE: [string, string][] = [
    ['quote-or', "x' OR '1'='1"],
    ['quote-semicolon', "x'; DROP TABLE t; --"],
    ['quote-comment', "'--"],
    ['quote-union', "' UNION SELECT 1 --"],
  ]
  it.each(HOSTILE)('neutralizes %s into a single escaped literal', async (_l, value) => {
    const d = await withCtx(value)
    expect(d.allow).toBe(true)
    if (d.allow) {
      // The forwarded SQL must still be exactly one statement (no injected break).
      const reparsed = await parse(d.sql)
      expect(reparsed.stmts?.length).toBe(1)
      // and the hostile single-quote must have been doubled (escaped).
      expect(d.sql).toContain("''")
    }
  })
  it('renders typed literals for non-strings', async () => {
    expect((await withCtx(42)).allow).toBe(true)
    expect((await withCtx(true)).allow).toBe(true)
    expect((await withCtx(null)).allow).toBe(true)
  })
})
