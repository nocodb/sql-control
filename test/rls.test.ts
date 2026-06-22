import { describe, expect, it } from 'vitest'
import { analyze } from '../src/analyzer/index'
import { ViolationCode } from '../src/analyzer/errors'
import { MemoryCatalog } from '../src/schema/memory-catalog'
import type { PermissionModel } from '../src/policy/model'

const model: PermissionModel = {
  tables: {
    'public.docs': {
      select: true,
      rls: { select: 'owner_id = ctx.user_id AND deleted = false' },
    },
    'public.users': {
      select: { columns: ['id', 'email'] },
      rls: { select: 'tenant = ctx.tenant' },
    },
    'public.tags': { select: true },
  },
}

const catalog = new MemoryCatalog({
  tables: { 'public.users': ['id', 'email', 'password'], 'public.docs': ['id', 'owner_id', 'deleted'] },
})

async function rewritten(sql: string, ctx: Record<string, string | number | boolean | null>): Promise<string> {
  const decision = await analyze(sql, { model, catalog, context: { ctx } })
  if (!decision.allow) throw new Error(`denied: ${JSON.stringify(decision.violations)}`)
  return decision.sql.replace(/\s+/g, ' ')
}

describe('RLS predicate injection', () => {
  it('wraps a relation in a row-filtering subquery with ctx substituted', async () => {
    const sql = await rewritten('SELECT id FROM docs', { user_id: 42 })
    expect(sql).toMatch(/FROM \( SELECT \* FROM public\.docs WHERE/i)
    expect(sql).toMatch(/owner_id = 42/)
    expect(sql).toMatch(/deleted = false/)
  })

  it('quotes string context values safely', async () => {
    const sql = await rewritten('SELECT id, email FROM users', { tenant: 'acme' })
    expect(sql).toMatch(/tenant = 'acme'/)
  })

  it('only wraps relations that have a policy (join)', async () => {
    const sql = await rewritten(
      'SELECT d.id, t.name FROM docs d JOIN tags t ON t.doc_id = d.id',
      { user_id: 7 },
    )
    expect(sql).toMatch(/owner_id = 7/)
    expect(sql).toMatch(/\) AS d/) // docs wrapped under its alias
    expect(sql).not.toMatch(/FROM \( SELECT \* FROM tags/) // tags has no RLS
  })

  it('composes with `*` expansion (rows filtered, columns narrowed)', async () => {
    const sql = await rewritten('SELECT * FROM users', { tenant: 't1' })
    expect(sql).toMatch(/users\.id/)
    expect(sql).toMatch(/users\.email/)
    expect(sql).not.toMatch(/password/)
    expect(sql).toMatch(/tenant = 't1'/)
  })

  it('applies RLS inside subquery scopes', async () => {
    const sql = await rewritten('SELECT x.id FROM (SELECT id FROM docs) x', { user_id: 9 })
    expect(sql).toMatch(/owner_id = 9/)
  })

  it('fails closed when a referenced context value is missing', async () => {
    const decision = await analyze('SELECT id FROM docs', { model, context: { ctx: {} } })
    expect(decision.allow).toBe(false)
    if (!decision.allow) expect(decision.violations[0]?.code).toBe(ViolationCode.RewriteFailed)
  })

  it('fails closed for a prototype-named ctx key (Object.hasOwn, not `in`)', async () => {
    // A predicate referencing an Object.prototype member must throw "missing context
    // value" rather than silently substitute the inherited member, which `key in ctx`
    // would have allowed. The SQL parser case-folds unquoted identifiers, so only the
    // already-lowercase prototype names (`constructor`, `__proto__`) are reachable —
    // exactly the ones the `in` operator would have wrongly resolved.
    for (const key of ['constructor', '__proto__']) {
      const mm: PermissionModel = {
        tables: { 'public.docs': { select: true, rls: { select: `owner_id = ctx.${key}` } } },
      }
      const d = await analyze('SELECT id FROM docs', { model: mm, context: { ctx: {} } })
      expect(d.allow, key).toBe(false)
      if (!d.allow) expect(d.violations[0]?.code, key).toBe(ViolationCode.RewriteFailed)
    }
    // sanity: a genuine own ctx key still substitutes (the guard only blocks inherited).
    const ok = await analyze('SELECT id FROM docs', {
      model: { tables: { 'public.docs': { select: true, rls: { select: 'owner_id = ctx.tenant' } } } },
      context: { ctx: { tenant: 7 } },
    })
    expect(ok.allow).toBe(true)
    if (ok.allow) expect(ok.sql.replace(/\s+/g, ' ')).toMatch(/owner_id = 7/)
  })

  it('does not wrap a relation without RLS (no row-filter subquery)', async () => {
    const decision = await analyze('SELECT name FROM tags', { model })
    expect(decision.allow).toBe(true)
    // relation is schema-qualified (F6) but no RLS subquery is injected
    if (decision.allow) expect(decision.sql).not.toMatch(/SELECT \* FROM/)
  })
})
