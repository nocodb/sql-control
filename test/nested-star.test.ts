import { describe, expect, it } from 'vitest'
import { analyze } from '../src/analyzer/index'
import { MemoryCatalog } from '../src/schema/memory-catalog'
import type { PermissionModel } from '../src/policy/model'

/**
 * Nested `SELECT *` expansion. The star directly over a column-restricted base
 * relation must be expanded to its permitted columns; a star over a *derived*
 * source (subquery / CTE / lateral) may remain, because that source already
 * exposes only permitted columns. A regression here (an unexpanded base-table
 * star) would let the backend expand it to every column — a leak. So each case
 * asserts: allowed, the inner star expanded, and `password` never reaches output.
 */
const catalog = new MemoryCatalog({ tables: { 'public.users': ['id', 'email', 'password'], 'public.o': ['id', 'uid'] } })
const model: PermissionModel = {
  tables: { 'public.users': { select: { columns: ['id', 'email'] } }, 'public.o': { select: true } },
}
const run = (sql: string) => analyze(sql, { model, catalog, context: { ctx: {} } })

const SAFE: [string, string][] = [
  ['nested star over star', 'SELECT * FROM (SELECT * FROM users) sub'],
  ['subquery t.* over star', 'SELECT sub.* FROM (SELECT * FROM users) sub'],
  ['cte star over star', 'WITH c AS (SELECT * FROM users) SELECT * FROM c'],
  ['two subqueries', 'SELECT * FROM (SELECT * FROM users) a, (SELECT * FROM users) b'],
  ['deeply nested', 'SELECT * FROM (SELECT * FROM (SELECT * FROM users) x) y'],
  ['star in union subquery', 'SELECT * FROM (SELECT * FROM users UNION SELECT * FROM users) s'],
  ['lateral star', 'SELECT * FROM o, LATERAL (SELECT * FROM users WHERE id = o.uid) u'],
  ['star over joined subquery', 'SELECT * FROM o JOIN (SELECT * FROM users) u ON u.id = o.uid'],
]

describe('nested SELECT * never leaks a restricted column', () => {
  it.each(SAFE)('%s: expands the base-table star, no password', async (_l, sql) => {
    const d = await run(sql)
    expect(d.allow, sql).toBe(true)
    if (d.allow) {
      expect(d.sql, sql).not.toMatch(/password/)
      // the star touching the restricted base relation was expanded to its columns
      expect(d.sql, sql).toContain('users.id')
      expect(d.sql, sql).toContain('users.email')
    }
  })

  it('denies an explicit forbidden column inside a subquery', async () => {
    const d = await run('SELECT id FROM (SELECT id, password FROM users) sub')
    expect(d.allow).toBe(false)
  })
})
