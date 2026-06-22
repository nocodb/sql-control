import { describe, expect, it } from 'vitest'
import { analyze } from '../src/analyzer/index'
import { ViolationCode } from '../src/analyzer/errors'
import { MemoryCatalog } from '../src/schema/memory-catalog'
import type { PermissionModel } from '../src/policy/model'

/**
 * Cross-feature interaction regressions — combinations where one control could
 * mask a gap in another (schema-qualified calls, aliased joins, writes hidden in
 * set-op/subquery CTE arms, deep nesting). Each pins behaviour verified by
 * running `analyze()`.
 */
const model: PermissionModel = {
  tables: {
    'public.users': { select: { columns: ['id', 'email'] } },
    'public.orders': { select: true },
  },
}
const catalog = new MemoryCatalog({
  tables: { 'public.users': ['id', 'email', 'password'], 'public.orders': ['id', 'uid'] },
})
const run = (sql: string) => analyze(sql, { model, catalog, context: { ctx: {} } })
async function code(sql: string): Promise<ViolationCode | undefined> {
  const d = await run(sql)
  return d.allow ? undefined : d.violations[0]?.code
}
const allowed = async (sql: string) => (await run(sql)).allow

describe('schema-qualified call gating', () => {
  it('blocks a dangerous function called via its catalog schema', async () => {
    expect(await code("SELECT pg_catalog.pg_read_file('/etc/passwd')")).toBe(
      ViolationCode.FunctionNotAllowed,
    )
    expect(await code("SELECT pg_catalog.set_config('search_path', 'x', false)")).toBe(
      ViolationCode.FunctionNotAllowed,
    )
    expect(await code("SELECT * FROM pg_catalog.dblink('x', 'SELECT 1') AS t(a int)")).toBe(
      ViolationCode.FunctionNotAllowed,
    )
  })
})

describe('aliased join `(a JOIN b) x`', () => {
  const J = '(users a JOIN orders b ON a.id = b.uid) x'
  it('allows a permitted column through the join alias', async () => {
    expect(await allowed(`SELECT x.email FROM ${J}`)).toBe(true)
  })
  it('blocks a forbidden column through the join alias', async () => {
    expect(await code(`SELECT x.password FROM ${J}`)).toBe(ViolationCode.ColumnNotReadable)
  })
  it('blocks `x.*` over the join alias (restricted relation in it)', async () => {
    expect(await code(`SELECT x.* FROM ${J}`)).toBe(ViolationCode.ColumnNotReadable)
    expect(await code(`SELECT jsonb_build_array(x.*) FROM ${J}`)).toBe(
      ViolationCode.ColumnNotReadable,
    )
  })
})

describe('writes hidden in set-op / subquery CTE arms are still checked', () => {
  it('catches a DELETE in a set-operation arm CTE', async () => {
    expect(
      await code('SELECT 1 UNION (WITH w AS (DELETE FROM users RETURNING id) SELECT id FROM w)'),
    ).toBe(ViolationCode.DeleteNotAllowed)
  })
  it('catches an UPDATE in a nested subquery CTE', async () => {
    expect(
      await code("SELECT * FROM (WITH w AS (UPDATE users SET email = 'x' RETURNING id) SELECT id FROM w) z"),
    ).toBe(ViolationCode.UpdateNotAllowed)
  })
})

describe('MERGE is blocked', () => {
  it('rejects MERGE as a non-DML statement', async () => {
    expect(
      await code('MERGE INTO orders t USING users s ON t.uid = s.id WHEN MATCHED THEN UPDATE SET uid = 1'),
    ).toBe(ViolationCode.StatementNotAllowed)
  })
})

describe('F6: schema-qualify relations to defeat search_path divergence', () => {
  // Default `public` (defaultSchema unset) — the exact case the PoC exploits.
  const def: PermissionModel = {
    tables: {
      'public.users': { select: { columns: ['id', 'email'] }, update: { columns: ['email'] } },
    },
    introspection: { enabled: true },
  }
  const out = async (sql: string, m: PermissionModel = def): Promise<string> => {
    const d = await analyze(sql, { model: m, context: { ctx: {} } })
    if (!d.allow) throw new Error(`denied: ${JSON.stringify(d.violations)}`)
    return d.sql.replace(/\s+/g, ' ')
  }

  it('qualifies an unqualified read relation even with defaultSchema unset (default public)', async () => {
    expect(await out('SELECT id FROM users')).toMatch(/FROM public\.users/)
  })
  it('qualifies to an explicit per-tenant defaultSchema', async () => {
    const tenant: PermissionModel = {
      defaultSchema: 'tenant_7',
      tables: { 'tenant_7.users': { select: { columns: ['id'] } } },
    }
    expect(await out('SELECT id FROM users', tenant)).toMatch(/FROM tenant_7\.users/)
  })
  it('qualifies an unqualified write target', async () => {
    expect(await out("UPDATE users SET email = 'x' WHERE id = 1")).toMatch(/UPDATE public\.users/)
  })
  it('qualifies a pg_* catalog reference to pg_catalog (not defaultSchema)', async () => {
    expect(await out('SELECT attname FROM pg_attribute')).toMatch(/FROM pg_catalog\.pg_attribute/)
  })
  it('does NOT mis-route a user table named pg_foo to pg_catalog', async () => {
    // introspection off → `pg_foo` is a user table, must go to defaultSchema
    const m: PermissionModel = {
      defaultSchema: 'app',
      tables: { 'app.pg_foo': { select: { columns: ['id'] } } },
    }
    expect(await out('SELECT id FROM pg_foo', m)).toMatch(/FROM app\.pg_foo/)
  })
  it('leaves CTE references unqualified (not schema objects)', async () => {
    const sql = await out('WITH u AS (SELECT id FROM users) SELECT * FROM u')
    expect(sql).toMatch(/FROM public\.users/) // the inner table
    expect(sql).toMatch(/\) SELECT \* FROM u/) // the CTE ref stays `u`
  })
})

describe('deep nesting is bounded by the parser, not a crash', () => {
  it('analyzes within the parser depth limit and rejects beyond it (no stack overflow)', async () => {
    const nest = (n: number) => `SELECT 1 WHERE ${'('.repeat(n)}1 = 1${')'.repeat(n)}`
    // well within libpg_query's limit — must not throw
    expect(await allowed(nest(2000))).toBe(true)
    // beyond the parser's nesting limit — a clean parse error, never a crash
    expect(await code(nest(50000))).toBe(ViolationCode.ParseError)
  })
})
