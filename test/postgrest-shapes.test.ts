import { describe, expect, it } from 'vitest'
import { analyze } from '../src/analyzer/index'
import { MemoryCatalog } from '../src/schema/memory-catalog'
import type { PermissionModel } from '../src/policy/model'

/**
 * Real-world coverage: the SQL shapes PostgREST generates. All actual table
 * access hides inside a `WITH pgrst_source AS (...)` CTE and LATERAL subqueries,
 * and rows/columns are projected through whole-row JSON builders
 * (json_agg/to_jsonb/row_to_json/…). The analyzer must recurse into the CTE /
 * LATERAL, expand `t.*` to permitted columns there, RLS-wrap every relation
 * occurrence (incl. the embedded child and the count CTE), and treat a whole-row
 * reference as a read of every column. `secret` (clients) and `internal`
 * (projects) are the forbidden columns; if either reaches the output, it's a leak.
 */
const catalog = new MemoryCatalog({
  tables: {
    'public.clients': ['id', 'name', 'secret'],
    'public.projects': ['id', 'name', 'client_id', 'internal'],
  },
})
const model: PermissionModel = {
  tables: {
    'public.clients': { select: { columns: ['id', 'name'] }, rls: { select: 'id > 0' } },
    'public.projects': { select: { columns: ['id', 'name', 'client_id'] }, rls: { select: 'id > 0' } },
  },
}
const run = (sql: string) => analyze(sql, { model, catalog, context: { ctx: {} } })

describe('whole-row JSON builders over a restricted table are denied', () => {
  // PostgREST projects rows through these; each is an all-columns read of the row.
  const WHOLE_ROW = [
    'json_agg(clients)', 'jsonb_agg(clients)', 'to_json(clients)', 'to_jsonb(clients)',
    'row_to_json(clients)', "json_build_object('c', clients)", 'jsonb_build_array(clients)',
    'array_agg(clients)',
  ]
  it.each(WHOLE_ROW.map((e): [string, string] => [e, `SELECT ${e} FROM clients`]))(
    'denies %s',
    async (_e, sql) => {
      expect((await run(sql)).allow, sql).toBe(false)
    },
  )
})

describe('PostgREST query envelope', () => {
  it('expands clients.* inside the pgrst_source CTE without leaking secret', async () => {
    const d = await run(
      "WITH pgrst_source AS ( SELECT clients.* FROM clients ) " +
        "SELECT coalesce(json_agg(_postgrest_t), '[]') AS body FROM ( SELECT * FROM pgrst_source ) _postgrest_t",
    )
    expect(d.allow).toBe(true)
    if (d.allow) {
      expect(d.sql).not.toMatch(/secret/)
      expect(d.sql).toContain('clients.id')
      expect(d.sql).toContain('id > 0') // RLS wrap reached the relation inside the CTE
    }
  })
  it('denies an explicit forbidden column inside the CTE', async () => {
    const d = await run(
      'WITH pgrst_source AS ( SELECT id, secret FROM clients ) ' +
        'SELECT json_agg(_postgrest_t) FROM ( SELECT * FROM pgrst_source ) _postgrest_t',
    )
    expect(d.allow).toBe(false)
  })
})

describe('resource embedding (LATERAL) and the count CTE', () => {
  it('to-many embed authorizes the child and does not leak projects.internal', async () => {
    const d = await run(
      `WITH pgrst_source AS (
         SELECT clients.id, clients.name, COALESCE(p.j, '[]') AS projects
         FROM clients
         LEFT JOIN LATERAL ( SELECT json_agg(projects)::jsonb AS j
                             FROM ( SELECT projects.* FROM projects WHERE projects.client_id = clients.id ) projects ) p ON TRUE
       ) SELECT coalesce(json_agg(_postgrest_t), '[]') AS body FROM ( SELECT * FROM pgrst_source ) _postgrest_t`,
    )
    expect(d.allow).toBe(true)
    if (d.allow) {
      expect(d.sql).not.toMatch(/internal/)
      expect((d.sql.match(/id > 0/g) ?? []).length).toBeGreaterThanOrEqual(2) // both relations wrapped
    }
  })
  it('RLS-wraps the pgrst_source_count CTE too (no row-count probing bypass)', async () => {
    const d = await run(
      "WITH pgrst_source AS ( SELECT clients.id FROM clients LIMIT 10 ), " +
        "pgrst_source_count AS ( SELECT 1 FROM clients ) " +
        "SELECT (SELECT count(*) FROM pgrst_source_count) AS total, " +
        "coalesce(json_agg(_postgrest_t), '[]') AS body FROM ( SELECT * FROM pgrst_source ) _postgrest_t",
    )
    expect(d.allow).toBe(true)
    if (d.allow) expect((d.sql.match(/id > 0/g) ?? []).length).toBeGreaterThanOrEqual(2)
  })
  it('a computed column over a whole row is a read of every column (denied)', async () => {
    expect((await run('SELECT full_name(clients) FROM clients')).allow).toBe(false)
  })
  it('full-text search operators are permitted', async () => {
    expect((await run('SELECT clients.id FROM clients WHERE to_tsvector(clients.name) @@ to_tsquery($1)')).allow).toBe(true)
  })
})

describe('known limit: SETOF-table-returning RPC is a DB-object-opacity passthrough', () => {
  // `getallprojects() RETURNS SETOF projects` projects every column of projects,
  // and we cannot see inside the function body. In denylist mode the call is
  // permitted; the mitigation is functions allowlist mode + a least-privilege
  // backend role. Pinned here so the limit is explicit, not accidental.
  it('permits a table-returning function call (mitigated operationally)', async () => {
    expect((await run('SELECT * FROM getallprojects() pgrst_call')).allow).toBe(true)
  })
})
