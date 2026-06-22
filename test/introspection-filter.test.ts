import { describe, expect, it } from 'vitest'
import { analyze } from '../src/analyzer/index'
import { ViolationCode } from '../src/analyzer/errors'
import { FILTERABLE_CATALOGS } from '../src/policy/system-catalogs'
import { MemoryCatalog } from '../src/schema/memory-catalog'
import type { PermissionModel } from '../src/policy/model'

/**
 * The introspection row-filter boundary. With introspection on, the few
 * filterable catalogs are rewritten so a client only ever browses permitted
 * schemas/tables/columns; every other catalog is deny-most; sensitive catalogs
 * stay blocked even when opted in. These pin the rewrite shape (predicate +
 * `OFFSET 0` fence), alias/JOIN handling, column hiding, and the deny-most floor.
 */
const catalog = new MemoryCatalog({
  tables: { 'public.users': ['id', 'email', 'password'], 'public.orders': ['id', 'total'] },
})
const model: PermissionModel = {
  tables: {
    'public.users': { select: { columns: ['id', 'email'] } },
    'public.orders': { select: true },
    'public.secret_t': { select: false },
  },
  introspection: { enabled: true },
}
const run = (sql: string, m: PermissionModel = model) =>
  analyze(sql, { model: m, catalog, context: { ctx: {} } })

describe('filterable catalogs are allowed and rewritten (incl. aliased / unqualified)', () => {
  const cases: [string, string][] = [
    ['pg_class qualified', 'SELECT relname FROM pg_catalog.pg_class'],
    ['pg_class unqualified', 'SELECT relname FROM pg_class'],
    ['pg_class aliased', 'SELECT c.relname FROM pg_catalog.pg_class c'],
    ['pg_namespace', 'SELECT nspname FROM pg_catalog.pg_namespace'],
    ['pg_namespace aliased', 'SELECT n.nspname FROM pg_namespace n'],
    ['pg_attribute', 'SELECT attname FROM pg_catalog.pg_attribute'],
    ['pg_attribute aliased', 'SELECT a.attname FROM pg_attribute a'],
    ['info.tables', 'SELECT table_name FROM information_schema.tables'],
    ['info.tables aliased', 'SELECT t.table_name FROM information_schema.tables t'],
    ['info.views', 'SELECT table_name FROM information_schema.views'],
    ['info.columns', 'SELECT column_name FROM information_schema.columns'],
    ['info.columns aliased', 'SELECT col.column_name FROM information_schema.columns col'],
    ['info.schemata', 'SELECT schema_name FROM information_schema.schemata'],
    ['info.table_privileges', 'SELECT table_name FROM information_schema.table_privileges'],
    ['info.column_privileges', 'SELECT column_name FROM information_schema.column_privileges'],
  ]
  it.each(cases)('allows + fences %s', async (_label, sql) => {
    const d = await run(sql)
    expect(d.allow, sql).toBe(true)
    if (d.allow) expect(d.sql).toContain('OFFSET 0') // the row-filter wrap is present
  })
})

// INVARIANT: every catalog on the FILTERABLE allowlist (`check.ts` permits these
// under introspection) MUST have a row-filter builder in `introspection.ts`. If an
// entry were added to FILTERABLE_CATALOGS without a matching FILTERS builder, the
// analyzer would *permit* it (it's on the allowlist) but the rewriter would skip
// it (`if (!build) continue`), passing every row through UNFILTERED — a silent
// object/data leak. This test is coupled to the real exported set, so it fails the
// moment the two drift apart. `SELECT 1 FROM` avoids per-catalog column resolution;
// the row-filter wrap (`OFFSET 0` fence) is applied to the relation regardless.
describe('INVARIANT: every FILTERABLE catalog is actually row-filtered (no allowlist/builder drift)', () => {
  it.each([...FILTERABLE_CATALOGS].map((c): [string, string] => [c, c]))(
    '%s is permitted AND wrapped in a row-filter (never passed through unfiltered)',
    async (key, _x) => {
      const d = await run(`SELECT 1 FROM ${key}`)
      expect(d.allow, key).toBe(true)
      // The filter wrap must be present — its absence means the catalog is on the
      // allowlist but has no predicate builder, leaking every row.
      if (d.allow) expect(d.sql, `${key} permitted but NOT row-filtered`).toContain('OFFSET 0')
    },
  )
})

describe('column catalogs hide non-readable columns', () => {
  it('information_schema.columns restricts column_name to the readable set', async () => {
    const d = await run('SELECT column_name FROM information_schema.columns')
    expect(d.allow).toBe(true)
    if (d.allow) {
      expect(d.sql).toContain("column_name IN ('id', 'email')")
      expect(d.sql).not.toContain('password')
    }
  })
  it('pg_attribute restricts attname to the readable set', async () => {
    const d = await run('SELECT attname FROM pg_catalog.pg_attribute')
    expect(d.allow).toBe(true)
    if (d.allow) {
      expect(d.sql).toContain("attname IN ('id', 'email')")
      expect(d.sql).not.toContain('password')
    }
  })
  it('a JOIN of two catalogs filters each arm independently', async () => {
    const d = await run(
      'SELECT c.relname, a.attname FROM pg_catalog.pg_class c JOIN pg_catalog.pg_attribute a ON a.attrelid = c.oid',
    )
    expect(d.allow).toBe(true)
    if (d.allow) {
      expect(d.sql).toContain("pg_class.relname = 'users'")
      expect(d.sql).toContain("attname IN ('id', 'email')")
    }
  })
  it('object catalogs exclude an explicitly-denied table', async () => {
    const d = await run('SELECT table_name FROM information_schema.tables')
    expect(d.allow).toBe(true)
    if (d.allow) expect(d.sql).toContain("NOT ((table_schema = 'public' AND table_name = 'secret_t'))")
  })
})

// Deny-most: any catalog without a row-filter is refused unless opted in. None of
// these are in FILTERABLE_CATALOGS, so introspection-on must still reject them.
const DENY_MOST_CATALOGS = [
  'pg_proc', 'pg_operator', 'pg_aggregate', 'pg_am', 'pg_amop', 'pg_amproc',
  'pg_language', 'pg_rewrite', 'pg_trigger', 'pg_event_trigger', 'pg_description',
  'pg_cast', 'pg_index', 'pg_constraint', 'pg_inherits', 'pg_depend',
  'pg_database', 'pg_tablespace', 'pg_auth_members', 'pg_roles', 'pg_settings',
  'pg_policy', 'pg_publication', 'pg_publication_rel', 'pg_default_acl', 'pg_init_privs',
  'pg_seclabel', 'pg_shdepend', 'pg_shdescription', 'pg_foreign_data_wrapper',
  'pg_foreign_server', 'pg_foreign_table', 'pg_opclass', 'pg_opfamily', 'pg_collation',
  'pg_conversion', 'pg_ts_config', 'pg_ts_dict', 'pg_ts_parser', 'pg_ts_template',
  'pg_extension', 'pg_transform', 'pg_sequence', 'pg_partitioned_table',
  'pg_attrdef', 'pg_statistic_ext', 'pg_replication_slots', 'pg_stat_activity',
  'pg_locks', 'pg_prepared_xacts', 'pg_prepared_statements', 'pg_cursors',
  'pg_views', 'pg_tables', 'pg_indexes', 'pg_matviews', 'pg_sequences',
  'pg_stat_user_tables', 'pg_stat_all_tables', 'pg_timezone_names', 'pg_file_settings',
]

describe('deny-most: unfilterable catalogs are refused under introspection', () => {
  it.each(DENY_MOST_CATALOGS.map((c): [string, string] => [c, c]))(
    'refuses %s',
    async (rel, _x) => {
      const d = await run(`SELECT * FROM ${rel}`)
      expect(d.allow, rel).toBe(false)
      if (!d.allow) expect(d.violations[0]?.code, rel).toBe(ViolationCode.IntrospectionNotAllowed)
    },
  )
})

// The only filterable information_schema views are tables/views/columns/
// *_privileges/schemata. Everything else — incl. routines (routine_definition =
// function source), parameters, *_column_usage (leaks constraint column names) —
// is deny-most, so it can't be browsed unless explicitly opted in.
const INFO_SCHEMA_DENY_MOST = [
  'routines', 'parameters', 'key_column_usage', 'constraint_column_usage',
  'referential_constraints', 'triggers', 'check_constraints', 'view_column_usage',
  'role_table_grants', 'role_column_grants', 'element_types', 'sequences', 'domains',
  'table_constraints', 'views_with_no_filter', 'usage_privileges',
]
describe('deny-most: long-tail information_schema views are refused', () => {
  it.each(INFO_SCHEMA_DENY_MOST.map((v): [string, string] => [v, v]))(
    'refuses information_schema.%s',
    async (view, _x) => {
      const d = await run(`SELECT * FROM information_schema.${view}`)
      expect(d.allow, view).toBe(false)
      if (!d.allow) expect(d.violations[0]?.code, view).toBe(ViolationCode.IntrospectionNotAllowed)
    },
  )
})

describe('pg_class / pg_attribute restrict to browsable relkinds (no dependent-object leak)', () => {
  // A schema-wide grant with an explicit table denial must not leak the denied
  // table's existence through its index/sequence rows (different relnames).
  const m: PermissionModel = {
    schemas: { public: { defaultTablePolicy: { select: true } } },
    tables: { 'public.secret_tbl': { select: false } },
    introspection: { enabled: true },
  }
  const RELKINDS = "relkind IN ('r', 'v', 'm', 'f', 'p')"
  it('pg_class filters out indexes/sequences/toast/composite via relkind', async () => {
    const d = await analyze('SELECT relname FROM pg_catalog.pg_class', { model: m, context: { ctx: {} } })
    expect(d.allow).toBe(true)
    if (d.allow) {
      expect(d.sql).toContain(`pg_class.${RELKINDS}`)
      // the denied table itself is still excluded by name
      expect(d.sql).toContain("pg_class.relname = 'secret_tbl'")
    }
  })
  it('pg_attribute also restricts the correlated relation by relkind', async () => {
    const d = await analyze('SELECT attname FROM pg_catalog.pg_attribute', { model: m, context: { ctx: {} } })
    expect(d.allow).toBe(true)
    if (d.allow) expect(d.sql).toContain(`c.${RELKINDS}`)
  })
})

describe('driver type catalogs (pg_type/pg_range/pg_enum) are filtered, not leaked', () => {
  const off: PermissionModel = { tables: { 'public.users': { select: { columns: ['id'] } } } }
  const on: PermissionModel = { tables: { 'public.users': { select: { columns: ['id'] } } }, introspection: { enabled: true } }
  it('are denied by default; allowed but ROW-FILTERED when introspection is enabled', async () => {
    for (const cat of ['pg_type', 'pg_range', 'pg_enum']) {
      expect((await analyze(`SELECT oid FROM pg_catalog.${cat}`, { model: off, context: { ctx: {} } })).allow, cat).toBe(false)
      const d = await analyze(`SELECT oid FROM pg_catalog.${cat}`, { model: on, context: { ctx: {} } })
      expect(d.allow, cat).toBe(true)
      // not a passthrough — the row-filter wrap (OFFSET 0 fence) must be present
      if (d.allow) expect(d.sql, cat).toContain('OFFSET 0')
    }
  })
  it('pg_type filter shows built-ins + permitted-relation composites only (no table-name leak)', async () => {
    const d = await analyze('SELECT typname FROM pg_catalog.pg_type', { model: on, context: { ctx: {} } })
    expect(d.allow).toBe(true)
    if (d.allow) {
      expect(d.sql).toContain('pg_catalog') // built-in types allowed
      expect(d.sql).toContain('typrelid') // composite types gated by relation visibility
      expect(d.sql).toMatch(/relname = 'users'/) // only the permitted relation's composite type
    }
  })
  it('do not extend to pg_proc (function source stays denied even with introspection on)', async () => {
    const d = await analyze('SELECT prosrc FROM pg_catalog.pg_proc', { model: on, context: { ctx: {} } })
    expect(d.allow).toBe(false)
    if (!d.allow) expect(d.violations[0]?.code).toBe(ViolationCode.IntrospectionNotAllowed)
  })
})

describe('opt-in and disabled-introspection behaviour', () => {
  it('allowUnfiltered lets a non-sensitive catalog through (unfiltered)', async () => {
    const m: PermissionModel = {
      tables: { 'public.users': { select: { columns: ['id'] } } },
      introspection: { enabled: true, allowUnfiltered: ['pg_catalog.pg_proc'] },
    }
    const d = await analyze('SELECT proname FROM pg_catalog.pg_proc', { model: m, catalog, context: { ctx: {} } })
    expect(d.allow).toBe(true)
  })
  it('allowUnfiltered does NOT override a sensitive catalog', async () => {
    const m: PermissionModel = {
      tables: { 'public.users': { select: { columns: ['id'] } } },
      introspection: { enabled: true, allowUnfiltered: ['pg_catalog.pg_authid', 'pg_authid'] },
    }
    const d = await analyze('SELECT rolpassword FROM pg_authid', { model: m, catalog, context: { ctx: {} } })
    expect(d.allow).toBe(false)
    if (!d.allow) expect(d.violations[0]?.code).toBe(ViolationCode.SystemCatalogBlocked)
  })
  it('with introspection OFF, a catalog is simply not a visible relation', async () => {
    const m: PermissionModel = { tables: { 'public.users': { select: { columns: ['id'] } } } }
    const d = await analyze('SELECT relname FROM pg_catalog.pg_class', { model: m, catalog, context: { ctx: {} } })
    expect(d.allow).toBe(false)
    if (!d.allow) expect(d.violations[0]?.code).toBe(ViolationCode.RelationNotVisible)
  })
})
