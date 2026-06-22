import { describe, expect, it } from 'vitest'
import { analyze } from '../src/analyzer/index'
import { ViolationCode } from '../src/analyzer/errors'
import { MemoryCatalog } from '../src/schema/memory-catalog'
import type { PermissionModel } from '../src/policy/model'

/**
 * Regression tests for the bypasses found in the security audit. Each `it` pins a
 * previously-exploitable vector to its fix; if any of these ever ALLOW again,
 * the boundary has regressed.
 */
const model: PermissionModel = {
  tables: {
    'public.users': { select: { columns: ['id', 'email'] }, update: { columns: ['email'] } },
    'public.profiles': { select: true },
  },
  introspection: { enabled: true },
}
const catalog = new MemoryCatalog({
  tables: { 'public.users': ['id', 'email', 'password'], 'public.profiles': ['user_id', 'bio'] },
})

const run = (sql: string, m: PermissionModel = model) =>
  analyze(sql, { model: m, catalog, context: { ctx: {} } })
async function code(sql: string, m?: PermissionModel): Promise<ViolationCode | undefined> {
  const d = await run(sql, m)
  return d.allow ? undefined : d.violations[0]?.code
}
const allowed = async (sql: string, m?: PermissionModel) => (await run(sql, m)).allow

describe('V1: dangerous functions (data/file/SQL bypass)', () => {
  it('blocks SQL-executing functions', async () => {
    expect(await code("SELECT query_to_xml('SELECT 1', true, false, '')")).toBe(
      ViolationCode.FunctionNotAllowed,
    )
    // ts_rewrite's 3-arg form runs its text argument as SQL (analyzer-invisible).
    expect(await code("SELECT ts_rewrite('a'::tsquery, 'SELECT 1, 2')")).toBe(
      ViolationCode.FunctionNotAllowed,
    )
  })
  it('blocks file-access functions', async () => {
    expect(await code("SELECT pg_read_file('/etc/passwd')")).toBe(ViolationCode.FunctionNotAllowed)
  })
  it('blocks dblink and tablefunc crosstab/connectby (SQL-string execution)', async () => {
    expect(await code("SELECT * FROM dblink('x','SELECT 1') AS t(a int)")).toBe(
      ViolationCode.FunctionNotAllowed,
    )
    expect(await code("SELECT * FROM crosstab('SELECT * FROM secret') AS t(a int, b int)")).toBe(
      ViolationCode.FunctionNotAllowed,
    )
    expect(await code("SELECT * FROM connectby('t','id','parent','1',0,'-') AS t(a int)")).toBe(
      ViolationCode.FunctionNotAllowed,
    )
  })
  it('blocks large-object, sleep, state-mutation, definition-leak and exfil functions', async () => {
    expect(await code("SELECT lo_import('/etc/passwd')")).toBe(ViolationCode.FunctionNotAllowed)
    expect(await code('SELECT pg_sleep(10)')).toBe(ViolationCode.FunctionNotAllowed)
    expect(await code("SELECT set_config('search_path','x',false)")).toBe(
      ViolationCode.FunctionNotAllowed,
    )
    expect(await code("SELECT pg_get_viewdef('v'::regclass)")).toBe(ViolationCode.FunctionNotAllowed)
    expect(await code("SELECT pg_notify('chan', 'data')")).toBe(ViolationCode.FunctionNotAllowed)
  })
  it('blocks adminpack server-file functions (pg_file_* / pg_logdir_ls)', async () => {
    // adminpack writes/reads server files and is NOT caught by the pg_read_/pg_ls_
    // prefixes (different names), so it must be blocked explicitly.
    expect(await code("SELECT pg_file_write('/tmp/x', 'data', false)")).toBe(ViolationCode.FunctionNotAllowed)
    expect(await code("SELECT pg_file_read('/etc/passwd', 0, 100)")).toBe(ViolationCode.FunctionNotAllowed)
    expect(await code("SELECT pg_file_unlink('/tmp/x')")).toBe(ViolationCode.FunctionNotAllowed)
    expect(await code("SELECT pg_file_rename('/a', '/b')")).toBe(ViolationCode.FunctionNotAllowed)
    expect(await code('SELECT * FROM pg_logdir_ls()')).toBe(ViolationCode.FunctionNotAllowed)
  })
  it('blocks cross-database/tablespace size, path, and object-address oracles', async () => {
    expect(await code("SELECT pg_database_size('postgres')")).toBe(ViolationCode.FunctionNotAllowed)
    expect(await code("SELECT pg_tablespace_size('pg_default')")).toBe(ViolationCode.FunctionNotAllowed)
    expect(await code('SELECT pg_tablespace_location(1663)')).toBe(ViolationCode.FunctionNotAllowed)
    expect(await code("SELECT pg_get_object_address('table', '{secret}', '{}')")).toBe(
      ViolationCode.FunctionNotAllowed,
    )
  })
  it('blocks cluster-internals / recon (pg_control_*, server addr, replication, blocking pids)', async () => {
    expect(await code('SELECT * FROM pg_control_system()')).toBe(ViolationCode.FunctionNotAllowed)
    expect(await code('SELECT * FROM pg_control_checkpoint()')).toBe(ViolationCode.FunctionNotAllowed)
    expect(await code('SELECT inet_server_addr()')).toBe(ViolationCode.FunctionNotAllowed)
    expect(await code('SELECT * FROM pg_get_replication_slots()')).toBe(ViolationCode.FunctionNotAllowed)
    expect(await code('SELECT pg_blocking_pids(1234)')).toBe(ViolationCode.FunctionNotAllowed)
  })
  it('blocks pg_try_advisory_* lock DoS (the prefix-gap the pg_advisory prefix missed)', async () => {
    // pg_try_advisory_* starts with "pg_try_advisory", not "pg_advisory", so the
    // pg_advisory prefix never matched them — same lock-DoS surface as pg_advisory_*.
    expect(await code('SELECT pg_try_advisory_lock(1)')).toBe(ViolationCode.FunctionNotAllowed)
    expect(await code('SELECT pg_try_advisory_lock_shared(1)')).toBe(ViolationCode.FunctionNotAllowed)
    expect(await code('SELECT pg_try_advisory_xact_lock(1)')).toBe(ViolationCode.FunctionNotAllowed)
    expect(await code('SELECT pg_try_advisory_xact_lock_shared(1)')).toBe(ViolationCode.FunctionNotAllowed)
  })
  it('blocks WAL state / replication-slot recon (write-volume & topology)', async () => {
    expect(await code('SELECT pg_current_wal_lsn()')).toBe(ViolationCode.FunctionNotAllowed)
    expect(await code('SELECT pg_last_wal_replay_lsn()')).toBe(ViolationCode.FunctionNotAllowed)
    expect(await code('SELECT pg_walfile_name(pg_current_wal_lsn())')).toBe(ViolationCode.FunctionNotAllowed)
    expect(await code('SELECT pg_split_walfile_name(name) FROM x')).toBe(ViolationCode.FunctionNotAllowed)
    expect(await code('SELECT pg_is_wal_replay_paused()')).toBe(ViolationCode.FunctionNotAllowed)
    expect(await code('SELECT pg_get_wal_summarizer_state()')).toBe(ViolationCode.FunctionNotAllowed)
    expect(await code("SELECT pg_copy_logical_replication_slot('a','b')")).toBe(ViolationCode.FunctionNotAllowed)
    expect(await code('SELECT pg_sync_replication_slots()')).toBe(ViolationCode.FunctionNotAllowed)
    expect(await code("SELECT pg_stat_reset_replication_slot('s')")).toBe(ViolationCode.FunctionNotAllowed)
    expect(await code('SELECT * FROM pg_show_replication_origin_status()')).toBe(ViolationCode.FunctionNotAllowed)
  })
  it('blocks shmem layout, cross-DB enumeration, collation import, own-conn addr', async () => {
    expect(await code('SELECT * FROM pg_get_shmem_allocations()')).toBe(ViolationCode.FunctionNotAllowed)
    expect(await code('SELECT * FROM pg_get_dsm_registry_allocations()')).toBe(ViolationCode.FunctionNotAllowed)
    expect(await code('SELECT pg_tablespace_databases(1663)')).toBe(ViolationCode.FunctionNotAllowed)
    expect(await code('SELECT pg_import_system_collations(0)')).toBe(ViolationCode.FunctionNotAllowed)
    expect(await code('SELECT inet_client_addr()')).toBe(ViolationCode.FunctionNotAllowed)
  })
  it('blocks PG18 planner-statistics mutation (cross-tenant planner poisoning / DoS)', async () => {
    expect(await code("SELECT pg_restore_relation_stats('relation','public.users'::regclass)")).toBe(
      ViolationCode.FunctionNotAllowed,
    )
    expect(await code("SELECT pg_restore_attribute_stats('relation','x'::regclass)")).toBe(ViolationCode.FunctionNotAllowed)
    expect(await code("SELECT pg_clear_relation_stats('public','users')")).toBe(ViolationCode.FunctionNotAllowed)
    expect(await code("SELECT pg_clear_extended_stats('public','s')")).toBe(ViolationCode.FunctionNotAllowed)
  })
  it('blocks checksum/standby admin, cross-session lock & 2PC recon', async () => {
    expect(await code('SELECT pg_enable_data_checksums()')).toBe(ViolationCode.FunctionNotAllowed)
    expect(await code('SELECT pg_disable_data_checksums()')).toBe(ViolationCode.FunctionNotAllowed)
    expect(await code('SELECT pg_log_standby_snapshot()')).toBe(ViolationCode.FunctionNotAllowed)
    expect(await code('SELECT * FROM pg_lock_status()')).toBe(ViolationCode.FunctionNotAllowed)
    expect(await code('SELECT * FROM pg_prepared_xact()')).toBe(ViolationCode.FunctionNotAllowed)
  })
  it('blocks definition leaks completing the pg_get_*def family (partkey, stats-obj, fn signature)', async () => {
    expect(await code('SELECT pg_get_partkeydef(1)')).toBe(ViolationCode.FunctionNotAllowed)
    expect(await code('SELECT pg_get_statisticsobjdef_columns(1)')).toBe(ViolationCode.FunctionNotAllowed)
    expect(await code('SELECT pg_get_function_arguments(1)')).toBe(ViolationCode.FunctionNotAllowed)
    expect(await code('SELECT pg_get_function_result(1)')).toBe(ViolationCode.FunctionNotAllowed)
  })
  it('blocks sequence-value, partition-hierarchy, extension-inventory & publication recon', async () => {
    expect(await code('SELECT pg_sequence_last_value(1)')).toBe(ViolationCode.FunctionNotAllowed)
    expect(await code('SELECT pg_sequence_parameters(1)')).toBe(ViolationCode.FunctionNotAllowed)
    expect(await code('SELECT * FROM pg_partition_tree(1)')).toBe(ViolationCode.FunctionNotAllowed)
    expect(await code('SELECT pg_partition_root(1)')).toBe(ViolationCode.FunctionNotAllowed)
    expect(await code('SELECT * FROM pg_available_extensions()')).toBe(ViolationCode.FunctionNotAllowed)
    expect(await code('SELECT * FROM pg_get_publication_tables($1)')).toBe(ViolationCode.FunctionNotAllowed)
    expect(await code('SELECT * FROM pg_get_loaded_modules()')).toBe(ViolationCode.FunctionNotAllowed)
  })
  it('blocks role/db existence oracles (pg_has_role, to_regdatabase, has_largeobject_privilege)', async () => {
    expect(await code("SELECT pg_has_role('postgres','member')")).toBe(ViolationCode.FunctionNotAllowed)
    expect(await code("SELECT to_regdatabase('postgres')")).toBe(ViolationCode.FunctionNotAllowed)
    expect(await code('SELECT has_largeobject_privilege(1, $1)')).toBe(ViolationCode.FunctionNotAllowed)
  })
  it('does NOT over-block search_path visibility helpers or standard session funcs (driver compat)', async () => {
    // *_is_visible drive psql \d / JDBC introspection and are OID-gated + already
    // behind the row-filter; current_*/session_* are standard. These must stay usable.
    expect(await allowed('SELECT pg_table_is_visible(123)')).toBe(true) // literal OID isolates the fn gate
    expect(await allowed('SELECT pg_type_is_visible(123)')).toBe(true)
    expect(await allowed('SELECT current_user, session_user, current_database()')).toBe(true)
    expect(await allowed('SELECT pg_size_pretty(pg_column_size(id)) FROM users')).toBe(true)
    expect(await allowed('SELECT pg_stat_clear_snapshot()')).toBe(true) // NOT caught by pg_clear_
  })
  it('still allows benign LSN/size math and version (no over-block from the WAL prefixes)', async () => {
    // These take caller-supplied values and must NOT be caught by the pg_*_wal prefixes.
    expect(await allowed('SELECT pg_wal_lsn_diff($1, $2)')).toBe(true)
    expect(await allowed('SELECT pg_column_size(id) FROM users')).toBe(true)
    expect(await allowed('SELECT version()')).toBe(true)
  })
  it('still allows safe functions', async () => {
    expect(await allowed('SELECT count(*) FROM users')).toBe(true)
  })
  it('allowlist mode permits only listed (plus safe) functions', async () => {
    const m: PermissionModel = { ...model, functions: { mode: 'allowlist', list: ['my_udf'] } }
    expect(await allowed('SELECT count(*) FROM users', m)).toBe(true) // safe builtin
    expect(await code('SELECT some_other_udf(id) FROM users', m)).toBe(
      ViolationCode.FunctionNotAllowed,
    )
  })
})

describe('V2: deny-most system catalogs', () => {
  it('blocks unfilterable catalogs that leak data', async () => {
    expect(await code('SELECT query FROM pg_stat_activity')).toBe(ViolationCode.IntrospectionNotAllowed)
    expect(await code('SELECT prosrc FROM pg_proc')).toBe(ViolationCode.IntrospectionNotAllowed)
    expect(await code('SELECT definition FROM pg_views')).toBe(ViolationCode.IntrospectionNotAllowed)
    expect(await code('SELECT rolname FROM pg_roles')).toBe(ViolationCode.IntrospectionNotAllowed)
  })
  it('still allows (and filters) the supported catalogs', async () => {
    expect(await allowed('SELECT table_name FROM information_schema.tables')).toBe(true)
    expect(await allowed('SELECT relname FROM pg_catalog.pg_class')).toBe(true)
  })
  it('row-filters pg_attribute (column catalog) instead of denying it', async () => {
    const d = await run('SELECT attname FROM pg_catalog.pg_attribute')
    expect(d.allow).toBe(true)
    if (d.allow) {
      const sql = d.sql.replace(/\s+/g, ' ')
      // wrapped + correlated to the column-visibility predicate
      expect(sql).toMatch(/EXISTS \(SELECT 1 FROM pg_catalog\.pg_class/i)
      expect(sql).toMatch(/pg_attribute\.attname IN \('id', 'email'\)/)
    }
  })
  it('honors an explicit allowUnfiltered opt-in', async () => {
    const m: PermissionModel = {
      ...model,
      introspection: { enabled: true, allowUnfiltered: ['pg_settings'] },
    }
    expect(await allowed('SELECT name FROM pg_settings', m)).toBe(true)
  })
})

describe('V7: operator-invoked functions (default-deny custom operators)', () => {
  it('allows built-in operators', async () => {
    expect(await allowed('SELECT id FROM users WHERE id = 1 AND email IS NOT NULL')).toBe(true)
    expect(await allowed("SELECT id FROM users WHERE email ~~ 'a%'")).toBe(true) // LIKE → ~~
  })
  it('blocks a custom (non-built-in) operator', async () => {
    expect(await code('SELECT 1 @!@ 2')).toBe(ViolationCode.OperatorNotAllowed)
  })
  it('blocks a custom operator in an ANY/ALL subquery', async () => {
    expect(await allowed('SELECT id FROM users WHERE id = ANY(SELECT 1)')).toBe(true) // built-in =
    expect(await code('SELECT id FROM users WHERE id OPERATOR(public.@!@) ANY(SELECT 1)')).toBe(
      ViolationCode.OperatorNotAllowed,
    )
  })
  it('permits a custom operator only when explicitly allowed', async () => {
    const m: PermissionModel = { ...model, functions: { allowOperators: ['@!@'] } }
    expect(await allowed('SELECT 1 @!@ 2', m)).toBe(true)
  })
  it('V43: blocks a custom operator in ORDER BY ... USING (SortBy.useOp was un-collected)', async () => {
    // `ORDER BY x USING <op>` chooses a sort operator that can be user-defined (its
    // oprcode an arbitrary function) — the same bypass the gate stops in WHERE, but
    // SortBy.useOp wasn't walked, so it slipped through. Built-in symbols still pass.
    expect(await code('SELECT id FROM users ORDER BY id USING OPERATOR(public.<<)')).toBe(
      ViolationCode.OperatorNotAllowed,
    )
    expect(await code('SELECT id FROM users ORDER BY id USING |@>@|')).toBe(ViolationCode.OperatorNotAllowed)
    expect(await allowed('SELECT id FROM users ORDER BY id USING >')).toBe(true) // built-in sort op
    expect(await allowed('SELECT id FROM users ORDER BY id USING OPERATOR(pg_catalog.<)')).toBe(true)
    expect(await allowed('SELECT id FROM users ORDER BY id DESC')).toBe(true) // no USING at all
  })
  it('V43: USING-operator gate reaches every nested sort position (agg/window/within-group/CTE/set-op)', async () => {
    // The fix keys on the SortBy node, so the generic walk gates a custom USING
    // operator wherever a sort clause can appear — not just top-level ORDER BY.
    const C = 'OPERATOR(public.<<)'
    const denied = [
      `SELECT array_agg(id ORDER BY id USING ${C}) FROM users`,
      `SELECT rank() OVER (ORDER BY id USING ${C}) FROM users`,
      `SELECT percentile_cont(0.5) WITHIN GROUP (ORDER BY id USING ${C}) FROM users`,
      `SELECT * FROM (SELECT id FROM users ORDER BY id USING ${C}) s`,
      `WITH c AS (SELECT id FROM users ORDER BY id USING ${C}) SELECT * FROM c`,
      `SELECT id FROM users UNION SELECT id FROM users ORDER BY 1 USING ${C}`,
    ]
    for (const sql of denied) expect(await code(sql), sql).toBe(ViolationCode.OperatorNotAllowed)
    // built-in operators in those same nested positions remain allowed
    expect(await allowed('SELECT array_agg(id ORDER BY id USING >) FROM users')).toBe(true)
    expect(await allowed('SELECT rank() OVER (ORDER BY id USING <) FROM users')).toBe(true)
  })
})

describe('V44: a prototype-named schema is not silently accessible (Object.hasOwn, not `in`)', () => {
  // The relation name comes from attacker SQL; `schema in model.schemas` walks the
  // prototype chain, so `'constructor'`/`'toString'`/… would test as accessible
  // without a grant. The gate must use an own-property check.
  const gated: PermissionModel = {
    schemas: { public: { defaultTablePolicy: { select: true } } },
    tables: {},
  }
  it.each(['toString', 'constructor', 'hasOwnProperty', '__proto__', 'valueOf', 'isPrototypeOf'])(
    'denies a query against the un-granted prototype-named schema %s',
    async (schema) => {
      const d = await analyze(`SELECT * FROM ${schema}.foo`, { model: gated, context: { ctx: {} } })
      expect(d.allow, schema).toBe(false)
      if (!d.allow) expect(d.violations[0]?.code, schema).toBe(ViolationCode.SchemaNotVisible)
    },
  )
  it('still allows the genuinely-granted schema', async () => {
    expect((await analyze('SELECT * FROM public.foo', { model: gated, context: { ctx: {} } })).allow).toBe(true)
  })
})

describe('V8: inheritance / partition parents (default-deny)', () => {
  const parented = new MemoryCatalog({
    tables: { 'public.events': ['id', 'ts'], 'public.plain': ['id'] },
    parents: ['public.events'], // events has child partitions
  })
  const m: PermissionModel = { tables: { 'public.events': { select: true }, 'public.plain': { select: true } } }
  const withCatalog = (sql: string, model: PermissionModel = m) =>
    analyze(sql, { model, catalog: parented })

  it('blocks reading a parent that has children', async () => {
    const d = await withCatalog('SELECT * FROM events')
    expect(d.allow).toBe(false)
    if (!d.allow) expect(d.violations[0]?.code).toBe(ViolationCode.InheritedRelationBlocked)
  })
  it('permits a parent read only with allowInherited', async () => {
    const allow: PermissionModel = { tables: { 'public.events': { select: true, allowInherited: true } } }
    expect((await withCatalog('SELECT * FROM events', allow)).allow).toBe(true)
  })
  it('does not affect a relation without children', async () => {
    expect((await withCatalog('SELECT * FROM plain')).allow).toBe(true)
  })

  it('blocks UPDATE/DELETE on a parent (writes children too)', async () => {
    const w: PermissionModel = {
      tables: { 'public.events': { select: true, update: { columns: ['ts'] }, delete: true } },
    }
    const u = await analyze('UPDATE events SET ts = now()', { model: w, catalog: parented })
    expect(u.allow).toBe(false)
    if (!u.allow) expect(u.violations[0]?.code).toBe(ViolationCode.InheritedRelationBlocked)
    expect((await analyze('DELETE FROM events', { model: w, catalog: parented })).allow).toBe(false)
  })

  it('permits ONLY parent (children untouched) for read and write', async () => {
    const w: PermissionModel = {
      tables: { 'public.events': { select: true, update: { columns: ['ts'] } } },
    }
    expect((await analyze('SELECT * FROM ONLY events', { model: w, catalog: parented })).allow).toBe(true)
    expect(
      (await analyze('UPDATE ONLY events SET ts = now()', { model: w, catalog: parented })).allow,
    ).toBe(true)
  })
})

describe('V14: TABLESAMPLE FROM-item is rewritten', () => {
  const m: PermissionModel = {
    tables: {
      'public.users': { select: { columns: ['id', 'email'] }, rls: { select: 'tenant = ctx.t' } },
      'public.orders': { select: true },
    },
  }
  const cat = new MemoryCatalog({
    tables: { 'public.users': ['id', 'email', 'password'], 'public.orders': ['id'] },
  })
  const rewrite = async (sql: string): Promise<string> => {
    const d = await analyze(sql, { model: m, catalog: cat, context: { ctx: { t: 42 } } })
    if (!d.allow) throw new Error(`denied: ${JSON.stringify(d.violations)}`)
    return d.sql.replace(/\s+/g, ' ')
  }

  it('expands `*` on a sampled relation and preserves TABLESAMPLE', async () => {
    const sql = await rewrite('SELECT * FROM users TABLESAMPLE SYSTEM (10)')
    expect(sql).toMatch(/users\.id/)
    expect(sql).toMatch(/users\.email/)
    expect(sql).not.toMatch(/password/)
    expect(sql).toMatch(/TABLESAMPLE/i)
  })
  it('applies RLS to a sampled relation (sample-then-filter)', async () => {
    const sql = await rewrite('SELECT id FROM users TABLESAMPLE SYSTEM (10)')
    expect(sql).toMatch(/TABLESAMPLE \w+ \(10\) WHERE tenant = 42/i)
  })
  it('applies RLS to a sampled relation inside a join', async () => {
    const sql = await rewrite('SELECT u.id FROM orders o JOIN users u TABLESAMPLE SYSTEM (5) ON o.id = u.id')
    expect(sql).toMatch(/TABLESAMPLE \w+ \(5\) WHERE tenant = 42/i)
  })
  it('still denies an explicit forbidden column on a sampled relation', async () => {
    const d = await analyze('SELECT password FROM users TABLESAMPLE SYSTEM (10)', {
      model: m,
      catalog: cat,
      context: { ctx: { t: 42 } },
    })
    expect(d.allow).toBe(false)
    if (!d.allow) expect(d.violations[0]?.code).toBe(ViolationCode.ColumnNotReadable)
  })
})

describe('V13: set-operation arms (UNION/INTERSECT/EXCEPT) are rewritten', () => {
  const m: PermissionModel = {
    tables: {
      'public.docs': { select: true, rls: { select: 'owner = ctx.uid' } },
      'public.users': { select: { columns: ['id', 'email'] } },
    },
  }
  const cat = new MemoryCatalog({ tables: { 'public.users': ['id', 'email', 'password'] } })
  const rewrite = async (sql: string): Promise<string> => {
    const d = await analyze(sql, { model: m, catalog: cat, context: { ctx: { uid: 7 } } })
    if (!d.allow) throw new Error(`denied: ${JSON.stringify(d.violations)}`)
    return d.sql.replace(/\s+/g, ' ')
  }
  it('applies RLS to every set-op arm', async () => {
    expect((await rewrite('SELECT id FROM docs UNION SELECT id FROM docs')).match(/owner = 7/g)?.length).toBe(2)
    expect(
      (await rewrite('SELECT id FROM docs INTERSECT SELECT id FROM docs')).match(/owner = 7/g)?.length,
    ).toBe(2)
    expect(
      (await rewrite('SELECT id FROM docs UNION SELECT id FROM docs UNION SELECT id FROM docs')).match(
        /owner = 7/g,
      )?.length,
    ).toBe(3)
  })
  it('expands `*` in every set-op arm (no column leak)', async () => {
    const sql = await rewrite('SELECT * FROM users UNION SELECT * FROM users')
    expect(sql).not.toMatch(/password/)
    expect(sql).not.toMatch(/users\.\*/)
    expect(sql).toMatch(/users\.email/)
  })
})

describe('V12: CTE-name shadowing of a real table', () => {
  it('blocks a CTE named after a forbidden table from reading it', async () => {
    // non-recursive CTE name is not in scope in its own body → inner `secret` is the table
    expect(await code('WITH secret AS (SELECT * FROM secret) SELECT * FROM secret')).toBe(
      ViolationCode.RelationNotVisible,
    )
  })
  it('catches a forbidden column inside a CTE that shadows an allowed table', async () => {
    expect(await code('WITH users AS (SELECT password FROM users) SELECT * FROM users')).toBe(
      ViolationCode.ColumnNotReadable,
    )
  })
  it('still allows legitimate and recursive CTEs', async () => {
    expect(await allowed('WITH x AS (SELECT id FROM users) SELECT * FROM x')).toBe(true)
    expect(
      await allowed(
        'WITH RECURSIVE t(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM t WHERE n < 5) SELECT n FROM t',
      ),
    ).toBe(true)
  })
})

describe('V33: a renamed derived-source column referenced unqualified (no over-block)', () => {
  // collect() is scope-flat: a column-restricted base relation inside a CTE/subquery
  // body becomes the outer query's only base relation, so an unqualified outer
  // reference to a RENAMED output column (`SELECT id AS pw ... SELECT pw`) was wrongly
  // attributed to the base relation and denied. The rename resolves in the source's
  // own scope; recognising output aliases (catalog-guarded) fixes the false denial
  // WITHOUT opening a leak — the source body is still validated independently.
  it('allows an unqualified reference to a renamed CTE / subquery output', async () => {
    expect(await allowed('WITH c AS (SELECT id AS pw FROM users) SELECT pw FROM c')).toBe(true)
    expect(await allowed('SELECT pw FROM (SELECT id AS pw FROM users) z')).toBe(true)
    expect(await allowed('WITH c AS (SELECT email AS mail FROM users) SELECT count(mail) FROM c')).toBe(true)
    expect(await allowed('SELECT pw FROM (SELECT x AS pw FROM (SELECT id AS x FROM users) a) b')).toBe(true)
  })
  it('still blocks the forbidden column read inside the derived body (no leak)', async () => {
    // the rename targets the hidden column itself — caught in the source's own scope
    expect(await code('WITH c AS (SELECT password AS pw FROM users) SELECT pw FROM c')).toBe(
      ViolationCode.ColumnNotReadable,
    )
    expect(await code('SELECT pw FROM (SELECT password AS pw FROM users) z')).toBe(
      ViolationCode.ColumnNotReadable,
    )
    // alias collides with a real hidden column AND the outer ref reads the base table → fail closed
    expect(await code('WITH c AS (SELECT id AS password FROM users) SELECT password FROM users')).toBe(
      ViolationCode.ColumnNotReadable,
    )
  })
})

describe('expression-position references are all checked', () => {
  const m: PermissionModel = { tables: { 'public.users': { select: { columns: ['id', 'email', 'data'] } } } }
  const cat = new MemoryCatalog({ tables: { 'public.users': ['id', 'email', 'password', 'data'] } })
  const run2 = (sql: string) => analyze(sql, { model: m, catalog: cat, context: { ctx: {} } })
  const deny2 = async (sql: string) => {
    const d = await run2(sql)
    return d.allow ? undefined : d.violations[0]?.code
  }
  it('catches a forbidden column in a json_table / xmltable document expression', async () => {
    expect(
      await deny2("SELECT jt.a FROM users u, json_table(u.password, '$' COLUMNS (a text PATH '$')) jt"),
    ).toBe(ViolationCode.ColumnNotReadable)
    expect(
      await deny2("SELECT x FROM xmltable('/r' PASSING (SELECT password FROM users) COLUMNS x text)"),
    ).toBe(ViolationCode.ColumnNotReadable)
  })
  it('catches a forbidden column via whole-row field access or subscript', async () => {
    expect(await deny2('SELECT (users).password FROM users')).toBe(ViolationCode.ColumnNotReadable)
    expect(await deny2('SELECT password[1] FROM users')).toBe(ViolationCode.ColumnNotReadable)
  })
  it('allows field access / subscript on a permitted column', async () => {
    expect((await run2('SELECT (u.data).city FROM users u')).allow).toBe(true)
    expect((await run2("SELECT data['k'] FROM users")).allow).toBe(true)
  })
})

describe('RLS AND-injection respects OR precedence (deparse fidelity)', () => {
  const m: PermissionModel = {
    tables: { 'public.docs': { select: true, update: { columns: ['x'] }, rls: { update: 'owner = ctx.uid' } } },
  }
  it('parenthesizes an existing OR before ANDing the USING filter', async () => {
    const d = await analyze('UPDATE docs SET x = 1 WHERE a = 1 OR b = 2', {
      model: m,
      context: { ctx: { uid: 7 } },
    })
    expect(d.allow).toBe(true)
    if (d.allow) expect(d.sql.replace(/\s+/g, ' ')).toMatch(/\(a = 1 OR b = 2\) AND/)
  })
})

describe('V11: qualified `t.*` in non-expandable positions', () => {
  it('blocks restricted `t.*` inside function args / constructors', async () => {
    // these expand to ALL columns (incl. password) at the backend
    expect(await code('SELECT jsonb_build_array(users.*) FROM users')).toBe(
      ViolationCode.ColumnNotReadable,
    )
    expect(await code('SELECT row_to_json(users.*) FROM users')).toBe(
      ViolationCode.ColumnNotReadable,
    )
    expect(await code('SELECT ROW(users.*) FROM users')).toBe(ViolationCode.ColumnNotReadable)
  })
  it('still allows top-level `t.*` (expanded) and fully-allowed `t.*`', async () => {
    expect(await allowed('SELECT users.* FROM users')).toBe(true) // expanded to id,email
    expect(await allowed('SELECT jsonb_build_array(profiles.*) FROM profiles')).toBe(true) // profiles = select:true
  })
})

describe('V10: RLS on UPDATE...FROM / DELETE...USING read relations', () => {
  const m: PermissionModel = {
    tables: {
      'public.mine': { select: true, update: { columns: ['x'] }, delete: true },
      'public.other': { select: true, rls: { select: 'owner = ctx.uid' } },
    },
  }
  const rewrite = async (sql: string): Promise<string> => {
    const d = await analyze(sql, { model: m, context: { ctx: { uid: 7 } } })
    if (!d.allow) throw new Error('denied')
    return d.sql.replace(/\s+/g, ' ')
  }
  it('wraps the FROM relation of an UPDATE with its RLS filter', async () => {
    const sql = await rewrite('UPDATE mine SET x = other.secret FROM other WHERE mine.id = other.id')
    expect(sql).toMatch(/SELECT \* FROM public\.other WHERE owner = 7/)
  })
  it('wraps the USING relation of a DELETE with its RLS filter', async () => {
    const sql = await rewrite('DELETE FROM mine USING other WHERE mine.ref = other.id')
    expect(sql).toMatch(/SELECT \* FROM public\.other WHERE owner = 7/)
  })
})

describe('V9: SELECT INTO (a table-creating statement)', () => {
  it('blocks SELECT ... INTO (and the empty-table form)', async () => {
    expect(await code('SELECT * INTO exfil FROM users')).toBe(ViolationCode.StatementNotAllowed)
    expect(await code('SELECT 1 INTO foo')).toBe(ViolationCode.StatementNotAllowed)
    expect(await code('WITH x AS (SELECT 1 AS n) SELECT * INTO t FROM x')).toBe(
      ViolationCode.StatementNotAllowed,
    )
  })
})

describe('V3: ambiguous column via join', () => {
  it('blocks a forbidden column made ambiguous by a join (catalog-resolved)', async () => {
    expect(await code('SELECT password FROM users JOIN profiles p ON true')).toBe(
      ViolationCode.ColumnNotReadable,
    )
  })
  it('fails closed without a catalog when a restricted relation is in scope', async () => {
    const d = await analyze('SELECT password FROM users JOIN profiles p ON true', { model })
    expect(d.allow).toBe(false)
  })
  it('still allows a permitted column resolved via the catalog', async () => {
    expect(await allowed('SELECT email FROM users JOIN profiles p ON true')).toBe(true)
  })
})

describe('V4: write read-back via RETURNING / ON CONFLICT', () => {
  it('blocks a forbidden column in RETURNING', async () => {
    expect(await code("UPDATE users SET email='x' RETURNING password")).toBe(
      ViolationCode.ColumnNotReadable,
    )
  })
  it('blocks RETURNING * on a column-restricted table', async () => {
    expect(await code("UPDATE users SET email='x' RETURNING *")).toBe(ViolationCode.ColumnNotReadable)
  })
  it('allows RETURNING of permitted columns', async () => {
    expect(await allowed("UPDATE users SET email='x' RETURNING id, email")).toBe(true)
  })
  it('V6: blocks the blind channel — forbidden column in UPDATE/DELETE WHERE', async () => {
    expect(await code("UPDATE users SET email = email WHERE password LIKE 'a%'")).toBe(
      ViolationCode.ColumnNotReadable,
    )
    // and via a value expression that reads a forbidden column
    expect(await code('UPDATE users SET email = password')).toBe(ViolationCode.ColumnNotReadable)
  })
  it('still allows an UPDATE whose WHERE references only readable columns', async () => {
    expect(await allowed("UPDATE users SET email = 'x' WHERE id = 5")).toBe(true)
  })

  it('checks ON CONFLICT DO UPDATE column writes', async () => {
    // INSERT(email) is allowed; the ON CONFLICT SET targets a non-writable column.
    const m: PermissionModel = {
      ...model,
      tables: {
        ...model.tables,
        'public.users': {
          select: { columns: ['id', 'email'] },
          insert: { columns: ['email'] },
          update: { columns: ['email'] },
        },
      },
    }
    expect(
      await code("INSERT INTO users(email) VALUES('a') ON CONFLICT (id) DO UPDATE SET id = 5", m),
    ).toBe(ViolationCode.ColumnNotWritable)
  })
})

describe('V15: aliased join `(a JOIN b) x` must not launder a restricted column', () => {
  it('blocks a forbidden column addressed through the join alias', async () => {
    expect(await code('SELECT x.password FROM (users u JOIN profiles p ON true) x')).toBe(
      ViolationCode.ColumnNotReadable,
    )
    // nested parens / 3-way still resolve to the component relations
    expect(await code('SELECT x.password FROM ((users u JOIN profiles p ON true)) x')).toBe(
      ViolationCode.ColumnNotReadable,
    )
  })
  it('blocks `alias.*` when a component relation is column-restricted', async () => {
    expect(await code('SELECT x.* FROM (users u JOIN profiles p ON true) x')).toBe(
      ViolationCode.ColumnNotReadable,
    )
  })
  it('fails closed without a catalog when a restricted relation is in the join', async () => {
    const d = await analyze('SELECT x.password FROM (users u JOIN profiles p ON true) x', { model })
    expect(d.allow).toBe(false)
  })
  it('still allows a permitted column resolved through the alias', async () => {
    expect(await allowed('SELECT x.email FROM (users u JOIN profiles p ON true) x')).toBe(true)
    expect(await allowed('SELECT x.bio FROM (users u JOIN profiles p ON true) x')).toBe(true)
  })
  it('still allows `alias.*` when every component is fully-allowed', async () => {
    const m: PermissionModel = { tables: { 'public.profiles': { select: true }, 'public.orders': { select: true } } }
    const c = new MemoryCatalog({ tables: { 'public.profiles': ['user_id', 'bio'], 'public.orders': ['id'] } })
    const d = await analyze('SELECT x.* FROM (profiles p JOIN orders o ON true) x', { model: m, catalog: c })
    expect(d.allow).toBe(true)
  })
})

describe('V16: schema-qualified operator OPERATOR(schema.symbol) is treated as custom', () => {
  it('blocks a qualified (user-defined) operator reusing a built-in symbol', async () => {
    expect(await code('SELECT id OPERATOR(evil.=) id FROM users')).toBe(ViolationCode.OperatorNotAllowed)
    // also via the `op ANY (subquery)` SubLink path
    expect(
      await code('SELECT id FROM users WHERE id OPERATOR(evil.=) ANY (SELECT id FROM users)'),
    ).toBe(ViolationCode.OperatorNotAllowed)
  })
  it('still allows bare and pg_catalog-qualified built-in operators', async () => {
    expect(await allowed('SELECT id FROM users WHERE id = 1')).toBe(true)
    expect(await allowed('SELECT id FROM users WHERE id OPERATOR(pg_catalog.=) 1')).toBe(true)
  })
  it('permits a qualified operator only when explicitly allowed', async () => {
    const m: PermissionModel = { ...model, functions: { allowOperators: ['evil.='] } }
    expect(await allowed('SELECT id OPERATOR(evil.=) id FROM users', m)).toBe(true)
  })
})

describe('V17: schema-qualified function must not pass the allowlist by bare-name collision', () => {
  const allowlist: PermissionModel = { ...model, functions: { mode: 'allowlist', list: ['my_udf'] } }
  it('blocks evil.<safe-or-listed-name> in allowlist mode', async () => {
    expect(await code('SELECT evil.count(id) FROM users', allowlist)).toBe(ViolationCode.FunctionNotAllowed)
    expect(await code('SELECT evil.my_udf(id) FROM users', allowlist)).toBe(ViolationCode.FunctionNotAllowed)
  })
  it('still allows the built-in / listed function unqualified or via pg_catalog', async () => {
    expect(await allowed('SELECT count(id) FROM users', allowlist)).toBe(true)
    expect(await allowed('SELECT my_udf(id) FROM users', allowlist)).toBe(true)
    expect(await allowed('SELECT pg_catalog.count(id) FROM users', allowlist)).toBe(true)
  })
})

describe('V18: configuration / auth-file reading functions are blocked', () => {
  it('blocks GUC and HBA/ident-file readers in default (denylist) mode', async () => {
    expect(await code("SELECT current_setting('data_directory')")).toBe(ViolationCode.FunctionNotAllowed)
    expect(await code('SELECT * FROM pg_hba_file_rules()')).toBe(ViolationCode.FunctionNotAllowed)
    expect(await code('SELECT * FROM pg_ident_file_mappings()')).toBe(ViolationCode.FunctionNotAllowed)
    expect(await code('SELECT * FROM pg_show_all_settings()')).toBe(ViolationCode.FunctionNotAllowed)
  })
})

describe('V19: write-RLS USING filter is scope-aware (no subquery re-qualification)', () => {
  const m: PermissionModel = {
    tables: {
      'public.docs': {
        select: true,
        update: { columns: ['body'] },
        rls: { update: 'owner_id IN (SELECT owner_id FROM memberships WHERE org_id = ctx.org)' },
      },
      'public.memberships': { select: true },
    },
  }
  it('qualifies only the predicate’s outer columns, leaving the subquery’s own intact', async () => {
    const d = await analyze("UPDATE docs SET body = 'x'", { model: m, context: { ctx: { org: 7 } } })
    expect(d.allow).toBe(true)
    if (d.allow) {
      const sql = d.sql.replace(/\s+/g, ' ')
      expect(sql).toMatch(
        /docs\.owner_id IN \(SELECT owner_id FROM public\.memberships WHERE org_id = 7\)/,
      )
      // the subquery's own columns must NOT be rebound to the write target
      expect(sql).not.toMatch(/SELECT docs\.owner_id/)
      expect(sql).not.toMatch(/docs\.org_id/)
    }
  })
})

describe('V20: SELECT INTO hidden in a set-op arm / CTE / subquery', () => {
  it('blocks SELECT INTO on the leftmost arm of a set-operation (it creates a table)', async () => {
    expect(await code('SELECT id INTO newt FROM users UNION SELECT user_id FROM profiles')).toBe(
      ViolationCode.StatementNotAllowed,
    )
    expect(await code('SELECT id INTO newt FROM users INTERSECT SELECT user_id FROM profiles')).toBe(
      ViolationCode.StatementNotAllowed,
    )
  })
  it('blocks SELECT INTO nested in a CTE body or subquery', async () => {
    expect(await code('WITH x AS (SELECT id INTO newt FROM users) SELECT * FROM x')).toBe(
      ViolationCode.StatementNotAllowed,
    )
    expect(await code('SELECT * FROM (SELECT id INTO newt FROM users) q')).toBe(
      ViolationCode.StatementNotAllowed,
    )
  })
  it('still allows a plain set-operation', async () => {
    expect(await allowed('SELECT id FROM users UNION SELECT user_id FROM profiles')).toBe(true)
  })
})

describe('V21: reg* object-resolution casts are blocked (catalog/OID oracle)', () => {
  it('blocks ::reg* casts and CAST(... AS reg*)', async () => {
    expect(await code("SELECT 'pg_authid'::regclass")).toBe(ViolationCode.TypeCastNotAllowed)
    expect(await code("SELECT 'secret'::regclass::int")).toBe(ViolationCode.TypeCastNotAllowed)
    expect(await code("SELECT CAST('secret' AS regclass)")).toBe(ViolationCode.TypeCastNotAllowed)
    expect(await code("SELECT 'x'::regproc")).toBe(ViolationCode.TypeCastNotAllowed)
    expect(await code("SELECT 'r'::regrole")).toBe(ViolationCode.TypeCastNotAllowed)
  })
  it('blocks a reg* cast smuggled into an otherwise-permitted query', async () => {
    expect(await code("SELECT id FROM users WHERE id = ('pg_authid'::regclass::int)")).toBe(
      ViolationCode.TypeCastNotAllowed,
    )
  })
  it('blocks the to_reg* lookup function family', async () => {
    expect(await code("SELECT to_regclass('secret')")).toBe(ViolationCode.FunctionNotAllowed)
  })
  it('blocks the function-call spelling of a reg* cast (regclass(...) ≡ ::regclass)', async () => {
    // `regclass('x')` is the same name→OID oracle as `'x'::regclass` but parses as a
    // FuncCall, so it would slip past the (cast-only) gate — route it to the cast check.
    expect(await code("SELECT regclass('pg_authid')")).toBe(ViolationCode.TypeCastNotAllowed)
    expect(await code("SELECT regnamespace('pg_catalog')")).toBe(ViolationCode.TypeCastNotAllowed)
    expect(await code("SELECT regrole('postgres')")).toBe(ViolationCode.TypeCastNotAllowed)
    // …and the raw I/O functions (name↔OID resolvers), incl. the PG18 regdatabase type.
    expect(await code("SELECT regclassin('pg_authid')")).toBe(ViolationCode.TypeCastNotAllowed)
    expect(await code('SELECT regclassout(1259)')).toBe(ViolationCode.TypeCastNotAllowed)
    expect(await code("SELECT regdatabase('postgres')")).toBe(ViolationCode.TypeCastNotAllowed)
  })
  it('does NOT over-block regexp_*/regr_* (names that merely start with "reg")', async () => {
    expect(await allowed("SELECT regexp_replace(email, 'a', 'b') FROM users")).toBe(true)
    expect(await allowed('SELECT regr_slope(id, id) FROM users')).toBe(true)
  })
  it('still allows ordinary type casts', async () => {
    expect(await allowed('SELECT id::text FROM users')).toBe(true)
  })
})

describe('V22: a disallowed statement (MERGE) nested in a CTE is blocked', () => {
  it('blocks MERGE at the top level and hidden inside a CTE body', async () => {
    expect(
      await code('MERGE INTO users u USING profiles s ON u.id = s.user_id WHEN MATCHED THEN DO NOTHING'),
    ).toBe(ViolationCode.StatementNotAllowed)
    expect(
      await code(
        "WITH m AS (MERGE INTO users u USING profiles s ON u.id = s.user_id WHEN MATCHED THEN UPDATE SET email = 'x' RETURNING 1) SELECT * FROM m",
      ),
    ).toBe(ViolationCode.StatementNotAllowed)
  })
  it('still allows a data-modifying CTE of a permitted write', async () => {
    expect(
      await allowed("WITH u AS (UPDATE users SET email = 'x' WHERE id = 1 RETURNING id) SELECT * FROM u"),
    ).toBe(true)
  })
})

describe('V23: non-finite numeric ctx value fails closed', () => {
  const m: PermissionModel = {
    tables: { 'public.users': { select: { columns: ['id', 'email'] }, rls: { select: 'org = ctx.t' } } },
  }
  const withT = (t: number) => analyze('SELECT id FROM users', { model: m, catalog, context: { ctx: { t } } })
  it('denies Infinity / -Infinity / NaN (would deparse to a bare identifier)', async () => {
    for (const t of [Infinity, -Infinity, NaN]) {
      const d = await withT(t)
      expect(d.allow, String(t)).toBe(false)
      if (!d.allow) expect(d.violations[0]?.code).toBe(ViolationCode.RewriteFailed)
    }
  })
  it('still allows a finite value, injected as a literal', async () => {
    const d = await withT(42)
    expect(d.allow).toBe(true)
    if (d.allow) expect(d.sql.replace(/\s+/g, ' ')).toMatch(/org = 42/)
  })
})

describe('V24: object-introspection functions are blocked', () => {
  it('blocks size / privilege / lookup metadata functions on hidden objects', async () => {
    expect(await code("SELECT pg_relation_size('secret')")).toBe(ViolationCode.FunctionNotAllowed)
    expect(await code("SELECT has_table_privilege('secret', 'SELECT')")).toBe(ViolationCode.FunctionNotAllowed)
    expect(await code("SELECT pg_get_serial_sequence('secret', 'id')")).toBe(ViolationCode.FunctionNotAllowed)
    expect(await code('SELECT obj_description(2200)')).toBe(ViolationCode.FunctionNotAllowed)
  })
})

describe('V25: explicit grant wins over the pg_ name-prefix introspection heuristic', () => {
  const pgcat = new MemoryCatalog({
    tables: {
      'public.pg_class': ['relname', 'relowner'],
      'pg_catalog.pg_class': ['oid', 'relname', 'relowner', 'relacl'],
    },
  })
  const m: PermissionModel = {
    tables: { 'public.pg_class': { select: { columns: ['relname'] } } },
    introspection: { enabled: true },
  }
  it('a granted user table named pg_* is not hijacked to the system catalog', async () => {
    // relowner is a catalog column NOT granted on public.pg_class → must DENY
    const d = await analyze('SELECT relowner FROM pg_class', { model: m, catalog: pgcat })
    expect(d.allow).toBe(false)
    if (!d.allow) expect(d.violations[0]?.code).toBe(ViolationCode.ColumnNotReadable)
  })
  it('reads the granted column from the user table, qualified to its own schema', async () => {
    const d = await analyze('SELECT relname FROM pg_class', { model: m, catalog: pgcat })
    expect(d.allow).toBe(true)
    if (d.allow) expect(d.sql).toMatch(/public\.pg_class/)
  })
})

describe('V26: NUL byte in a ctx value fails closed', () => {
  const m: PermissionModel = {
    tables: { 'public.users': { select: true, rls: { select: 'email = ctx.v' } } },
  }
  const withV = (v: string) => analyze('SELECT id FROM users', { model: m, catalog, context: { ctx: { v } } })
  it('denies a ctx value containing a NUL (would truncate the wire statement)', async () => {
    expect((await withV('a' + String.fromCharCode(0) + 'b')).allow).toBe(false)
  })
  it('still allows an ordinary string ctx value', async () => {
    expect((await withV('normal@example.com')).allow).toBe(true)
  })
})

describe('V27: malformed RLS predicate fails closed (no tautology absorption)', () => {
  const withPred = (pred: string) =>
    analyze('SELECT id FROM users', {
      model: { tables: { 'public.users': { select: { columns: ['id'] }, rls: { select: pred } } } },
      catalog,
      context: { ctx: {} },
    })
  it('denies a predicate with self-balancing parens instead of widening access', async () => {
    const d = await withPred('org = 1) OR (1=1')
    expect(d.allow).toBe(false)
    if (!d.allow) expect(d.violations[0]?.code).toBe(ViolationCode.RewriteFailed)
  })
  it('still applies a well-formed predicate', async () => {
    const d = await withPred('org = 1')
    expect(d.allow).toBe(true)
    if (d.allow) expect(d.sql.replace(/\s+/g, ' ')).toMatch(/org = 1/)
  })
})

describe('V30: deparse preserves identifiers with embedded newlines (no pretty-print mangling)', () => {
  it('a granted column whose name contains a newline is forwarded unchanged', async () => {
    const weird = 'col\nx'
    const m: PermissionModel = { tables: { 'public.t': { select: { columns: [weird, 'id'] } } } }
    const c = new MemoryCatalog({ tables: { 'public.t': ['id', weird] } })
    const d = await analyze('SELECT * FROM t', { model: m, catalog: c })
    expect(d.allow).toBe(true)
    // `*` expands to the granted column; the forwarded SQL must contain the exact
    // identifier (newline directly followed by `x`), not the indented `col\n  x`.
    if (d.allow) expect(d.sql).toContain(weird)
  })
})

describe('V28: cluster-administration functions are blocked', () => {
  it('blocks WAL / backup / replication / promotion / recovery admin functions', async () => {
    for (const sql of [
      'SELECT pg_promote()',
      'SELECT pg_switch_wal()',
      "SELECT pg_create_restore_point('x')",
      "SELECT pg_backup_start('l')",
      'SELECT pg_wal_replay_pause()',
      "SELECT pg_drop_replication_slot('s')",
      "SELECT pg_create_logical_replication_slot('s', 'pgoutput')",
      "SELECT pg_logical_emit_message(true, 'p', 'm')",
      "SELECT pg_replication_origin_create('o')", // prefix family
      "SELECT pg_logical_slot_get_changes('s', NULL, NULL)", // prefix family
    ]) {
      expect(await code(sql), sql).toBe(ViolationCode.FunctionNotAllowed)
    }
  })
})

describe('V31: a whole-row aggregate over a derived source is allowed (not over-denied)', () => {
  it('allows json_agg/array_agg/to_jsonb of a subquery, CTE, or function whose columns are permitted', async () => {
    expect(await allowed('SELECT json_agg(o) FROM (SELECT id FROM users) o')).toBe(true)
    expect(await allowed('SELECT array_agg(o) FROM (SELECT id, email FROM users) o')).toBe(true)
    expect(await allowed('WITH c AS (SELECT id FROM users) SELECT json_agg(c) FROM c')).toBe(true)
    expect(await allowed('SELECT json_agg(g) FROM generate_series(1, 3) g')).toBe(true)
    expect(await allowed('SELECT json_agg(o) FROM (SELECT id FROM users) o, profiles p WHERE p.user_id = 1')).toBe(true)
  })
  it('still denies a whole-row aggregate over a column-restricted base relation', async () => {
    expect(await code('SELECT json_agg(users) FROM users')).toBe(ViolationCode.ColumnNotReadable)
  })
  it('still denies a forbidden column hidden inside the derived source', async () => {
    expect(await code('SELECT json_agg(o) FROM (SELECT password FROM users) o')).toBe(
      ViolationCode.ColumnNotReadable,
    )
  })
  it('respects column precedence: a derived alias that collides with a real forbidden column is denied', async () => {
    expect(await code('SELECT password FROM (SELECT 1) password, users')).toBe(
      ViolationCode.ColumnNotReadable,
    )
  })
})

describe('V32: INSERT WITH CHECK fails closed on an unprovable DEFAULT value', () => {
  const m: PermissionModel = {
    tables: { 'public.t': { select: true, insert: { columns: ['id', 'tenant'] }, rls: { insert: 'tenant = ctx.tid' } } },
  }
  const cat = new MemoryCatalog({ tables: { 'public.t': ['id', 'tenant'] } })
  const run2 = (sql: string) => analyze(sql, { model: m, catalog: cat, context: { ctx: { tid: 1 } } })
  it('denies an explicit DEFAULT in the row (the server-side value can’t be checked)', async () => {
    const d = await run2('INSERT INTO t (id, tenant) VALUES (1, DEFAULT)')
    expect(d.allow).toBe(false)
    if (!d.allow) expect(d.violations[0]?.code).toBe(ViolationCode.RewriteFailed)
  })
  it('allows an explicit value — the WITH CHECK filters non-matching rows at runtime', async () => {
    // matching tenant is forwarded; a wrong tenant is still allowed but filtered to 0 rows
    expect((await run2('INSERT INTO t (id, tenant) VALUES (1, 1)')).allow).toBe(true)
    const wrong = await run2('INSERT INTO t (id, tenant) VALUES (1, 5)')
    expect(wrong.allow).toBe(true)
    if (wrong.allow) expect(wrong.sql.replace(/\s+/g, ' ')).toMatch(/WHERE tenant = 1/)
  })
})
