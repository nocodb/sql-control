import { describe, expect, it } from 'vitest'
import { analyze } from '../src/analyzer/index'
import { ViolationCode } from '../src/analyzer/errors'
import { MemoryCatalog } from '../src/schema/memory-catalog'
import {
  BUILTIN_OPERATORS,
  DANGEROUS_FUNCTIONS,
  SAFE_FUNCTIONS,
} from '../src/policy/functions'
import { SENSITIVE_SYSTEM_RELATIONS } from '../src/policy/system-catalogs'
import { REG_CAST_TYPES } from '../src/analyzer/collect'
import type { PermissionModel } from '../src/policy/model'

/**
 * Exhaustive, data-driven enforcement matrix generated from the actual policy
 * sets, so the suite grows automatically whenever a set does and any drift
 * between a set and its enforcement shows up as a failing case. Covers: every
 * dangerous function denied, prefix families denied, every sensitive catalog
 * blocked (even when opted into introspection), every reg* cast denied, built-in
 * operators allowed, and a representative slice of safe functions allowed.
 */
const model: PermissionModel = {
  tables: { 'public.users': { select: { columns: ['id', 'email'] } } },
}
const catalog = new MemoryCatalog({ tables: { 'public.users': ['id', 'email', 'password'] } })
const run = (sql: string, m: PermissionModel = model) =>
  analyze(sql, { model: m, catalog, context: { ctx: {} } })

async function firstCode(sql: string, m?: PermissionModel): Promise<ViolationCode | undefined> {
  const d = await run(sql, m)
  return d.allow ? undefined : d.violations[0]?.code
}

// ── every dangerous function is denied as a function call ─────────────────────
describe('dangerous functions are denied', () => {
  const cases: [string, string][] = [...DANGEROUS_FUNCTIONS].map((fn) => [fn, `SELECT ${fn}(NULL)`])
  it.each(cases)('denies %s', async (_fn, sql) => {
    expect(await firstCode(sql)).toBe(ViolationCode.FunctionNotAllowed)
  })
})

// ── dangerous prefix families: members NOT explicitly listed are still denied ──
describe('dangerous function families are denied by prefix', () => {
  const familyMembers = [
    'pg_read_server_files', 'pg_read_file_old',
    'pg_ls_dir_recurse', 'pg_ls_tmpdir',
    'lo_truncate', 'lo_truncate64', 'lo_tell', 'lo_lseek',
    'dblink_error_message', 'dblink_get_connections', 'dblink_is_busy',
    'binary_upgrade_create_empty_extension', 'binary_upgrade_set_next_pg_type_oid',
    'pg_advisory_lock', 'pg_advisory_unlock', 'pg_advisory_xact_lock',
    'crosstab2', 'crosstab3', 'crosstab4',
    'pg_replication_origin_create', 'pg_replication_origin_session_setup',
    'pg_logical_slot_get_changes', 'pg_logical_slot_peek_changes',
    'pg_stat_get_backend_pid', 'pg_stat_get_db_xact_commit', 'pg_stat_get_backend_dbid',
  ]
  const cases: [string, string][] = familyMembers.map((fn) => [fn, `SELECT ${fn}(NULL)`])
  it.each(cases)('denies %s', async (_fn, sql) => {
    expect(await firstCode(sql)).toBe(ViolationCode.FunctionNotAllowed)
  })
})

// ── every sensitive catalog is blocked even with introspection + allowUnfiltered ─
describe('sensitive catalogs are blocked even when opted into introspection', () => {
  const cases = [...SENSITIVE_SYSTEM_RELATIONS].map((rel): [string, string] => [rel, rel])
  it.each(cases)('blocks %s', async (rel, _x) => {
    const m: PermissionModel = {
      tables: { 'public.users': { select: { columns: ['id'] } } },
      introspection: { enabled: true, allowUnfiltered: [rel, `pg_catalog.${rel}`, `information_schema.${rel}`] },
    }
    const d = await analyze(`SELECT * FROM ${rel}`, { model: m, context: { ctx: {} } })
    expect(d.allow, rel).toBe(false)
    if (!d.allow) expect(d.violations[0]?.code, rel).toBe(ViolationCode.SystemCatalogBlocked)
  })
})

// ── every reg* object-resolution cast is denied ───────────────────────────────
describe('reg* casts are denied (object/OID oracle)', () => {
  // Driven from the REAL exported set so a reg type added to the source (e.g. PG18's
  // regdatabase) is automatically covered here — the test can never silently miss one.
  const REG = [...REG_CAST_TYPES]
  const cases: [string, string][] = REG.flatMap((t) => [
    [`${t} (target)`, `SELECT 'x'::${t}`],
    [`${t} (where)`, `SELECT id FROM users WHERE 'x'::${t} IS NOT NULL`],
    // array-of-reg: the array-ness lives in arrayBounds, the type name is still `${t}`,
    // so the detection must still fire (a `${t}[]` cast resolves names element-wise).
    [`${t}[] (array)`, `SELECT '{x}'::${t}[]`],
  ])
  it.each(cases)('denies cast to %s', async (_label, sql) => {
    expect(await firstCode(sql)).toBe(ViolationCode.TypeCastNotAllowed)
  })
})

// ── built-in operators (binary forms) are allowed ─────────────────────────────
describe('built-in operators are allowed', () => {
  // Curated binary forms that parse cleanly; each symbol is in BUILTIN_OPERATORS.
  const binary: [string, string][] = [
    ['=', "SELECT id FROM users WHERE id = 1"],
    ['<>', "SELECT id FROM users WHERE id <> 1"],
    ['<', "SELECT id FROM users WHERE id < 1"],
    ['>', "SELECT id FROM users WHERE id > 1"],
    ['<=', "SELECT id FROM users WHERE id <= 1"],
    ['>=', "SELECT id FROM users WHERE id >= 1"],
    ['+', "SELECT id FROM users WHERE id + 1 > 0"],
    ['-', "SELECT id FROM users WHERE id - 1 > 0"],
    ['*', "SELECT id FROM users WHERE id * 2 > 0"],
    ['/', "SELECT id FROM users WHERE id / 2 > 0"],
    ['%', "SELECT id FROM users WHERE id % 2 = 0"],
    ['^', "SELECT id FROM users WHERE id ^ 2 > 0"],
    ['||', "SELECT email || 'x' FROM users"],
    ['~~ (like)', "SELECT id FROM users WHERE email ~~ 'a%'"],
    ['!~~ (not like)', "SELECT id FROM users WHERE email !~~ 'a%'"],
    ['~ (regex)', "SELECT id FROM users WHERE email ~ 'a'"],
    ['~* (iregex)', "SELECT id FROM users WHERE email ~* 'a'"],
    ['-> (json)', "SELECT ('{}'::jsonb) -> 'k' FROM users"],
    ['->> (json)', "SELECT ('{}'::jsonb) ->> 'k' FROM users"],
    ['#> (json)', "SELECT ('{}'::jsonb) #> '{k}' FROM users"],
    ['@> (contains)', "SELECT id FROM users WHERE '{}'::jsonb @> '{}'::jsonb"],
    ['<@ (contained)', "SELECT id FROM users WHERE '{}'::jsonb <@ '{}'::jsonb"],
    ['&& (overlap)', "SELECT id FROM users WHERE ARRAY[1] && ARRAY[1]"],
    ['? (json exists)', "SELECT id FROM users WHERE '{}'::jsonb ? 'k'"],
  ]
  it.each(binary)('allows %s', async (_label, sql) => {
    expect((await run(sql)).allow, sql).toBe(true)
  })
  it('every curated symbol is actually a member of BUILTIN_OPERATORS', () => {
    const symbols = ['=', '<>', '<', '>', '<=', '>=', '+', '-', '*', '/', '%', '^', '||', '~~', '!~~', '~', '~*', '->', '->>', '#>', '@>', '<@', '&&', '?']
    for (const s of symbols) expect(BUILTIN_OPERATORS.has(s), s).toBe(true)
  })
})

// ── a representative slice of safe functions is allowed in denylist mode ───────
describe('safe functions are allowed', () => {
  const safe: [string, string][] = [
    ['lower', "SELECT lower(email) FROM users"],
    ['upper', "SELECT upper(email) FROM users"],
    ['length', "SELECT length(email) FROM users"],
    ['char_length', "SELECT char_length(email) FROM users"],
    ['trim', "SELECT trim(email) FROM users"],
    ['btrim', "SELECT btrim(email) FROM users"],
    ['ltrim', "SELECT ltrim(email) FROM users"],
    ['rtrim', "SELECT rtrim(email) FROM users"],
    ['substr', "SELECT substr(email, 1, 2) FROM users"],
    ['substring', "SELECT substring(email, 1, 2) FROM users"],
    ['replace', "SELECT replace(email, 'a', 'b') FROM users"],
    ['concat', "SELECT concat(email, '!') FROM users"],
    ['concat_ws', "SELECT concat_ws(',', email, email) FROM users"],
    ['left', "SELECT left(email, 2) FROM users"],
    ['right', "SELECT right(email, 2) FROM users"],
    ['split_part', "SELECT split_part(email, '@', 1) FROM users"],
    ['initcap', "SELECT initcap(email) FROM users"],
    ['md5', "SELECT md5(email) FROM users"],
    ['strpos', "SELECT strpos(email, '@') FROM users"],
    ['position', "SELECT position('@' in email) FROM users"],
    ['format', "SELECT format('%s', email) FROM users"],
    ['abs', "SELECT abs(id) FROM users"],
    ['round', "SELECT round(id) FROM users"],
    ['ceil', "SELECT ceil(id) FROM users"],
    ['floor', "SELECT floor(id) FROM users"],
    ['mod', "SELECT mod(id, 2) FROM users"],
    ['power', "SELECT power(id, 2) FROM users"],
    ['sqrt', "SELECT sqrt(id) FROM users"],
    ['trunc', "SELECT trunc(id) FROM users"],
    ['coalesce', "SELECT coalesce(email, '?') FROM users"],
    ['nullif', "SELECT nullif(email, '') FROM users"],
    ['greatest', "SELECT greatest(id, 1) FROM users"],
    ['least', "SELECT least(id, 1) FROM users"],
    ['count', "SELECT count(*) FROM users"],
    ['sum', "SELECT sum(id) FROM users"],
    ['avg', "SELECT avg(id) FROM users"],
    ['min', "SELECT min(id) FROM users"],
    ['max', "SELECT max(id) FROM users"],
    ['array_agg', "SELECT array_agg(id) FROM users"],
    ['string_agg', "SELECT string_agg(email, ',') FROM users"],
    ['date_trunc', "SELECT date_trunc('day', now()) FROM users"],
    ['to_char', "SELECT to_char(now(), 'YYYY') FROM users"],
  ]
  it.each(safe)('allows %s', async (_label, sql) => {
    expect((await run(sql)).allow, sql).toBe(true)
  })
  it('each curated name is in SAFE_FUNCTIONS', () => {
    const names = ['lower', 'upper', 'length', 'char_length', 'trim', 'btrim', 'ltrim', 'rtrim', 'substr', 'substring', 'replace', 'concat', 'concat_ws', 'left', 'right', 'split_part', 'initcap', 'md5', 'strpos', 'position', 'format', 'abs', 'round', 'ceil', 'floor', 'mod', 'power', 'sqrt', 'trunc', 'coalesce', 'nullif', 'greatest', 'least', 'count', 'sum', 'avg', 'min', 'max', 'array_agg', 'string_agg', 'date_trunc', 'to_char']
    for (const n of names) expect(SAFE_FUNCTIONS.has(n), n).toBe(true)
  })
})
