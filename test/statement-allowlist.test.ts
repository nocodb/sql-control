import { describe, expect, it } from 'vitest'
import { analyze } from '../src/analyzer/index'
import type { PermissionModel } from '../src/policy/model'

/**
 * The statement allowlist is the "no schema altering / no code execution / no
 * privilege change" guarantee. This pins the statements that must ALWAYS be
 * denied regardless of any future session-statement policy (the corpus test
 * covers the long tail generically). Session-control statements drivers need
 * (transaction control, safe SET/SHOW/DISCARD) are deliberately NOT asserted here
 * — those are gated by a separate session policy, not this hard allowlist.
 */
const model: PermissionModel = {
  tables: { 'public.t': { select: true, insert: true, update: true, delete: true } },
}
const allowed = async (sql: string): Promise<boolean> =>
  (await analyze(sql, { model, context: { ctx: {} } })).allow

const DANGEROUS: [string, string][] = [
  // arbitrary code / SQL execution
  ['EXPLAIN ANALYZE (executes the plan)', 'EXPLAIN ANALYZE SELECT * FROM t'],
  ['CALL procedure', 'CALL my_proc(1)'],
  ['DO anonymous block', 'DO $$ BEGIN PERFORM 1; END $$'],
  // prepared-statement & cursor statements — they run / fetch a query the analyzer
  // never re-checks at use time, and cursors imply connection affinity we don't
  // support; must stay denied even if a future session policy is added.
  ['PREPARE', 'PREPARE p AS SELECT * FROM t'],
  ['EXECUTE (runs an unanalyzed prepared stmt)', 'EXECUTE p(1)'],
  ['DEALLOCATE', 'DEALLOCATE p'],
  ['DECLARE CURSOR', 'DECLARE c CURSOR FOR SELECT * FROM t'],
  ['FETCH', 'FETCH 10 FROM c'],
  ['MOVE', 'MOVE 5 IN c'],
  ['CLOSE', 'CLOSE c'],
  ['DISCARD ALL', 'DISCARD ALL'],
  // MERGE writes (insert/update/delete) without going through our write checks — it
  // is NOT one of the four permitted DML tags, so it must be denied at top level too
  // (the nested-in-CTE case is covered separately in security.test.ts).
  ['MERGE (top-level write bypass)', 'MERGE INTO t USING t s ON t.id = s.id WHEN MATCHED THEN DELETE'],
  // table-creating SELECTs (distinct from the intoClause scan).
  ['CREATE TABLE AS', 'CREATE TABLE x AS SELECT * FROM t'],
  ['CREATE MATERIALIZED VIEW AS', 'CREATE MATERIALIZED VIEW mv AS SELECT * FROM t'],
  ['IMPORT FOREIGN SCHEMA', 'IMPORT FOREIGN SCHEMA s FROM SERVER srv INTO public'],
  // file / program / network access
  ['COPY TO PROGRAM', "COPY t TO PROGRAM 'sh -c whoami'"],
  ['COPY FROM file', "COPY t FROM '/etc/passwd'"],
  ['COPY (SELECT) TO STDOUT', 'COPY (SELECT * FROM t) TO STDOUT'],
  ['CREATE EXTENSION', 'CREATE EXTENSION dblink'],
  ['LOAD shared library', "LOAD 'evil.so'"],
  // dangerous session/role state (must stay denied even with a session policy)
  ['SET search_path', 'SET search_path = evil'],
  ['SET ROLE', 'SET ROLE postgres'],
  ['SET session_authorization', 'SET SESSION AUTHORIZATION postgres'],
  ['SET row_security', 'SET row_security = off'],
  // server / async / maintenance
  ['LISTEN', 'LISTEN ch'],
  ['NOTIFY', "NOTIFY ch, 'x'"],
  ['CHECKPOINT', 'CHECKPOINT'],
  ['VACUUM', 'VACUUM t'],
  ['CLUSTER', 'CLUSTER t'],
  ['REINDEX', 'REINDEX TABLE t'],
  ['REFRESH MATERIALIZED VIEW', 'REFRESH MATERIALIZED VIEW mv'],
  // schema-altering DDL
  ['CREATE TABLE', 'CREATE TABLE x (i int)'],
  ['DROP TABLE', 'DROP TABLE t'],
  ['ALTER TABLE', 'ALTER TABLE t ADD COLUMN z int'],
  ['TRUNCATE', 'TRUNCATE t'],
  ['GRANT', 'GRANT ALL ON t TO public'],
  ['CREATE FUNCTION', 'CREATE FUNCTION f() RETURNS int AS $$ SELECT 1 $$ LANGUAGE sql'],
  ['COMMENT ON', "COMMENT ON TABLE t IS 'x'"],
  ['SECURITY LABEL', "SECURITY LABEL ON TABLE t IS 'x'"],
]

describe('statement allowlist denies every non-DML statement type', () => {
  it.each(DANGEROUS)('denies %s', async (_l, sql) => {
    expect(await allowed(sql), sql).toBe(false)
  })
})

describe('statement stacking is rejected (no second statement rides along)', () => {
  // Even when the FIRST statement is permitted, a stacked second statement must
  // sink the whole request — a denied tail can't piggyback on an allowed head.
  it.each([
    ['DML head + DDL tail', 'SELECT * FROM t; DROP TABLE t'],
    ['DML head + COPY-PROGRAM tail', "SELECT 1; COPY t TO PROGRAM 'id'"],
    ['two permitted statements still rejected', 'SELECT 1; SELECT 2'],
  ])('denies %s', async (_l, sql) => {
    expect(await allowed(sql), sql).toBe(false)
  })
  // A bare trailing semicolon is NOT a second statement (Postgres accepts it too) —
  // it must stay allowed so the guard doesn't false-reject ordinary client SQL.
  it('allows a single statement with a trailing semicolon', async () => {
    expect(await allowed('SELECT * FROM t;')).toBe(true)
    expect(await allowed('SELECT * FROM t;;')).toBe(true)
  })
})

describe('the four permitted DML statements are allowed', () => {
  it.each([
    ['SELECT', 'SELECT * FROM t'],
    ['INSERT', "INSERT INTO t DEFAULT VALUES"],
    ['UPDATE', 'UPDATE t SET x = 1'],
    ['DELETE', 'DELETE FROM t'],
  ])('allows %s', async (_l, sql) => {
    expect(await allowed(sql), sql).toBe(true)
  })
})
