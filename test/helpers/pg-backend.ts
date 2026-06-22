/**
 * Adapt a real Postgres query runner (PGlite in-process, or a node-pg Pool) into
 * a sql-control {@link Backend}, so the e2e suite can run the proxy in front of a
 * REAL Postgres and verify the rewritten SQL actually executes and returns the
 * right data. Values are rendered to Postgres text format (what the wire sends).
 */
import type { Backend, QueryResult } from '../../src/proxy/handler'

/** Result of an array-mode query from a real Postgres runner. */
export interface RawResult {
  rows: unknown[][]
  fields: readonly { name: string; dataTypeID: number }[]
  affectedRows?: number
  command?: string
}

/** Runs SQL (array row mode) against a real Postgres — PGlite or a node-pg Pool. */
export type RawQuery = (sql: string, params: unknown[] | undefined) => Promise<RawResult>

/** Render a JS value to the Postgres text representation used on the wire. */
function toText(value: unknown): string | null {
  if (value === null || value === undefined) return null
  if (typeof value === 'boolean') return value ? 't' : 'f'
  if (value instanceof Date) return value.toISOString()
  if (typeof value === 'object') return JSON.stringify(value)
  return String(value)
}

/** Build a command tag (`SELECT 2`, `UPDATE 1`, `INSERT 0 1`, …). */
function commandTag(
  sql: string,
  command: string | undefined,
  rowCount: number,
  affected: number | undefined,
): string {
  const cmd = (command ?? sql.trimStart().split(/[\s(]+/)[0] ?? '').toUpperCase()
  const n = affected ?? rowCount
  if (cmd === 'INSERT') return `INSERT 0 ${n}`
  if (cmd === 'SELECT' || cmd === 'WITH' || cmd === 'VALUES') return `SELECT ${rowCount}`
  return `${cmd} ${n}`
}

function toQueryResult(
  sql: string,
  rows: unknown[][],
  fields: readonly { name: string; dataTypeID: number }[],
  affected: number | undefined,
  command: string | undefined,
): QueryResult {
  return {
    fields: fields.map((f) => ({ name: f.name, dataTypeID: f.dataTypeID })),
    rows: rows.map((row) => row.map(toText)),
    tag: commandTag(sql, command, rows.length, affected),
  }
}

/** A {@link Backend} backed by any array-mode Postgres runner (PGlite / node-pg). */
export function backendFromQuery(run: RawQuery): Backend {
  return async (sql, params) => {
    const result = await run(sql, params ? [...params] : undefined)
    return toQueryResult(sql, result.rows, result.fields, result.affectedRows, result.command)
  }
}

/** Schema + rows used by the e2e tests: multi-tenant, with a hidden table.
 *  Idempotent so it can re-seed a persistent real-PG database between runs. */
export const SEED_SQL = `
  DROP TABLE IF EXISTS users, notes, secrets;
  CREATE TABLE users (id int PRIMARY KEY, email text, password text, tenant_id int);
  INSERT INTO users VALUES
    (1, 'a@x.com', 'hash-a', 1),
    (2, 'b@y.com', 'hash-b', 1),
    (3, 'c@z.com', 'hash-c', 2);
  CREATE TABLE notes (id int PRIMARY KEY, body text, tenant_id int);
  INSERT INTO notes VALUES (1, 'note-1', 1), (2, 'note-2', 2);
  CREATE TABLE secrets (id int PRIMARY KEY, val text);
  INSERT INTO secrets VALUES (1, 'top-secret');
`
