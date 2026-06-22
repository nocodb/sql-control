import { parse } from 'pgsql-parser'
import { Violations } from './errors'
import { tagOf, type AstNode, type NodeTag, type ParseResult } from './nodes'
import { deny, type Decision } from './types'

/**
 * The only statement node types permitted. Everything else — DDL (CREATE /
 * ALTER / DROP / TRUNCATE), GRANT/REVOKE, COPY, transaction and session
 * utilities, etc. — is rejected outright. This is the "no schema altering"
 * guarantee, enforced as a default-deny allow-list rather than a denylist.
 *
 * Declared as `NodeTag[]` so a typo is a compile error, then read as a string
 * set so membership tests need no assertion.
 */
const ALLOWED_STATEMENT_TAGS: readonly NodeTag[] = [
  'SelectStmt',
  'InsertStmt',
  'UpdateStmt',
  'DeleteStmt',
]
const ALLOWED_STATEMENTS = new Set<string>(ALLOWED_STATEMENT_TAGS)

/**
 * Whether a non-null `intoClause` appears anywhere in the tree. `SELECT ... INTO`
 * creates a table, and it can hide on the leftmost arm of a set-operation (where
 * Postgres binds it and turns the whole statement into CREATE TABLE AS), in a CTE
 * body, or in a subquery. Set-operation arms are bare `SelectStmt` objects (not
 * wrapped under a `SelectStmt` key), so this scans raw object shape.
 */
function containsIntoClause(value: unknown): boolean {
  if (value === null || typeof value !== 'object') return false
  if (Array.isArray(value)) return value.some(containsIntoClause)
  if ('intoClause' in value && value.intoClause != null) return true
  return Object.values(value).some(containsIntoClause)
}

/**
 * Find a disallowed statement node nested anywhere in the tree (e.g. a `MergeStmt`
 * hidden in a CTE body or subquery). The top-level tag is checked separately; a
 * nested statement whose tag is not in {@link ALLOWED_STATEMENTS} — every node
 * type ends in `Stmt` — is rejected so a write/DDL can't ride inside an allowed
 * statement. Nested Select/Insert/Update/Delete are fine (subqueries, data-
 * modifying CTEs) and still get permission-checked downstream.
 */
function nestedDisallowedStatement(value: unknown): string | undefined {
  if (value === null || typeof value !== 'object') return undefined
  if (Array.isArray(value)) {
    for (const item of value) {
      const found = nestedDisallowedStatement(item)
      if (found) return found
    }
    return undefined
  }
  const tag = tagOf(value)
  if (tag && tag.endsWith('Stmt') && !ALLOWED_STATEMENTS.has(tag)) return tag
  for (const child of Object.values(value)) {
    const found = nestedDisallowedStatement(child)
    if (found) return found
  }
  return undefined
}

export interface GuardOk {
  ok: true
  /** The single top-level statement node, e.g. `{ SelectStmt: {...} }`. */
  stmt: AstNode
  /** The full parse result, for deparse round-tripping after rewrite. */
  parsed: ParseResult
  type: string
}

export type GuardResult = GuardOk | { ok: false; decision: Decision }

/**
 * Parse the SQL and enforce the structural rules that precede any permission
 * check: it must parse, be exactly one statement (no stacking), and be a DML
 * statement.
 */
export async function guard(sql: string): Promise<GuardResult> {
  let parsed: ParseResult
  try {
    parsed = await parse(sql)
  } catch (err) {
    const detail = err instanceof Error ? err.message : String(err)
    return { ok: false, decision: deny(Violations.parseError(detail)) }
  }

  const stmts = parsed.stmts ?? []
  if (stmts.length > 1) {
    return { ok: false, decision: deny(Violations.statementStacking(stmts.length)) }
  }

  const first = stmts[0]
  const stmt: AstNode = first?.stmt ?? {}
  const type = tagOf(stmt)
  if (!type) {
    return { ok: false, decision: deny(Violations.emptyStatement()) }
  }
  if (!ALLOWED_STATEMENTS.has(type)) {
    return { ok: false, decision: deny(Violations.statementNotAllowed(type)) }
  }

  // A disallowed statement (e.g. MERGE) can hide inside a CTE body or subquery of
  // an allowed one; reject it before any permission analysis.
  const nested = nestedDisallowedStatement(stmt)
  if (nested) {
    return { ok: false, decision: deny(Violations.statementNotAllowed(nested)) }
  }

  // `SELECT ... INTO` is a table-creating statement disguised as a SELECT — and
  // it can lurk in a set-operation arm, CTE body, or subquery, so scan the tree.
  if (containsIntoClause(stmt)) {
    return { ok: false, decision: deny(Violations.statementNotAllowed('SELECT INTO')) }
  }

  return { ok: true, stmt, parsed, type }
}
