/**
 * INSERT row-level security (WITH CHECK semantics): a row inserted into a table
 * with an `rls.insert` predicate must satisfy it, or a tenant could write rows
 * stamped for another tenant (cross-tenant poisoning). The check cannot be a
 * WHERE on the target (there are no existing rows), so the inserted source is
 * wrapped in a filtering subquery:
 *
 *   INSERT INTO t (a, b) VALUES (...)        -- or SELECT ...
 *     ->  INSERT INTO t (a, b)
 *         SELECT * FROM ( <original source> ) AS _ins (a, b) WHERE <check>
 *
 * Rows that fail the check are dropped rather than inserted (fail-safe). If the
 * check references a column the INSERT does not provide (so its value would come
 * from a default we cannot see), the statement fails closed (denies) — we can't
 * prove the new row satisfies the policy.
 */
import { parse } from 'pgsql-parser'
import { parseColumnRef, parseRangeVar, walk } from '../analyzer/ast'
import type { AstNode, ParseResult } from '../analyzer/nodes'
import { effectiveTablePolicy, resolveSchema, type PermissionModel } from '../policy/model'
import type { Catalog } from '../analyzer/types'
import type { Node as PgNode } from '@pgsql/types'
import {
  parsePredicate,
  RewriteError,
  strField,
  substituteContext,
  view,
  type ContextValues,
} from './build'

let template: Promise<PgNode> | undefined

/** A canonical `SELECT * FROM (SELECT 1) AS _ins WHERE true`, cloned per use. */
async function wrapperTemplate(): Promise<PgNode> {
  template ??= parse('SELECT * FROM (SELECT 1) AS _sqlcontrol_ins WHERE true').then(
    (r: { stmts?: { stmt?: PgNode }[] }) => {
      const stmt = r.stmts?.[0]?.stmt
      if (!stmt) throw new Error('failed to parse insert-check template')
      return stmt
    },
  )
  return template
}

/** Unqualified column names referenced by a (context-substituted) predicate. */
function predicateColumns(expr: PgNode): Set<string> {
  const cols = new Set<string>()
  walk(expr, (node) => {
    if (!node.ColumnRef) return
    const info = parseColumnRef(node.ColumnRef)
    if (info.column && !info.qualifier) cols.add(info.column)
  })
  return cols
}

/** The explicit INSERT column list, or the table's catalog order when implicit. */
function insertedColumns(
  insert: NonNullable<AstNode['InsertStmt']>,
  model: PermissionModel,
  catalog: Catalog | undefined,
  schema: string | undefined,
  relname: string,
): string[] {
  if (insert.cols) {
    const names: string[] = []
    for (const item of insert.cols) {
      const target: AstNode = item
      const name = target.ResTarget?.name
      if (name) names.push(name)
    }
    return names
  }
  const cols = catalog?.columns(resolveSchema(model, schema), relname)
  if (!cols) {
    throw new RewriteError(
      `cannot enforce INSERT row policy on "${relname}": the column list is implicit and no catalog is available`,
    )
  }
  return [...cols]
}

export async function applyInsertCheck(
  parsed: ParseResult,
  model: PermissionModel,
  ctx: ContextValues,
  catalog: Catalog | undefined,
): Promise<boolean> {
  const inserts: NonNullable<AstNode['InsertStmt']>[] = []
  walk(parsed, (node) => {
    if (node.InsertStmt) inserts.push(node.InsertStmt)
  })
  if (inserts.length === 0) return false

  let changed = false
  for (const insert of inserts) {
    if (!insert.relation) continue
    const target = parseRangeVar(insert.relation)
    if (!target) continue
    const checkSql = effectiveTablePolicy(model, target.schema, target.relname)?.rls?.insert
    if (!checkSql) continue

    // `INSERT ... DEFAULT VALUES` has no source rows to filter; its values are all
    // defaults we cannot inspect, so the check can't be proven — fail closed.
    if (!insert.selectStmt) {
      throw new RewriteError(
        `cannot enforce INSERT row policy on "${target.relname}": DEFAULT VALUES provides no inspectable row`,
      )
    }

    // An explicit `DEFAULT` in the row (`VALUES (..., DEFAULT)`) is a server-side
    // value we cannot inspect — and it is also illegal inside the wrapping
    // subquery — so the policy can't be proven; fail closed rather than emit SQL
    // the backend rejects.
    let hasDefault = false
    walk(insert.selectStmt, (node) => {
      if (node.SetToDefault) hasDefault = true
    })
    if (hasDefault) {
      throw new RewriteError(
        `cannot enforce INSERT row policy on "${target.relname}": a DEFAULT value can't be checked against the policy`,
      )
    }

    const cols = insertedColumns(insert, model, catalog, target.schema, target.relname)
    const check = substituteContext(await parsePredicate(checkSql), ctx)
    for (const column of predicateColumns(check)) {
      if (!cols.includes(column)) {
        throw new RewriteError(
          `cannot enforce INSERT row policy on "${target.relname}": it references column "${column}", not in the INSERT column list`,
        )
      }
    }

    const wrapper: PgNode = structuredClone(await wrapperTemplate())
    const sel = view(wrapper)?.SelectStmt
    const sub = sel?.fromClause?.[0]
    const subView = view(sub)
    if (!sel || !subView?.RangeSubselect) {
      throw new RewriteError('insert-check template malformed')
    }
    subView.RangeSubselect.subquery = insert.selectStmt
    subView.RangeSubselect.alias = {
      aliasname: '_sqlcontrol_ins',
      colnames: cols.map((name) => strField(name)),
    }
    sel.whereClause = check
    insert.selectStmt = wrapper
    changed = true
  }
  return changed
}
