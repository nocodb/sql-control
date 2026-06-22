/**
 * Replace a base relation with a row-filtering subquery — `users u` becomes
 * `(SELECT * FROM users WHERE <predicate>) AS u` — applied per SELECT scope. The
 * filter sits at the scan level, matching Postgres's native RLS semantics (so it
 * is correct even on the nullable side of an outer join), and references the
 * table's own columns unqualified.
 */
import { parse } from 'pgsql-parser'
import { parseRangeVar, walk, type RangeVarInfo } from '../analyzer/ast'
import type { AstNode, ParseResult } from '../analyzer/nodes'
import type { Node as PgNode } from '@pgsql/types'
import { view } from './build'

/** A predicate source: returns the filter for a relation, or null to leave it. */
export type PredicateFor = (relation: RangeVarInfo) => PgNode | null

let template: Promise<PgNode> | undefined

/**
 * A canonical `SELECT * FROM x OFFSET 0` parsed once, cloned per wrap. The
 * `OFFSET 0` is a deliberate optimization fence (per the Postgres planner): it
 * stops the row filter from being flattened into the outer query, so an outer
 * leaky/volatile qual can't be pushed *below* the RLS predicate and observe
 * unfiltered rows.
 */
async function selectStarTemplate(): Promise<PgNode> {
  template ??= parse('SELECT * FROM __sql_control_relation__ OFFSET 0').then(
    (r: { stmts?: { stmt?: PgNode }[] }) => {
      const stmt = r.stmts?.[0]?.stmt
      if (!stmt) throw new Error('failed to parse wrap template')
      return stmt
    },
  )
  return template
}

/** Clone a FROM item, removing the alias from its (possibly sampled) RangeVar so
 *  the alias can migrate to the wrapping subquery. */
function withoutAlias(fromItem: PgNode): PgNode {
  const clone: PgNode = structuredClone(fromItem)
  const v = view(clone)
  if (v?.RangeVar) {
    delete v.RangeVar.alias
  } else if (v?.RangeTableSample) {
    const inner = view(v.RangeTableSample.relation)
    if (inner?.RangeVar) delete inner.RangeVar.alias
  }
  return clone
}

/** Build `(SELECT * FROM <fromItem> WHERE <where> OFFSET 0) AS <binding>`,
 *  preserving the original FROM item (so TABLESAMPLE stays on the real table). */
function buildWrap(tmpl: PgNode, fromItem: PgNode, binding: string, where: PgNode): PgNode {
  const subquery: PgNode = structuredClone(tmpl)
  const sub = view(subquery)
  if (sub?.SelectStmt) {
    sub.SelectStmt.fromClause = [withoutAlias(fromItem)]
    sub.SelectStmt.whereClause = structuredClone(where)
  }
  return { RangeSubselect: { subquery, alias: { aliasname: binding } } }
}

interface WrapResult {
  item: PgNode
  changed: boolean
}

function wrapItem(
  item: PgNode,
  tmpl: PgNode,
  cteRefs: ReadonlySet<object>,
  predicateFor: PredicateFor,
  generated: WeakSet<object>,
): WrapResult {
  // Wrap `fromItem` (a RangeVar or a RangeTableSample) under `binding`, and mark
  // every SELECT inside the wrap so the outer walk doesn't re-process it.
  const wrap = (fromItem: PgNode, binding: string, where: PgNode): WrapResult => {
    const wrapped = buildWrap(tmpl, fromItem, binding, where)
    walk(wrapped, (node) => {
      if (node.SelectStmt) generated.add(node.SelectStmt)
    })
    return { item: wrapped, changed: true }
  }

  const v = view(item)
  if (v?.RangeVar) {
    if (cteRefs.has(item)) return { item, changed: false } // CTE reference, not a base relation
    const rv = parseRangeVar(v.RangeVar)
    if (!rv) return { item, changed: false }
    const where = predicateFor(rv)
    return where ? wrap(item, rv.binding, where) : { item, changed: false }
  }
  if (v?.RangeTableSample) {
    // `users TABLESAMPLE ...` — filter the sampled rows: keep TABLESAMPLE on the
    // real table inside the wrap (sample-then-filter, matching SampleScan + RLS).
    const relNode = v.RangeTableSample.relation
    const inner = view(relNode)
    if (!inner?.RangeVar || (relNode && cteRefs.has(relNode))) return { item, changed: false }
    const rv = parseRangeVar(inner.RangeVar)
    if (!rv) return { item, changed: false }
    const where = predicateFor(rv)
    return where ? wrap(item, rv.binding, where) : { item, changed: false }
  }
  if (v?.JoinExpr) {
    let changed = false
    if (v.JoinExpr.larg) {
      const r = wrapItem(v.JoinExpr.larg, tmpl, cteRefs, predicateFor, generated)
      v.JoinExpr.larg = r.item
      changed = changed || r.changed
    }
    if (v.JoinExpr.rarg) {
      const r = wrapItem(v.JoinExpr.rarg, tmpl, cteRefs, predicateFor, generated)
      v.JoinExpr.rarg = r.item
      changed = changed || r.changed
    }
    return { item, changed }
  }
  return { item, changed: false } // subqueries/functions are their own scopes
}

/**
 * Wrap matching relations with their predicate, across every SELECT scope.
 * Scopes produced by wrapping are not re-processed (the relation inside an
 * `(SELECT * FROM r WHERE …)` wrapper is already filtered).
 */
export async function wrapRelations(
  parsed: ParseResult,
  cteRefs: ReadonlySet<object>,
  predicateFor: PredicateFor,
): Promise<boolean> {
  const tmpl = await selectStarTemplate()
  const generated = new WeakSet<object>()
  let changed = false
  const mapClause = (items: PgNode[]): PgNode[] =>
    items.map((item) => {
      const r = wrapItem(item, tmpl, cteRefs, predicateFor, generated)
      if (r.changed) changed = true
      return r.item
    })
  // Set-operation arms (UNION/INTERSECT/EXCEPT) are bare SelectStmt fields, so the
  // generic walk never visits them as a SELECT scope — recurse through larg/rarg.
  const processSelect = (sel: NonNullable<AstNode['SelectStmt']>): void => {
    if (sel.fromClause && !generated.has(sel)) sel.fromClause = mapClause(sel.fromClause)
    if (sel.larg) processSelect(sel.larg)
    if (sel.rarg) processSelect(sel.rarg)
  }
  walk(parsed, (node) => {
    // SELECT FROM, and also the read relations of UPDATE ... FROM and
    // DELETE ... USING (otherwise their rows skip RLS — a cross-relation leak).
    if (node.SelectStmt) processSelect(node.SelectStmt)
    if (node.UpdateStmt?.fromClause) {
      node.UpdateStmt.fromClause = mapClause(node.UpdateStmt.fromClause)
    }
    if (node.DeleteStmt?.usingClause) {
      node.DeleteStmt.usingClause = mapClause(node.DeleteStmt.usingClause)
    }
  })
  return changed
}
