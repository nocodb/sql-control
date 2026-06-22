/**
 * Rewrites `SELECT *` and `t.*` to the role's permitted columns, per source
 * relation, across joins — so a wildcard never returns a column the role cannot
 * read. Expansion is only *required* for column-restricted relations (whose
 * allowed list comes straight from the model); fully-allowed relations keep
 * their `*` unless a catalog is available to make it explicit. The pass fails
 * closed: if a restricted relation cannot be expanded safely, it throws and the
 * caller denies the statement rather than forward a leaky wildcard.
 */
import { parseColumnRef, parseRangeVar, walk, type RangeVarInfo } from '../analyzer/ast'
import type { AstNode, ParseResult } from '../analyzer/nodes'
import type { Catalog } from '../analyzer/types'
import {
  effectiveTablePolicy,
  isColumnRestricted,
  resolveSchema,
  selectColumns,
  type PermissionModel,
} from '../policy/model'
import type { Node as PgNode } from '@pgsql/types'
import { RewriteError, strField, view } from './build'

export { RewriteError }

export interface ExpandOptions {
  /** RangeVar nodes that are CTE references (treated as opaque, like subqueries). */
  cteRefs: ReadonlySet<object>
  /** Optional schema catalog, used to expand fully-allowed `*` into columns. */
  catalog?: Catalog
}

/** A `ResTarget` selecting `qualifier.column`. */
function columnTarget(qualifier: string, column: string): PgNode {
  return { ResTarget: { val: { ColumnRef: { fields: [strField(qualifier), strField(column)] } } } }
}

/** A `ResTarget` selecting `qualifier.*`. */
function starTarget(qualifier: string): PgNode {
  return { ResTarget: { val: { ColumnRef: { fields: [strField(qualifier), { A_Star: {} }] } } } }
}

interface FromRelation {
  binding?: string
  base?: { schema?: string; relname: string }
}

/** Flatten a FROM clause into its in-scope relations (joins recurse; subqueries
 *  and CTE references are opaque sources we cannot expand from the catalog). */
function collectFrom(items: (PgNode | undefined)[] | undefined, cteRefs: ReadonlySet<object>): FromRelation[] {
  const out: FromRelation[] = []
  for (const item of items ?? []) {
    if (!item) continue
    const v = view(item)
    if (!v) continue
    if (v.RangeVar) {
      const rv = parseRangeVar(v.RangeVar)
      if (!rv) continue
      if (cteRefs.has(item)) out.push({ binding: rv.binding })
      else out.push({ binding: rv.binding, base: { schema: rv.schema, relname: rv.relname } })
    } else if (v.JoinExpr) {
      out.push(...collectFrom([v.JoinExpr.larg, v.JoinExpr.rarg], cteRefs))
    } else if (v.RangeTableSample) {
      // `users TABLESAMPLE ...` — the real relation is at `.relation`.
      const relNode = v.RangeTableSample.relation
      const inner = view(relNode)
      const rv = inner?.RangeVar ? parseRangeVar(inner.RangeVar) : undefined
      if (rv) {
        if (relNode && cteRefs.has(relNode)) out.push({ binding: rv.binding })
        else out.push({ binding: rv.binding, base: { schema: rv.schema, relname: rv.relname } })
      }
    } else if (v.RangeSubselect) {
      out.push({ binding: v.RangeSubselect.alias?.aliasname })
    } else if (v.RangeFunction) {
      out.push({ binding: v.RangeFunction.alias?.aliasname })
    }
  }
  return out
}

/** Allowed columns for a base relation, or `null` when it is fully allowed and
 *  should keep its `*` (no catalog to enumerate). */
function allowedColumns(
  model: PermissionModel,
  catalog: Catalog | undefined,
  base: { schema?: string; relname: string },
): readonly string[] | null {
  const policy = effectiveTablePolicy(model, base.schema, base.relname)
  const cols = policy ? selectColumns(policy) : null
  if (!cols) return null // visibility already passed; treat as keep-star
  const resolved = resolveSchema(model, base.schema)
  const catalogCols = catalog?.columns(resolved, base.relname)
  if (cols === '*') {
    return catalogCols ?? null // enumerate if known, else keep `*`
  }
  // Restricted: use the model's list, ordered by the catalog when available.
  return catalogCols ? catalogCols.filter((c) => cols.includes(c)) : cols
}

function isRestricted(model: PermissionModel, base: { schema?: string; relname: string }): boolean {
  const policy = effectiveTablePolicy(model, base.schema, base.relname)
  const cols = policy ? selectColumns(policy) : null
  return Array.isArray(cols)
}

/** Rewrite the wildcards of a single SELECT scope. Returns whether it changed. */
function rewriteSelect(select: NonNullable<AstNode['SelectStmt']>, opts: ExpandOptions, model: PermissionModel): boolean {
  const targets = select.targetList
  if (!targets || !select.fromClause) return false
  const froms = collectFrom(select.fromClause, opts.cteRefs)
  const next: PgNode[] = []
  let changed = false

  for (const target of targets) {
    const columnRef = view(view(target)?.ResTarget?.val)?.ColumnRef
    if (!columnRef) {
      next.push(target)
      continue
    }
    const info = parseColumnRef(columnRef)
    if (!info.star) {
      next.push(target)
      continue
    }

    if (info.qualifier) {
      const rel = froms.find((f) => f.binding === info.qualifier)
      const cols = rel?.base ? allowedColumns(model, opts.catalog, rel.base) : null
      if (rel?.base && cols && rel.binding) {
        for (const c of cols) next.push(columnTarget(rel.binding, c))
        changed = true
      } else {
        next.push(target) // opaque source, fully-allowed, or unknown alias
      }
      continue
    }

    // Bare `*`: only decompose when some base relation is column-restricted.
    if (!froms.some((f) => f.base && isRestricted(model, f.base))) {
      next.push(target)
      continue
    }
    for (const rel of froms) {
      if (!rel.binding) {
        throw new RewriteError('cannot expand "*" over an unaliased source alongside a restricted table')
      }
      const cols = rel.base ? allowedColumns(model, opts.catalog, rel.base) : null
      if (cols) for (const c of cols) next.push(columnTarget(rel.binding, c))
      else next.push(starTarget(rel.binding))
    }
    changed = true
  }

  if (changed) select.targetList = next
  return changed
}

/**
 * Expand wildcards throughout the statement, in place. Each SELECT scope (top
 * level, subqueries, CTE bodies, set-operation arms) is rewritten against its
 * own FROM clause. Returns whether anything changed.
 */
export function expandStars(parsed: ParseResult, model: PermissionModel, opts: ExpandOptions): boolean {
  let changed = false
  const process = (sel: NonNullable<AstNode['SelectStmt']>): void => {
    changed = rewriteSelect(sel, opts, model) || changed
    // Set-operation arms (UNION/INTERSECT/EXCEPT) are bare SelectStmt fields, not
    // wrapped nodes, so the generic walk never visits them as a SELECT scope.
    if (sel.larg) process(sel.larg)
    if (sel.rarg) process(sel.rarg)
  }
  walk(parsed, (node) => {
    if (node.SelectStmt) process(node.SelectStmt)
  })
  return changed
}

/**
 * After expansion, find a qualified `t.*` that still resolves to a
 * column-restricted relation. Top-level target stars are expanded above, so a
 * surviving one is in a position we don't expand (a function argument, a row /
 * array constructor, …) where Postgres would expand it to *all* columns — a
 * leak. Returns the offending relation name, or null. Fails closed.
 */
export function findUnsafeStar(
  parsed: ParseResult,
  bindings: ReadonlyMap<string, RangeVarInfo>,
  model: PermissionModel,
  joinAliases?: ReadonlyMap<string, readonly RangeVarInfo[]>,
): string | null {
  let found: string | null = null
  const flagIfRestricted = (rel: RangeVarInfo | undefined): void => {
    if (rel && isColumnRestricted(model, rel.schema, rel.relname)) {
      found = `${resolveSchema(model, rel.schema)}.${rel.relname}`
    }
  }
  walk(parsed, (node) => {
    if (found || !node.ColumnRef) return
    const info = parseColumnRef(node.ColumnRef)
    if (!info.star || !info.qualifier) return
    flagIfRestricted(bindings.get(info.qualifier))
    // `x.*` over an aliased join `(a JOIN b) x` is never expanded above (the
    // alias is not a base relation), so a survivor that covers a column-
    // restricted relation would leak its hidden columns at the backend.
    if (!found) (joinAliases?.get(info.qualifier) ?? []).forEach(flagIfRestricted)
  })
  return found
}
