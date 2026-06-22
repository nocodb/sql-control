/**
 * Traversal and small interpreters over the typed AST. The generic walker
 * reaches every node (subqueries, CTEs, joins) so nothing hides from analysis.
 */
import { isAstNode, type AstNode, type ColumnRef, type RangeVar } from './nodes'

/**
 * Depth-first walk over every wrapper node in the tree. The visitor receives the
 * typed node; narrow it via its single key (`node.RangeVar`, `node.ColumnRef`,
 * …), each typed as `T | undefined`.
 */
export function walk(value: unknown, visit: (node: AstNode) => void): void {
  if (value === null || typeof value !== 'object') return
  if (Array.isArray(value)) {
    for (const item of value) walk(item, visit)
    return
  }
  if (isAstNode(value)) visit(value)
  for (const child of Object.values(value)) walk(child, visit)
}

/** A parsed `ColumnRef`, split into its optional qualifier and target. */
export interface ColumnRefInfo {
  /** Qualifier as written (table name or alias), if any. */
  qualifier?: string
  /** Column name, or undefined when the reference is a `*` wildcard. */
  column?: string
  /** True for `*` or `qualifier.*`. */
  star: boolean
}

/** Interpret a `ColumnRef`'s dotted field path. */
export function parseColumnRef(ref: ColumnRef): ColumnRefInfo {
  const parts: AstNode[] = ref.fields ?? []
  const names: string[] = []
  let star = false
  for (const part of parts) {
    if (part.A_Star) star = true
    else if (part.String?.sval !== undefined) names.push(part.String.sval)
  }
  if (star) {
    return { qualifier: names.at(-1), star: true }
  }
  // Last name is the column; the one before it (if present) is the qualifier.
  return {
    qualifier: names.length >= 2 ? names.at(-2) : undefined,
    column: names.at(-1),
    star: false,
  }
}

/** A relation reference (`RangeVar`): a base table or view named in FROM/JOIN/etc. */
export interface RangeVarInfo {
  schema?: string
  relname: string
  /** Alias if present, else the relation name (how columns qualify against it). */
  binding: string
  /** Whether inheritance/partition children are included (false for `ONLY`). */
  includeChildren: boolean
}

/** Interpret a `RangeVar`; returns undefined if it has no relation name. */
export function parseRangeVar(rv: RangeVar): RangeVarInfo | undefined {
  if (!rv.relname) return undefined
  const binding = rv.alias?.aliasname ?? rv.relname
  return {
    schema: rv.schemaname ?? undefined,
    relname: rv.relname,
    binding,
    includeChildren: rv.inh === true,
  }
}
