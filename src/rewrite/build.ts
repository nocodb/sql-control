/**
 * Shared building blocks for the rewrite passes: node construction, context
 * substitution, and predicate parsing. Node construction uses the typed
 * `@pgsql/types` shapes; inspection widens to the all-optional {@link AstNode}
 * view (an assignment, never a cast).
 */
import { parse } from 'pgsql-parser'
import { parseColumnRef, walk } from '../analyzer/ast'
import type { AstNode } from '../analyzer/nodes'
import type { Node as PgNode } from '@pgsql/types'

/** Thrown when a required rewrite cannot be applied safely; the caller denies. */
export class RewriteError extends Error {}

/** Context values an RLS predicate may reference as `ctx.<key>`. */
export type ContextValues = Record<string, string | number | boolean | null>

/** Widen a typed `Node` to the inspectable all-optional-keys view (no cast). */
export function view(node: PgNode | undefined): AstNode | undefined {
  return node
}

/** A `String` field node, e.g. an identifier part of a `ColumnRef`. */
export function strField(value: string): PgNode {
  return { String: { sval: value } }
}

/** Combine two boolean expressions with `AND`. */
export function andNode(left: PgNode, right: PgNode): PgNode {
  return { BoolExpr: { boolop: 'AND_EXPR', args: [left, right] } }
}

/**
 * Build an `A_Const` literal from a JS value (injection-safe; deparse quotes it).
 * Values that cannot be represented as a safe literal fail closed (throw): a
 * non-finite number would deparse to a bare `Infinity`/`NaN` token that re-parses
 * as a *column reference* (silently corrupting an RLS predicate), and a NUL byte
 * would truncate the forwarded statement at the wire cstring.
 */
export function constNode(value: string | number | boolean | null): PgNode {
  if (value === null) return { A_Const: { isnull: true } }
  if (typeof value === 'boolean') return { A_Const: { boolval: { boolval: value } } }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) {
      throw new RewriteError(`context value is not a finite number: ${String(value)}`)
    }
    return Number.isInteger(value)
      ? { A_Const: { ival: { ival: value } } }
      : { A_Const: { fval: { fval: String(value) } } }
  }
  if (/\u0000/.test(value)) {
    throw new RewriteError('context value contains a NUL byte')
  }
  return { A_Const: { sval: { sval: value } } }
}

/**
 * Deep-clone an expression and replace every `ctx.<key>` column reference with a
 * literal from `ctx`. A missing key fails closed (throws), so a predicate is
 * never silently dropped — that would widen access.
 */
export function substituteContext(expr: PgNode, ctx: ContextValues): PgNode {
  const clone: PgNode = structuredClone(expr)
  walk(clone, (node) => {
    if (!node.ColumnRef) return
    const info = parseColumnRef(node.ColumnRef)
    if (info.qualifier !== 'ctx' || !info.column) return
    // Own-property check, NOT `in`: `'toString' in ctx` etc. are true via the
    // prototype chain, which would bypass this fail-closed guard and substitute an
    // inherited `Object.prototype` member instead of throwing on a missing key.
    if (!Object.hasOwn(ctx, info.column)) {
      throw new RewriteError(`missing context value "ctx.${info.column}"`)
    }
    delete node.ColumnRef
    Object.assign(node, constNode(ctx[info.column] ?? null))
  })
  return clone
}

/**
 * Parse a boolean predicate (raw SQL) into its expression node by parsing a
 * throwaway `SELECT 1 WHERE <predicate>`. Throws {@link RewriteError} on invalid
 * input so a misconfigured policy fails closed. The predicate is NOT wrapped in
 * parens: a malformed string like `a) OR (b` must surface as a syntax error,
 * not be silently absorbed into a tautology `(a) OR (b)`.
 */
export async function parsePredicate(predicate: string): Promise<PgNode> {
  let parsed: { stmts?: { stmt?: PgNode }[] }
  try {
    parsed = await parse(`SELECT 1 WHERE ${predicate}`)
  } catch (err) {
    const detail = err instanceof Error ? err.message : String(err)
    throw new RewriteError(`invalid predicate "${predicate}": ${detail}`)
  }
  const where = view(parsed.stmts?.[0]?.stmt)?.SelectStmt?.whereClause
  if (!where) throw new RewriteError(`predicate produced no expression: "${predicate}"`)
  return where
}
