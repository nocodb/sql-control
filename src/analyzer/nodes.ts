/**
 * Typed access to the libpg_query JSON AST, backed by the parser's own generated
 * types (`@pgsql/types`). In those types every field is optional, which is the
 * honest shape of parser output — so callers narrow rather than assume. The only
 * `unknown`→typed boundary is the {@link isAstNode} type guard.
 */
import type {
  Node as PgNodeUnion,
  ParseResult,
  RangeVar,
  ColumnRef,
  A_Star,
  String as PgString,
} from '@pgsql/types'

/** `@pgsql/types` models `Node` as a union of single-key objects; fold it into one. */
type UnionToIntersection<U> = (U extends unknown ? (arg: U) => void : never) extends (
  arg: infer I,
) => void
  ? I
  : never

/** Every node type as one object: `{ RangeVar: RangeVar; ColumnRef: ColumnRef; ... }`. */
type AllNodes = UnionToIntersection<PgNodeUnion>

/**
 * A wrapper node with every node-type key made optional, e.g. `{ RangeVar?: ... }`.
 * A real node carries exactly one key; the rest narrow to `undefined`.
 */
export type AstNode = Partial<AllNodes>

/** The set of valid node-type tags (`'SelectStmt' | 'RangeVar' | ...`). */
export type NodeTag = keyof AllNodes

export type { ParseResult, RangeVar, ColumnRef, A_Star, PgString }

/**
 * The single key of a wrapper node, or `undefined` if the value is not a
 * single-key object (arrays, scalars, and multi-key records like `RawStmt` and
 * `ParseResult` are not wrapper nodes).
 */
export function tagOf(value: unknown): string | undefined {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return undefined
  }
  const keys = Object.keys(value)
  return keys.length === 1 ? keys[0] : undefined
}

/** Type guard: narrows an unknown value to a wrapper AST node. */
export function isAstNode(value: unknown): value is AstNode {
  return tagOf(value) !== undefined
}
