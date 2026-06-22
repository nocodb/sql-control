/**
 * The contract between the analyzer and its callers (tests today, the wire
 * proxy later). Everything here is transport-agnostic.
 */
import type { Violation } from './errors'

/** Read-only view of the database schema, used to expand `*` and resolve columns. */
export interface Catalog {
  /**
   * Ordered column names for a base relation or view, or `undefined` if the
   * relation is unknown to the catalog.
   */
  columns(schema: string, relname: string): readonly string[] | undefined
  /** Whether the relation is a view (affects visibility/RLS semantics). */
  isView(schema: string, relname: string): boolean
  /**
   * Whether the relation has inheritance/partition children (so reading it also
   * reads them). Optional — when absent, inheritance cannot be checked.
   */
  hasChildren?(schema: string, relname: string): boolean
}

/** Per-request context: who is asking and the values their RLS predicates bind to. */
export interface RequestContext {
  /** Free-form values referenced by RLS predicates as `ctx.<key>`. */
  ctx?: Record<string, string | number | boolean | null>
}

/** The analyzer's verdict. On allow, `sql` is the (possibly rewritten) statement. */
export type Decision =
  | { allow: true; sql: string; rewritten: boolean; notes: string[] }
  | { allow: false; violations: Violation[] }

/** Build a deny decision from one or more violations. */
export function deny(...violations: Violation[]): Decision {
  return { allow: false, violations }
}

export type { Violation } from './errors'
export { ViolationCode } from './errors'
