import { deparse } from 'pgsql-parser'
import type { PermissionModel } from '../policy/model'
import { RewriteError } from '../rewrite/build'
import { applyInsertCheck } from '../rewrite/insert-check'
import { applyIntrospectionFilter } from '../rewrite/introspection'
import { applyRowLimit } from '../rewrite/limit'
import { applyRls } from '../rewrite/rls'
import { qualifyRelations } from '../rewrite/qualify'
import { expandStars, findUnsafeStar } from '../rewrite/star'
import { applyConflictRls, applyUpdateCheck, applyWriteRls } from '../rewrite/write-rls'
import { check } from './check'
import { collect } from './collect'
import { Violations } from './errors'
import { guard } from './guard'
import { deny, type Catalog, type Decision, type RequestContext } from './types'

export interface AnalyzeOptions {
  model: PermissionModel
  /** Schema catalog; enables expanding fully-allowed `*` into explicit columns. */
  catalog?: Catalog
  context?: RequestContext
  /** Cap the rows a SELECT may return (DoS guard); injected as a top-level LIMIT.
   *  The handler treats an over-cap result as an error rather than truncating. */
  maxRows?: number
}

/**
 * Analyze a single SQL statement against a permission model and return a
 * verdict. On allow, `sql` is the statement to forward to Postgres — rewritten
 * (e.g. `*` expanded to permitted columns) when the analyzer changed it.
 */
export async function analyze(sql: string, options: AnalyzeOptions): Promise<Decision> {
  const guarded = await guard(sql)
  if (!guarded.ok) return guarded.decision

  const collected = collect(guarded.stmt)
  const { violations, notes } = check(collected, options.model, options.catalog)
  if (violations.length) return { allow: false, violations }

  // Rewrites run only after the statement is known to be permitted, and fail
  // closed: anything that cannot be made safe denies the statement rather than
  // forward it. Order: expand `*`, then wrap rows for RLS, then filter catalogs.
  let out = sql
  let rewritten = false
  try {
    const ctx = options.context?.ctx ?? {}
    const { cteRefs, relations } = collected
    let changed = expandStars(guarded.parsed, options.model, { cteRefs, catalog: options.catalog })
    // A qualified `t.*` we couldn't expand (e.g. inside a function argument) on a
    // column-restricted relation would expand to all columns at the backend.
    const unsafeStar = findUnsafeStar(
      guarded.parsed,
      collected.bindings,
      options.model,
      collected.joinAliases,
    )
    if (unsafeStar) return deny(Violations.columnNotReadable('*', unsafeStar))
    changed = (await applyRls(guarded.parsed, options.model, ctx, cteRefs, relations)) || changed
    changed =
      (await applyIntrospectionFilter(guarded.parsed, options.model, cteRefs, relations)) || changed
    changed = (await applyWriteRls(guarded.parsed, options.model, ctx)) || changed
    // UPDATE WITH CHECK: the row's NEW values must satisfy `rls.insert` too, so an
    // UPDATE can't move a row out of the tenant's slice.
    changed = (await applyUpdateCheck(guarded.parsed, options.model, ctx)) || changed
    // ON CONFLICT DO UPDATE: the conflict branch updates an existing row, so it
    // gets the same USING + WITH CHECK protection as a plain UPDATE.
    changed = (await applyConflictRls(guarded.parsed, options.model, ctx)) || changed
    // INSERT WITH CHECK: filter the inserted rows so a new row must satisfy the
    // table's `rls.insert` predicate (cross-tenant write prevention).
    changed = (await applyInsertCheck(guarded.parsed, options.model, ctx, options.catalog)) || changed
    // Last: schema-qualify every relation (incl. those inside the wraps above) so
    // the backend's search_path can't resolve a name to a different table (F6).
    changed = qualifyRelations(guarded.parsed, options.model, cteRefs) || changed
    // Result-size guard: cap an unbounded SELECT so it can't exhaust memory.
    if (options.maxRows !== undefined) {
      changed = applyRowLimit(guarded.parsed, options.maxRows) || changed
    }
    if (changed) {
      // `pretty: false` disables the deparser's line-indentation pass, which
      // otherwise injects whitespace *inside* a quoted identifier containing a
      // newline — changing the identifier the backend resolves (the forwarded
      // statement must reference exactly the relation/column that was authorized).
      out = await deparse(guarded.parsed, { pretty: false })
      rewritten = true
    }
  } catch (err) {
    if (err instanceof RewriteError) return deny(Violations.rewriteFailed(err.message))
    throw err
  }

  return { allow: true, sql: out, rewritten, notes }
}

export type { Decision, Catalog, RequestContext } from './types'
export { ViolationCode, type Violation } from './errors'
export type { PermissionModel, TablePolicy } from '../policy/model'
