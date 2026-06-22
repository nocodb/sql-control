/**
 * Row-level security: wrap each read relation that has an `rls.select` predicate
 * in a row-filtering subquery, with `ctx.*` placeholders resolved from the
 * request context. A relation with no predicate is left untouched.
 */
import type { RangeVarInfo } from '../analyzer/ast'
import type { ParseResult } from '../analyzer/nodes'
import { effectiveTablePolicy, type PermissionModel } from '../policy/model'
import type { Node as PgNode } from '@pgsql/types'
import { parsePredicate, substituteContext, type ContextValues } from './build'
import { wrapRelations } from './wrap'

function selectPredicate(model: PermissionModel, rel: RangeVarInfo): string | undefined {
  return effectiveTablePolicy(model, rel.schema, rel.relname)?.rls?.select
}

export async function applyRls(
  parsed: ParseResult,
  model: PermissionModel,
  ctx: ContextValues,
  cteRefs: ReadonlySet<object>,
  relations: readonly RangeVarInfo[],
): Promise<boolean> {
  // Pre-parse each distinct predicate once (parsing is async; wrapping is sync).
  const parsedPredicates = new Map<string, PgNode>()
  for (const rel of relations) {
    const predicate = selectPredicate(model, rel)
    if (predicate && !parsedPredicates.has(predicate)) {
      parsedPredicates.set(predicate, await parsePredicate(predicate))
    }
  }
  if (parsedPredicates.size === 0) return false

  return wrapRelations(parsed, cteRefs, (rel) => {
    const predicate = selectPredicate(model, rel)
    const expr = predicate ? parsedPredicates.get(predicate) : undefined
    return expr ? substituteContext(expr, ctx) : null
  })
}
