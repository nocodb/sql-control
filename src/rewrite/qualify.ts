/**
 * Close search_path divergence (F6): the analyzer resolves an unqualified
 * relation against the model's `defaultSchema`, but if it forwards the name
 * still-unqualified the backend could resolve it to a *different* table via its
 * own `search_path` — leaking another schema's rows/columns or applying RLS to
 * the wrong table. So every unqualified base relation is rewritten to exactly the
 * schema the checker resolved it against, making name resolution authoritative
 * and independent of the backend's search_path.
 *
 * This runs unconditionally (the default `public` case is the very one the PoC
 * exploits). The schema is chosen with the *same* `isIntrospectionRelation` test
 * the checker uses — so an unqualified `pg_class` (a catalog reference) goes to
 * `pg_catalog`, while a user table `pg_foo` goes to `defaultSchema` — never a
 * name-prefix guess that could diverge from what was checked. CTE references are
 * not schema objects and already-qualified names are left untouched.
 */
import { walk } from '../analyzer/ast'
import type { ParseResult, RangeVar } from '../analyzer/nodes'
import { isIntrospectionRelation, resolveSchema, type PermissionModel } from '../policy/model'

export function qualifyRelations(
  parsed: ParseResult,
  model: PermissionModel,
  cteRefs: ReadonlySet<object>,
): boolean {
  const defaultSchema = resolveSchema(model, undefined)
  let changed = false

  // `FOR UPDATE OF <name>` must name a relation/alias from the FROM clause,
  // *unqualified* — Postgres rejects "FOR UPDATE OF public.u" ("must specify
  // unqualified relation names"). Those RangeVar nodes are left untouched.
  const lockTargets = new Set<object>()
  walk(parsed, (node) => {
    const rels = node.LockingClause?.lockedRels
    if (rels) for (const rel of rels) lockTargets.add(rel)
  })

  const qualify = (rv: RangeVar): void => {
    if (rv.schemaname || !rv.relname) return
    // Match the checker's resolution: catalog references → pg_catalog (which is
    // always implicitly first on the search_path), everything else → defaultSchema.
    rv.schemaname = isIntrospectionRelation(model, undefined, rv.relname)
      ? 'pg_catalog'
      : defaultSchema
    changed = true
  }

  walk(parsed, (node) => {
    if (node.RangeVar && !cteRefs.has(node) && !lockTargets.has(node)) qualify(node.RangeVar)
    // Write targets are bare RangeVar fields (not visited as RangeVar nodes).
    if (node.InsertStmt?.relation) qualify(node.InsertStmt.relation)
    if (node.UpdateStmt?.relation) qualify(node.UpdateStmt.relation)
    if (node.DeleteStmt?.relation) qualify(node.DeleteStmt.relation)
  })

  return changed
}
