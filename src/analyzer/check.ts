import { functionAllowed, operatorAllowed } from '../policy/functions'
import {
  columnAllowed,
  effectiveTablePolicy,
  insertColumns,
  isColumnRestricted,
  isIntrospectionRelation,
  resolveSchema,
  schemaAccessible,
  selectColumns,
  updateColumns,
  type ColumnSet,
  type PermissionModel,
} from '../policy/model'
import {
  catalogKey,
  FILTERABLE_CATALOGS,
  isSensitiveSystemRelation,
} from '../policy/system-catalogs'
import type { RangeVarInfo } from './ast'
import type { Collected, ReturningInfo, WriteInfo } from './collect'
import { Violations, type Violation } from './errors'
import type { Catalog } from './types'

export interface CheckResult {
  violations: Violation[]
  notes: string[]
  /** Introspection relations read; the rewriter filters their rows. */
  introspectionRelations: RangeVarInfo[]
}

/**
 * Apply the permission model to what the collector found: function calls,
 * write permissions (incl. RETURNING), relation visibility (with deny-most
 * system catalogs), and column readability (catalog-resolved, fail-closed).
 */
export function check(
  collected: Collected,
  model: PermissionModel,
  catalog?: Catalog,
): CheckResult {
  const violations: Violation[] = []
  const notes: string[] = []
  const introspectionRelations: RangeVarInfo[] = []
  const result = (): CheckResult => ({ violations, notes, introspectionRelations })

  // Functions and operators — block dangerous / out-of-policy calls (a bypass
  // surface; a custom operator can wrap a dangerous function).
  for (const fn of collected.functions) {
    if (!functionAllowed(model.functions, fn)) violations.push(Violations.functionNotAllowed(fn))
  }
  for (const op of collected.operators) {
    if (!operatorAllowed(model.functions, op)) violations.push(Violations.operatorNotAllowed(op))
  }
  // A `reg*` cast (`'pg_authid'::regclass`) resolves any catalog object by name —
  // an existence/OID oracle that sidesteps introspection filtering — so reject it.
  for (const type of collected.regCasts) violations.push(Violations.typeCastNotAllowed(type))

  // Write permissions (INSERT/UPDATE/DELETE, ON CONFLICT, RETURNING).
  for (const write of collected.writes) checkWrite(write, model, catalog, violations)
  if (violations.length) return result()

  // Relation visibility, with deny-most introspection.
  const introspectionBindings = new Set<string>()
  const allowUnfiltered = new Set(model.introspection?.allowUnfiltered ?? [])
  for (const rel of collected.relations) {
    if (isIntrospectionRelation(model, rel.schema, rel.relname)) {
      const key = catalogKey(rel.schema, rel.relname)
      if (isSensitiveSystemRelation(rel.relname)) {
        violations.push(Violations.systemCatalogBlocked(key))
      } else if (
        FILTERABLE_CATALOGS.has(key) ||
        allowUnfiltered.has(key) ||
        allowUnfiltered.has(rel.relname)
      ) {
        introspectionRelations.push(rel)
        introspectionBindings.add(rel.binding)
      } else {
        violations.push(Violations.introspectionNotAllowed(key))
      }
      continue
    }
    const schema = resolveSchema(model, rel.schema)
    if (!schemaAccessible(model, schema)) {
      violations.push(Violations.schemaNotVisible(schema))
      continue
    }
    const policy = effectiveTablePolicy(model, rel.schema, rel.relname)
    if (!policy || selectColumns(policy) === null) {
      violations.push(Violations.relationNotVisible(`${schema}.${rel.relname}`))
    } else if (
      rel.includeChildren &&
      !policy.allowInherited &&
      catalog !== undefined &&
      catalog.hasChildren?.(schema, rel.relname) !== false
    ) {
      // Reading a parent (not `ONLY`) also reads its inheritance/partition
      // children. With a catalog present it must be *proven* childless
      // (`hasChildren === false`); a catalog that can't answer (no `hasChildren`)
      // leaves it unproven, so fail closed rather than risk reading a child's rows.
      // (Without any catalog the analyzer is in degraded mode — `*` can't expand
      // either — and inheritance can't be checked; supply a catalog in production.)
      // Opt a known parent in with `allowInherited`.
      violations.push(Violations.inheritedRelationBlocked(`${schema}.${rel.relname}`))
    }
  }
  if (violations.length) return result()

  if (introspectionRelations.length) {
    notes.push('introspection relations present; rows are filtered to permitted objects by the rewriter')
  }

  // Column readability. An UPDATE/DELETE also *reads* its target (its WHERE,
  // value expressions, and RETURNING reference the target's columns), so the
  // target is resolved as a readable relation here — otherwise a forbidden
  // column could be probed via `UPDATE ... WHERE secret = ?` (a blind channel).
  const readTargets = collected.writes
    .filter((w) => w.type !== 'insert')
    .map((w) => w.target)
    .filter((t): t is RangeVarInfo => t !== undefined)
  const bindings = new Map(collected.bindings)
  for (const target of readTargets) {
    if (!bindings.has(target.binding)) bindings.set(target.binding, target)
  }
  const baseRelations = [
    ...collected.relations.filter((r) => !introspectionBindings.has(r.binding)),
    ...readTargets,
  ]
  const onlyRelation = baseRelations.length === 1 ? baseRelations[0] : undefined

  for (const col of collected.columns) {
    if (col.star) {
      notes.push('wildcard present; expansion to permitted columns is handled by the rewriter')
      continue
    }
    if (!col.column) continue

    // A bare name that names either a derived-source alias (a whole-row reference,
    // e.g. `SELECT c FROM ... c`) or a derived SELECT's output alias (a *renamed*
    // column, e.g. `WITH c AS (SELECT id AS pw ...) SELECT pw FROM c`) resolves in
    // that source's own scope, where its columns were already validated — so it is
    // not a base-relation read. Postgres resolves a real column before such a name,
    // so only skip when the name is NOT also a real column of a base relation
    // (catalog-checked; without a catalog, a column-restricted relation in scope
    // means we can't rule out a collision, so fall through and fail closed).
    if (!col.qualifier && (collected.derivedAliases.has(col.column) || collected.outputAliases.has(col.column))) {
      const column = col.column
      const baseHasColumn = catalog
        ? baseRelations.some((r) => catalog.columns(resolveSchema(model, r.schema), r.relname)?.includes(column))
        : baseRelations.some((r) => isColumnRestricted(model, r.schema, r.relname))
      if (!baseHasColumn) continue
    }

    const rel = col.qualifier ? bindings.get(col.qualifier) : onlyRelation
    if (rel && introspectionBindings.has(rel.binding)) continue
    if (rel) {
      checkReadable(model, rel, col.column, violations)
      continue
    }
    if (col.qualifier) {
      // A column addressed through an aliased join `(a JOIN b) x` (`x.col`) is
      // resolved against the join's component relations, catalog-aware and fail-
      // closed — otherwise the join alias would launder a forbidden column. A
      // qualifier that is neither a base relation nor a join alias names a
      // subquery/CTE output, already checked in its own scope.
      const components = collected.joinAliases.get(col.qualifier)
      if (components?.length) {
        const violation = resolveUnqualified(model, catalog, components, col.column)
        if (violation) violations.push(violation)
      }
      continue
    }
    // Unqualified column with multiple sources: resolve via the catalog, and
    // fail closed if a restricted relation is in scope and we cannot prove it
    // safe — otherwise an ambiguous join would slip a forbidden column through.
    const violation = resolveUnqualified(model, catalog, baseRelations, col.column)
    if (violation) violations.push(violation)
  }

  // NATURAL JOIN keys are the catalog intersection of the two arms — implicit
  // columns the loop above never saw (they carry no `ColumnRef`). Gate them so a
  // forbidden column can't be a silent join key (a blind inference channel).
  for (const nj of collected.naturalJoins) checkNaturalJoin(nj, model, catalog, violations)

  return result()
}

function checkNaturalJoin(
  nj: { left: RangeVarInfo[]; right: RangeVarInfo[] },
  model: PermissionModel,
  catalog: Catalog | undefined,
  violations: Violation[],
): void {
  const arms = [...nj.left, ...nj.right]
  if (!catalog) {
    // Without a catalog the common columns are unknown; if either side is
    // column-restricted, a forbidden column could be the join key — fail closed.
    const restricted = arms.find((r) => isColumnRestricted(model, r.schema, r.relname))
    if (restricted) {
      violations.push(Violations.columnNotReadable('(natural join key)', relName(model, restricted)))
    }
    return
  }
  const leftCols = new Set<string>()
  for (const r of nj.left) {
    for (const c of catalog.columns(resolveSchema(model, r.schema), r.relname) ?? []) leftCols.add(c)
  }
  const common = new Set<string>()
  for (const r of nj.right) {
    for (const c of catalog.columns(resolveSchema(model, r.schema), r.relname) ?? []) {
      if (leftCols.has(c)) common.add(c)
    }
  }
  for (const column of common) {
    const violation = resolveUnqualified(model, catalog, arms, column)
    if (violation) violations.push(violation)
  }
}

function relName(model: PermissionModel, rel: RangeVarInfo): string {
  return `${resolveSchema(model, rel.schema)}.${rel.relname}`
}

function readableColumns(model: PermissionModel, rel: RangeVarInfo): ColumnSet | null {
  const policy = effectiveTablePolicy(model, rel.schema, rel.relname)
  return policy ? selectColumns(policy) : null
}

function checkReadable(
  model: PermissionModel,
  rel: RangeVarInfo,
  column: string,
  violations: Violation[],
): void {
  const cols = readableColumns(model, rel)
  if (!cols || !columnAllowed(cols, column)) {
    violations.push(Violations.columnNotReadable(column, relName(model, rel)))
  }
}

function resolveUnqualified(
  model: PermissionModel,
  catalog: Catalog | undefined,
  baseRelations: readonly RangeVarInfo[],
  column: string,
): Violation | null {
  if (catalog) {
    const sources = baseRelations.filter((r) =>
      catalog.columns(resolveSchema(model, r.schema), r.relname)?.includes(column),
    )
    if (sources.length > 0) {
      for (const source of sources) {
        const cols = readableColumns(model, source)
        if (!cols || !columnAllowed(cols, column)) {
          return Violations.columnNotReadable(column, relName(model, source))
        }
      }
      return null
    }
  }
  const restricted = baseRelations.find((r) => isColumnRestricted(model, r.schema, r.relname))
  return restricted ? Violations.columnNotReadable(column, relName(model, restricted)) : null
}

/** Enforce INSERT/UPDATE/DELETE permission, column writes, and RETURNING reads. */
function checkWrite(
  write: WriteInfo,
  model: PermissionModel,
  catalog: Catalog | undefined,
  violations: Violation[],
): void {
  const target = write.target
  if (!target) return
  const schema = resolveSchema(model, target.schema)
  const full = `${schema}.${target.relname}`
  if (!schemaAccessible(model, schema)) {
    violations.push(Violations.schemaNotVisible(schema))
    return
  }
  const policy = effectiveTablePolicy(model, target.schema, target.relname)

  // Writing a parent also writes its children (unless `ONLY` was used). As with
  // reads, a catalog present must *prove* childlessness (`hasChildren === false`);
  // if it can't, fail closed rather than risk writing a child's rows.
  if (
    target.includeChildren &&
    !policy?.allowInherited &&
    catalog !== undefined &&
    catalog.hasChildren?.(schema, target.relname) !== false
  ) {
    violations.push(Violations.inheritedRelationBlocked(full))
  }

  if (write.type === 'delete') {
    if (!policy?.delete) violations.push(Violations.deleteNotAllowed(full))
  } else {
    const cols = policy
      ? write.type === 'insert'
        ? insertColumns(policy)
        : updateColumns(policy)
      : null
    if (!cols) {
      violations.push(
        write.type === 'insert' ? Violations.insertNotAllowed(full) : Violations.updateNotAllowed(full),
      )
    } else {
      checkWriteColumns(write.columns, cols, full, violations)
    }
  }

  if (write.returning) checkReturning(write.returning, target, model, violations)

  // An ON CONFLICT arbiter reads the target's columns (to find a unique index /
  // evaluate a partial-index predicate); gate them by the target's select policy
  // so a forbidden column can't be used as a blind conflict-existence oracle.
  if (write.inferColumns?.length) {
    const cols = readableColumns(model, target)
    for (const column of write.inferColumns) {
      if (!cols || !columnAllowed(cols, column)) {
        violations.push(Violations.columnNotReadable(column, full))
      }
    }
  }
}

/** RETURNING reads from the target — gated by its select policy. */
function checkReturning(
  returning: ReturningInfo,
  target: RangeVarInfo,
  model: PermissionModel,
  violations: Violation[],
): void {
  const full = relName(model, target)
  const cols = readableColumns(model, target)
  if (returning.star && cols !== '*') {
    violations.push(Violations.columnNotReadable('*', full))
  }
  for (const column of returning.columns) {
    if (!cols || !columnAllowed(cols, column)) {
      violations.push(Violations.columnNotReadable(column, full))
    }
  }
}

function checkWriteColumns(
  columns: string[] | null,
  allowed: ColumnSet,
  relation: string,
  violations: Violation[],
): void {
  // An implicit column list (INSERT ... VALUES with no columns) targets every
  // column, so it is only safe when all columns are writable.
  if (columns === null) {
    if (allowed !== '*') violations.push(Violations.columnNotWritable('*', relation))
    return
  }
  for (const column of columns) {
    if (!columnAllowed(allowed, column)) {
      violations.push(Violations.columnNotWritable(column, relation))
    }
  }
}
