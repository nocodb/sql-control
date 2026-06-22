/**
 * Row-level security for writes (USING semantics): restrict which existing rows
 * an UPDATE or DELETE may touch by ANDing the relevant RLS predicates into the
 * statement's WHERE clause. The predicate columns are qualified to the target so
 * they remain unambiguous when the statement also has a FROM/USING clause.
 *
 * Rows touched = `rls.select` AND `rls.<op>` (both must hold). INSERT WITH CHECK
 * is handled separately in `insert-check.ts`. UPDATE WITH CHECK (the *new* row must
 * satisfy `rls.insert`, e.g. an UPDATE that moves a row to another tenant) is
 * {@link applyUpdateCheck}, below.
 */
import { parseColumnRef, parseRangeVar, walk } from '../analyzer/ast'
import { isAstNode, type AstNode, type ParseResult, type RangeVar } from '../analyzer/nodes'
import { effectiveTablePolicy, type PermissionModel, type TablePolicy } from '../policy/model'
import type { Node as PgNode } from '@pgsql/types'
import {
  andNode,
  parsePredicate,
  RewriteError,
  strField,
  substituteContext,
  view,
  type ContextValues,
} from './build'

type WriteOp = 'update' | 'delete'

/** A statement node carrying a write target and an optional WHERE clause. */
interface WriteStmt {
  relation?: RangeVar
  whereClause?: PgNode
}

interface Target {
  stmt: WriteStmt
  op: WriteOp
  binding: string
  predicates: string[]
}

/** The USING predicates that gate which rows a write may affect. */
function usingPredicates(policy: TablePolicy | undefined, op: WriteOp): string[] {
  const rls = policy?.rls
  return [rls?.select, rls?.[op]].filter((p): p is string => typeof p === 'string')
}

/**
 * Qualify the predicate's own unqualified columns with the target binding, in
 * place — but only those in the predicate's outer scope. A nested subquery is its
 * own scope: rebinding its columns to the write target would turn them into
 * correlated references and change which rows the USING filter matches (a row
 * filter that widens, not narrows). So descent stops at a `SelectStmt`, and only
 * the test expression of a `SubLink` (`x op ANY (subquery)`) — which lives in the
 * outer scope — is qualified.
 */
function qualifyColumns(expr: PgNode, binding: string): void {
  const visit = (value: unknown): void => {
    if (value === null || typeof value !== 'object') return
    if (Array.isArray(value)) {
      for (const item of value) visit(item)
      return
    }
    if (!isAstNode(value)) {
      for (const child of Object.values(value)) visit(child)
      return
    }
    const node = value
    if (node.SelectStmt) return // nested query: its own scope, leave untouched
    if (node.SubLink) {
      visit(node.SubLink.testexpr)
      return
    }
    const ref = node.ColumnRef
    if (ref?.fields?.length === 1 && !view(ref.fields[0])?.A_Star) {
      ref.fields = [strField(binding), ...ref.fields]
      return
    }
    for (const child of Object.values(node)) visit(child)
  }
  visit(expr)
}

export async function applyWriteRls(
  parsed: ParseResult,
  model: PermissionModel,
  ctx: ContextValues,
): Promise<boolean> {
  const targets: Target[] = []
  const collect = (stmt: WriteStmt | undefined, op: WriteOp): void => {
    if (!stmt?.relation) return
    const target = parseRangeVar(stmt.relation)
    if (!target) return
    const predicates = usingPredicates(effectiveTablePolicy(model, target.schema, target.relname), op)
    if (predicates.length) targets.push({ stmt, op, binding: target.binding, predicates })
  }

  walk(parsed, (node) => {
    collect(node.UpdateStmt, 'update')
    collect(node.DeleteStmt, 'delete')
  })
  if (targets.length === 0) return false

  const compiled = new Map<string, PgNode>()
  for (const target of targets) {
    for (const predicate of target.predicates) {
      if (!compiled.has(predicate)) compiled.set(predicate, await parsePredicate(predicate))
    }
  }

  let changed = false
  for (const target of targets) {
    let filter: PgNode | undefined
    for (const predicate of target.predicates) {
      const base = compiled.get(predicate)
      if (!base) continue
      const expr = substituteContext(base, ctx)
      qualifyColumns(expr, target.binding)
      filter = filter ? andNode(filter, expr) : expr
    }
    if (!filter) continue
    target.stmt.whereClause = target.stmt.whereClause
      ? andNode(target.stmt.whereClause, filter)
      : filter
    changed = true
  }
  return changed
}

/** Simple `col = expr` SET assignments; columns assigned by a multi-column
 *  assignment (`(a,b)=(...)`) yield no scalar expression and are flagged. */
function setAssignments(targetList: PgNode[] | undefined): {
  simple: Map<string, PgNode>
  complex: Set<string>
} {
  const simple = new Map<string, PgNode>()
  const complex = new Set<string>()
  for (const item of targetList ?? []) {
    const rt = view(item)?.ResTarget
    if (!rt?.name || !rt.val) continue
    if (view(rt.val)?.MultiAssignRef) complex.add(rt.name)
    else simple.set(rt.name, rt.val)
  }
  return { simple, complex }
}

/** Replace each unqualified reference to a SET column with that column's new-value
 *  expression, so the predicate is evaluated against the post-UPDATE row. The
 *  substituted expression is not re-descended (its own columns are old values,
 *  qualified afterwards by {@link qualifyColumns}). */
function substituteSetColumns(expr: PgNode, simple: ReadonlyMap<string, PgNode>): void {
  const visit = (value: unknown): void => {
    if (value === null || typeof value !== 'object') return
    if (Array.isArray(value)) {
      for (const item of value) visit(item)
      return
    }
    if (!isAstNode(value)) {
      for (const child of Object.values(value)) visit(child)
      return
    }
    const node = value
    if (node.ColumnRef) {
      const info = parseColumnRef(node.ColumnRef)
      const replacement = info.column && !info.qualifier ? simple.get(info.column) : undefined
      if (replacement) {
        delete node.ColumnRef
        Object.assign(node, structuredClone(replacement))
      }
      return
    }
    for (const child of Object.values(node)) visit(child)
  }
  visit(expr)
}

/** Unqualified column names a predicate references. */
function predicateColumns(expr: PgNode): Set<string> {
  const cols = new Set<string>()
  walk(expr, (node) => {
    if (!node.ColumnRef) return
    const info = parseColumnRef(node.ColumnRef)
    if (info.column && !info.qualifier) cols.add(info.column)
  })
  return cols
}

/**
 * UPDATE WITH CHECK (`rls.insert` semantics): the *new* row an UPDATE produces must
 * satisfy the policy, or `UPDATE t SET tenant = 999` would hand your row to another
 * tenant. The check predicate is evaluated against the post-update row by replacing
 * each referenced SET column with its assigned expression (unset columns keep their
 * old value, qualified to the target) and ANDing the result into WHERE — so a row
 * whose new value violates the policy simply matches nothing and is not updated.
 * Fails closed if a checked column is set by an inextractable multi-assignment.
 */
export async function applyUpdateCheck(
  parsed: ParseResult,
  model: PermissionModel,
  ctx: ContextValues,
): Promise<boolean> {
  interface UpdTarget {
    stmt: NonNullable<AstNode['UpdateStmt']>
    binding: string
    check: string
  }
  const targets: UpdTarget[] = []
  walk(parsed, (node) => {
    const u = node.UpdateStmt
    if (!u?.relation) return
    const target = parseRangeVar(u.relation)
    if (!target) return
    const check = effectiveTablePolicy(model, target.schema, target.relname)?.rls?.insert
    if (check) targets.push({ stmt: u, binding: target.binding, check })
  })
  if (targets.length === 0) return false

  let changed = false
  for (const { stmt, binding, check } of targets) {
    const expr = substituteContext(await parsePredicate(check), ctx)
    const { simple, complex } = setAssignments(stmt.targetList)
    for (const column of predicateColumns(expr)) {
      if (complex.has(column)) {
        throw new RewriteError(
          `cannot enforce UPDATE row policy: checked column "${column}" is set by a multi-column assignment`,
        )
      }
    }
    substituteSetColumns(expr, simple)
    qualifyColumns(expr, binding)
    stmt.whereClause = stmt.whereClause ? andNode(stmt.whereClause, expr) : expr
    changed = true
  }
  return changed
}

/**
 * RLS for `INSERT ... ON CONFLICT DO UPDATE`: the on-conflict branch updates an
 * *existing* row, so it needs the same protection as a plain UPDATE — USING
 * (`rls.select` AND `rls.update`, so a tenant can't update a colliding row it
 * cannot see) and WITH CHECK (`rls.insert`, so it can't move the row to another
 * tenant). Both are ANDed into the conflict clause's own WHERE. The inserted
 * tuple itself is handled by {@link applyInsertCheck}.
 */
export async function applyConflictRls(
  parsed: ParseResult,
  model: PermissionModel,
  ctx: ContextValues,
): Promise<boolean> {
  type Conflict = NonNullable<NonNullable<AstNode['InsertStmt']>['onConflictClause']>
  interface ConflictTarget {
    occ: Conflict
    binding: string
    using: string[]
    check: string | undefined
  }
  const targets: ConflictTarget[] = []
  walk(parsed, (node) => {
    const insert = node.InsertStmt
    const occ = insert?.onConflictClause
    if (!insert?.relation || !occ || occ.action !== 'ONCONFLICT_UPDATE') return
    const target = parseRangeVar(insert.relation)
    if (!target) return
    const policy = effectiveTablePolicy(model, target.schema, target.relname)
    const using = usingPredicates(policy, 'update')
    const check = policy?.rls?.insert
    if (using.length > 0 || check) targets.push({ occ, binding: target.binding, using, check })
  })
  if (targets.length === 0) return false

  let changed = false
  for (const { occ, binding, using, check } of targets) {
    let filter: PgNode | undefined
    const add = (expr: PgNode): void => {
      filter = filter ? andNode(filter, expr) : expr
    }
    // USING: the existing (conflicting) row must be visible to the tenant.
    for (const predicate of using) {
      const expr = substituteContext(await parsePredicate(predicate), ctx)
      qualifyColumns(expr, binding)
      add(expr)
    }
    // WITH CHECK: the post-update row must satisfy the insert policy.
    if (check) {
      const expr = substituteContext(await parsePredicate(check), ctx)
      const { simple, complex } = setAssignments(occ.targetList)
      for (const column of predicateColumns(expr)) {
        if (complex.has(column)) {
          throw new RewriteError(
            `cannot enforce ON CONFLICT row policy: checked column "${column}" is set by a multi-column assignment`,
          )
        }
      }
      substituteSetColumns(expr, simple)
      qualifyColumns(expr, binding)
      add(expr)
    }
    if (!filter) continue
    occ.whereClause = occ.whereClause ? andNode(occ.whereClause, filter) : filter
    changed = true
  }
  return changed
}
