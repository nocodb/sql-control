import {
  parseColumnRef,
  parseRangeVar,
  walk,
  type ColumnRefInfo,
  type RangeVarInfo,
} from './ast'
import { isAstNode, type AstNode } from './nodes'
import type { Node as PgNode } from '@pgsql/types'

/** Columns returned by a write's `RETURNING` clause (reads of the target). */
export interface ReturningInfo {
  star: boolean
  columns: string[]
}

/** A write statement and the columns it targets. */
export interface WriteInfo {
  type: 'insert' | 'update' | 'delete'
  target?: RangeVarInfo
  columns: string[] | null
  returning?: ReturningInfo
  /** Target columns named by an `ON CONFLICT` arbiter (index columns/expressions
   *  and the partial-index predicate) — reads of the target, gated like RETURNING. */
  inferColumns?: string[]
}

export interface Collected {
  /** Base relations (tables/views) referenced in read positions. */
  relations: RangeVarInfo[]
  /** Qualifier (alias or relname) → relation, for resolving column references. */
  bindings: Map<string, RangeVarInfo>
  /** Every column reference in the statement. */
  columns: ColumnRefInfo[]
  /** Lower-cased names of every function called, schema-qualified when written so
   *  (`evil.count`); a bare name has no dot. */
  functions: string[]
  /** Operator symbols used, schema-qualified when written so (`evil.=`). */
  operators: string[]
  /** `reg*` cast target types used (`'x'::regclass`) — catalog/OID oracles. */
  regCasts: string[]
  /** RangeVar wrapper nodes that are genuine CTE references (scope-aware). */
  cteRefs: Set<object>
  /** Alias of an aliased join `(a JOIN b) x` → its component base relations, so a
   *  column addressed through the join alias (`x.col`) can be resolved/restricted. */
  joinAliases: Map<string, RangeVarInfo[]>
  /** `NATURAL JOIN` arms (their base relations). The join keys are the catalog
   *  intersection of the two sides — implicit columns with no `ColumnRef` — so the
   *  checker resolves them against the catalog to deny a forbidden silent key. */
  naturalJoins: { left: RangeVarInfo[]; right: RangeVarInfo[] }[]
  /** Aliases of derived FROM-sources (subquery / function / CTE) whose columns are
   *  validated in their own scope, so a bare whole-row reference to one is safe. */
  derivedAliases: Set<string>
  /** Output names a SELECT introduces via an explicit alias (`expr AS x`). An
   *  unqualified reference in an enclosing query may resolve to such an output of an
   *  inner/derived SELECT (validated in its own scope) rather than to a base
   *  relation buried in that SELECT's body — so the checker must not misattribute a
   *  renamed derived-source column to the base relation. */
  outputAliases: Set<string>
  /** Write statements (INSERT/UPDATE/DELETE) found anywhere, including CTEs. */
  writes: WriteInfo[]
}

/** Join a dotted name (`funcname` / operator `name`) of `String` parts into
 *  `schema.name`; a bare name has a single part. Returns undefined if empty. */
function dottedName(parts: PgNode[] | undefined): string | undefined {
  if (!parts || parts.length === 0) return undefined
  const names: string[] = []
  for (const part of parts) {
    const node: AstNode = part
    const sval = node.String?.sval
    if (sval !== undefined) names.push(sval)
  }
  return names.length ? names.join('.') : undefined
}

/**
 * The `reg*` object-identifier pseudo-types. A cast to one of these (`'x'::regclass`)
 * makes the backend resolve an arbitrary name against the catalog — an object
 * existence / OID oracle that bypasses introspection filtering and the function
 * gate (a cast is not a FuncCall and not a relation reference).
 */
export const REG_CAST_TYPES: ReadonlySet<string> = new Set([
  'regclass', 'regproc', 'regprocedure', 'regoper', 'regoperator', 'regtype',
  'regrole', 'regnamespace', 'regconfig', 'regdictionary', 'regcollation',
  'regdatabase',
])

/**
 * Whether a function name is the *function-call* spelling of a `reg*` cast and so
 * the same catalog/OID oracle as `'x'::regclass`: the bare type used as a function
 * (`regclass('pg_authid')`) or its raw I/O function (`regclassin`/`regclassout`).
 * Returns the underlying reg type, else `undefined`. Only built-in names qualify
 * (unqualified or `pg_catalog`); a user's own `myschema.regclass` is unrelated.
 */
function regOracleFunc(name: string): string | undefined {
  const dot = name.lastIndexOf('.')
  const schema = dot === -1 ? undefined : name.slice(0, dot)
  if (schema !== undefined && schema !== 'pg_catalog') return undefined
  const bare = dot === -1 ? name : name.slice(dot + 1)
  if (REG_CAST_TYPES.has(bare)) return bare
  const stem = bare.endsWith('in') ? bare.slice(0, -2)
    : bare.endsWith('out') ? bare.slice(0, -3)
    : undefined
  return stem !== undefined && REG_CAST_TYPES.has(stem) ? stem : undefined
}

/**
 * The `A_Expr` kinds whose `name` is a genuine operator that could be
 * user-defined (`a @@ b`, `a OPERATOR(s.=) b`, `a op ANY/ALL (...)`) and so must
 * be gated. All other kinds are fixed SQL syntax (`BETWEEN`, `IN`, `LIKE`,
 * `IS DISTINCT FROM`, `NULLIF`) desugared to the operand type's built-in
 * operators — they cannot smuggle a custom operator, so they are not collected.
 */
const OPERATOR_EXPR_KINDS: ReadonlySet<string> = new Set([
  'AEXPR_OP', 'AEXPR_OP_ANY', 'AEXPR_OP_ALL',
])

/**
 * Gather the base relations under an aliased join, descending only through join
 * operands (and TABLESAMPLE), so `(a JOIN b) x` maps `x` to [a, b]. Subqueries
 * and functions are opaque (their columns are checked in their own scope).
 */
function gatherJoinBases(
  item: AstNode | undefined,
  cteRefs: ReadonlySet<object>,
  lockedRels: ReadonlySet<object>,
): RangeVarInfo[] {
  const out: RangeVarInfo[] = []
  const visit = (v: AstNode | undefined): void => {
    if (!v) return
    if (v.RangeVar) {
      if (cteRefs.has(v) || lockedRels.has(v)) return
      const rv = parseRangeVar(v.RangeVar)
      if (rv) out.push(rv)
      return
    }
    if (v.JoinExpr) {
      visit(v.JoinExpr.larg)
      visit(v.JoinExpr.rarg)
      return
    }
    if (v.RangeTableSample) visit(v.RangeTableSample.relation)
  }
  visit(item)
  return out
}

/** Target columns named by an `ON CONFLICT` arbiter: index columns (`(secret)`),
 *  index expressions (`((lower(secret)))`), and the partial-index predicate
 *  (`WHERE secret > 0`). These reference the target's own columns. */
function collectInferColumns(infer: { indexElems?: PgNode[]; whereClause?: PgNode } | undefined): string[] {
  if (!infer) return []
  const out: string[] = []
  for (const elem of infer.indexElems ?? []) {
    const ie: AstNode = elem
    if (ie.IndexElem?.name) out.push(ie.IndexElem.name)
    if (ie.IndexElem?.expr) collectExprColumns(ie.IndexElem.expr, out)
  }
  if (infer.whereClause) collectExprColumns(infer.whereClause, out)
  return out
}

function resTargetNames(list: PgNode[] | undefined): string[] | null {
  if (!list) return null
  const names: string[] = []
  for (const item of list) {
    const target: AstNode = item
    const name = target.ResTarget?.name
    if (name) names.push(name)
  }
  return names
}

/** Gather every `ColumnRef` reached from a RETURNING expression, not descending
 *  into a subquery (its own scope, checked by the generic walk). */
function collectExprColumns(node: AstNode, out: string[]): void {
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
    const inner = value
    if (inner.SubLink) return // subquery: separate scope, its columns checked elsewhere
    if (inner.ColumnRef) {
      const info = parseColumnRef(inner.ColumnRef)
      if (info.column && !info.star) out.push(info.column)
      return
    }
    for (const child of Object.values(inner)) visit(child)
  }
  visit(node)
}

/**
 * Interpret a RETURNING list. `deep` (used for INSERT, which has no FROM clause so
 * every reference is the target's own column) also gathers columns nested inside
 * expressions like `secret * 2` — otherwise a forbidden column could be read back
 * through an `INSERT ... RETURNING <expr>`. UPDATE/DELETE need only the direct
 * columns here; their expression columns are resolved by the generic column pass
 * (which has the target in read scope and can attribute FROM/USING columns).
 */
function parseReturning(list: PgNode[] | undefined, deep = false): ReturningInfo | undefined {
  if (!list) return undefined
  let star = false
  const columns: string[] = []
  for (const item of list) {
    const target: AstNode = item
    const valNode: AstNode | undefined = target.ResTarget?.val
    if (!valNode) continue
    const ref = valNode.ColumnRef
    if (ref) {
      const info = parseColumnRef(ref)
      if (info.star) star = true
      else if (info.column) columns.push(info.column)
    } else if (deep) {
      collectExprColumns(valNode, columns)
    }
  }
  return { star, columns }
}

/**
 * Find every `RangeVar` node that is a genuine CTE reference, respecting scope.
 * A CTE name is visible in later CTEs of the same `WITH` and in the main query —
 * and, only for `WITH RECURSIVE`, inside its own body. An unqualified relation
 * that matches a CTE name *not* in scope (e.g. inside a non-recursive CTE's own
 * body) is the base table and is left to be permission-checked.
 */
function findCteReferences(stmt: AstNode): Set<object> {
  const refs = new Set<object>()

  const visit = (value: unknown, scope: ReadonlySet<string>): void => {
    if (value === null || typeof value !== 'object') return
    if (Array.isArray(value)) {
      for (const item of value) visit(item, scope)
      return
    }
    if (!isAstNode(value)) {
      for (const child of Object.values(value)) visit(child, scope)
      return
    }

    const node = value
    const rv = node.RangeVar
    if (rv && !rv.schemaname && rv.relname && scope.has(rv.relname)) refs.add(node)

    const stmtFields = node.SelectStmt ?? node.InsertStmt ?? node.UpdateStmt ?? node.DeleteStmt
    const ctes = stmtFields?.withClause?.ctes
    if (stmtFields && ctes && ctes.length > 0) {
      const names: string[] = []
      for (const cte of ctes) {
        const wrapper: AstNode = cte
        const name = wrapper.CommonTableExpr?.ctename
        if (name) names.push(name)
      }
      const recursive = stmtFields.withClause?.recursive === true
      ctes.forEach((cte, index) => {
        const wrapper: AstNode = cte
        const bodyScope = new Set(scope)
        if (recursive) {
          for (const name of names) bodyScope.add(name)
        } else {
          for (let j = 0; j < index; j++) {
            const earlier = names[j]
            if (earlier) bodyScope.add(earlier)
          }
        }
        visit(wrapper.CommonTableExpr?.ctequery, bodyScope)
      })

      const bodyScope = new Set(scope)
      for (const name of names) bodyScope.add(name)
      for (const [key, child] of Object.entries(stmtFields)) {
        if (key !== 'withClause') visit(child, bodyScope)
      }
      return
    }

    for (const child of Object.values(node)) visit(child, scope)
  }

  visit(stmt, new Set())
  return refs
}

/**
 * `ORDER BY <name>` and `GROUP BY <name>` resolve to a SELECT *output alias*
 * before a table column (Postgres name resolution). A bare reference to such an
 * alias is therefore not a table-column read and must not be permission-checked —
 * otherwise `SELECT expr AS a ... GROUP BY a ORDER BY a` (a routine pattern) would
 * be wrongly denied. Collect exactly those alias-referencing `ColumnRef` nodes, per
 * SELECT scope, so the column pass can skip them. Only a *bare* top-level sort/group
 * item is an alias reference; a column nested in an expression (`GROUP BY lower(x)`)
 * is a real column read and is left to be checked.
 */
function findOutputAliasRefs(stmt: AstNode): Set<object> {
  const refs = new Set<object>()
  const markIfAlias = (item: PgNode | undefined, aliases: ReadonlySet<string>): void => {
    if (!item) return
    const node: AstNode = item
    if (!node.ColumnRef) return
    const info = parseColumnRef(node.ColumnRef)
    if (info.column && !info.qualifier && aliases.has(info.column)) refs.add(item)
  }
  walk(stmt, (node) => {
    const sel = node.SelectStmt
    if (!sel) return
    const aliases = new Set<string>()
    for (const item of sel.targetList ?? []) {
      const target: AstNode = item
      if (target.ResTarget?.name) aliases.add(target.ResTarget.name)
    }
    if (aliases.size === 0) return
    for (const item of sel.sortClause ?? []) {
      const sortBy: AstNode = item
      markIfAlias(sortBy.SortBy?.node, aliases)
    }
    for (const item of sel.groupClause ?? []) markIfAlias(item, aliases)
  })
  return refs
}

/**
 * Gather everything the permission checker needs. Write targets are bare
 * RangeVars (not visited by the generic walk), so they never appear among the
 * readable `relations`; CTE references are resolved scope-aware so a CTE named
 * after a table can't launder access to it.
 */
export function collect(stmt: AstNode): Collected {
  const cteRefs = findCteReferences(stmt)
  const outputAliasRefs = findOutputAliasRefs(stmt)

  const relations: RangeVarInfo[] = []
  const bindings = new Map<string, RangeVarInfo>()
  const columns: ColumnRefInfo[] = []
  const functions: string[] = []
  const operators: string[] = []
  const regCasts: string[] = []
  // `FOR UPDATE OF x` holds a RangeVar naming an already-FROM relation.
  const lockedRels = new Set<object>()
  const joinAliases = new Map<string, RangeVarInfo[]>()
  const naturalJoins: { left: RangeVarInfo[]; right: RangeVarInfo[] }[] = []
  const derivedAliases = new Set<string>()
  const writes: WriteInfo[] = []
  const seen = new Set<string>()

  walk(stmt, (node) => {
    const locked = node.LockingClause?.lockedRels
    if (locked) for (const rel of locked) lockedRels.add(rel)
  })

  // An aliased join `(a JOIN b) x` exposes its columns only as `x.col`; the inner
  // aliases are hidden. Map the join alias to its component base relations so the
  // checker can apply column policy through it. The same pass records the implicit
  // join keys of `USING`/`NATURAL` joins, which carry no `ColumnRef` and so would
  // otherwise let a forbidden column be used as a silent join key.
  // Aliases of derived sources (subquery / set-returning function / table func /
  // CTE). A bare reference to one is a whole-row value of an already-scope-checked
  // source — not a base-relation column — so the checker must not attribute it to
  // a base relation.
  walk(stmt, (node) => {
    const alias =
      node.RangeSubselect?.alias?.aliasname ??
      node.RangeFunction?.alias?.aliasname ??
      node.RangeTableFunc?.alias?.aliasname ??
      node.CommonTableExpr?.ctename
    if (alias) derivedAliases.add(alias)
  })

  // Output aliases introduced by any SELECT (`expr AS x`). A renamed column of a
  // derived source referenced unqualified in the enclosing query resolves here, not
  // to a base relation in the source's body — without this it would be wrongly
  // denied. Safe to over-collect: a name a base relation actually has is still
  // checked (the column pass only skips when the catalog proves no base column
  // matches), so this can relax the over-block but never hide a real-column read.
  const outputAliases = new Set<string>()
  walk(stmt, (node) => {
    for (const item of node.SelectStmt?.targetList ?? []) {
      const name = (item as AstNode).ResTarget?.name
      if (name) outputAliases.add(name)
    }
  })

  walk(stmt, (node) => {
    const je = node.JoinExpr
    if (!je) return
    if (je.alias?.aliasname) joinAliases.set(je.alias.aliasname, gatherJoinBases(node, cteRefs, lockedRels))
    // `JOIN ... USING (a, b)`: each name is a column that must be readable in the
    // joined relations — record it as an ordinary unqualified column reference.
    if (je.usingClause) {
      for (const part of je.usingClause) {
        const named: AstNode = part
        const name = named.String?.sval
        if (name) columns.push({ column: name, star: false })
      }
    }
    // `a NATURAL JOIN b`: the keys are the common column names of the two sides,
    // resolved from the catalog by the checker.
    if (je.isNatural) {
      naturalJoins.push({
        left: gatherJoinBases(je.larg, cteRefs, lockedRels),
        right: gatherJoinBases(je.rarg, cteRefs, lockedRels),
      })
    }
  })

  walk(stmt, (node) => {
    if (node.RangeVar) {
      if (cteRefs.has(node) || lockedRels.has(node)) return
      const rv = parseRangeVar(node.RangeVar)
      if (!rv) return
      const key = `${rv.schema ?? ''}.${rv.relname}#${rv.binding}`
      if (!seen.has(key)) {
        seen.add(key)
        relations.push(rv)
      }
      bindings.set(rv.binding, rv)
      return
    }
    if (node.ColumnRef) {
      // A bare ORDER BY / GROUP BY reference to a SELECT output alias is not a
      // table-column read (Postgres resolves it to the alias), so skip it.
      if (!outputAliasRefs.has(node)) columns.push(parseColumnRef(node.ColumnRef))
      return
    }
    if (node.FuncCall) {
      // Keep the schema qualifier: `evil.count` is a user-defined function, not
      // the built-in `count`, and the gate must be able to tell them apart.
      const name = dottedName(node.FuncCall.funcname)
      if (name) {
        const lower = name.toLowerCase()
        // `regclass('x')` is the function-notation form of `'x'::regclass` — the
        // same name→OID oracle. The function gate would wave it through (it is not
        // a dangerous *function* name), so route it to the reg-cast check instead.
        const regType = regOracleFunc(lower)
        if (regType !== undefined) regCasts.push(regType)
        else functions.push(lower)
      }
      return
    }
    if (node.A_Expr) {
      // `OPERATOR(evil.=)` is a custom operator wearing a built-in symbol; keep
      // the qualifier so the gate does not mistake it for the built-in `=`. Only
      // genuine operator kinds can carry a user-defined operator — the keyword
      // forms (BETWEEN/IN/LIKE/ILIKE/SIMILAR/DISTINCT/NULLIF) are fixed grammar
      // that always uses the type's built-in operators, and their `name` is a
      // keyword (`BETWEEN`) the user cannot override, so gating them would
      // falsely reject ordinary queries like `x BETWEEN 1 AND 10`.
      const kind = node.A_Expr.kind
      if (kind !== undefined && OPERATOR_EXPR_KINDS.has(kind)) {
        const symbol = dottedName(node.A_Expr.name)
        if (symbol) operators.push(symbol)
      }
      return
    }
    if (node.SubLink?.operName) {
      // The operator in `x = ANY (subquery)` / `x op ALL (subquery)`.
      const symbol = dottedName(node.SubLink.operName)
      if (symbol) operators.push(symbol)
      return
    }
    if (node.SortBy?.useOp) {
      // `ORDER BY x USING <op>` chooses a sort operator that can be a custom
      // (user-defined) operator — whose oprcode is an arbitrary function — exactly
      // the bypass the operator gate exists to stop. Same surface as an operator in
      // WHERE, so collect it (built-in symbols still pass; custom/qualified denied).
      const symbol = dottedName(node.SortBy.useOp)
      if (symbol) operators.push(symbol)
    }
    if (node.TypeCast) {
      // `'name'::regclass` resolves an arbitrary catalog object; record the cast
      // type so the checker can reject it. (walk still descends into the arg.)
      const bare = dottedName(node.TypeCast.typeName?.names)?.toLowerCase().split('.').pop()
      if (bare && REG_CAST_TYPES.has(bare)) regCasts.push(bare)
    }
    if (node.InsertStmt?.relation) {
      const target = parseRangeVar(node.InsertStmt.relation)
      writes.push({
        type: 'insert',
        target,
        columns: resTargetNames(node.InsertStmt.cols),
        returning: parseReturning(node.InsertStmt.returningList, true),
        inferColumns: collectInferColumns(node.InsertStmt.onConflictClause?.infer),
      })
      const setList = node.InsertStmt.onConflictClause?.targetList
      if (setList?.length) {
        writes.push({ type: 'update', target, columns: resTargetNames(setList) ?? [] })
      }
    } else if (node.UpdateStmt?.relation) {
      writes.push({
        type: 'update',
        target: parseRangeVar(node.UpdateStmt.relation),
        columns: resTargetNames(node.UpdateStmt.targetList) ?? [],
        returning: parseReturning(node.UpdateStmt.returningList),
      })
    } else if (node.DeleteStmt?.relation) {
      writes.push({
        type: 'delete',
        target: parseRangeVar(node.DeleteStmt.relation),
        columns: [],
        returning: parseReturning(node.DeleteStmt.returningList),
      })
    }
  })

  return { relations, bindings, columns, functions, operators, regCasts, cteRefs, joinAliases, naturalJoins, derivedAliases, outputAliases, writes }
}
