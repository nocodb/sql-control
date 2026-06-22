/**
 * The permission model: a default-deny description of what a given role may do.
 *
 * Keys for `tables` are normalized relation names, "<schema>.<relname>" (the
 * schema defaults to `defaultSchema` for unqualified names). A relation that is
 * absent from `tables` is invisible: any reference to it is rejected.
 */

import type { FunctionPolicy } from './functions'

/** `'*'` means every column; otherwise an explicit allow-list of column names. */
export type ColumnSet = '*' | readonly string[]

export interface TablePolicy {
  /**
   * Read access. `true` is shorthand for `{ columns: '*' }`. Absent/false means
   * the relation may not appear in any read position (FROM / JOIN / subquery).
   */
  select?: boolean | { columns: ColumnSet }
  /** INSERT access, optionally restricted to a set of insertable columns. */
  insert?: boolean | { columns: ColumnSet }
  /** UPDATE access, optionally restricted to a set of updatable columns. */
  update?: boolean | { columns: ColumnSet }
  /** DELETE access for whole records. */
  delete?: boolean
  /**
   * Permit reading this relation even though it has inheritance/partition
   * children (reading a parent also reads its children). Off by default.
   */
  allowInherited?: boolean
  /**
   * Row-level security predicates, given as raw SQL boolean expressions in terms
   * of the table's columns (and `ctx.*` placeholders, resolved at rewrite time).
   * Injected into the query so the role only ever sees/affects matching rows.
   */
  rls?: {
    /** Filter applied to reads (and the read side of UPDATE/DELETE). */
    select?: string
    /** Extra filter restricting which existing rows UPDATE may touch. */
    update?: string
    /** Extra filter restricting which existing rows DELETE may remove. */
    delete?: string
    /** WITH CHECK expression new/updated rows must satisfy. */
    insert?: string
  }
}

/** Policy for a whole schema — a coarse gate above the per-table policy. */
export interface SchemaPolicy {
  /**
   * Default policy for every table/view in the schema, applied when a relation
   * has no explicit entry in `tables`. Set e.g. `{ select: true }` to expose the
   * entire schema; omit to require each table to be listed explicitly.
   */
  defaultTablePolicy?: TablePolicy
}

export interface PermissionModel {
  /** Schema assumed for unqualified relation names. Defaults to `public`. */
  defaultSchema?: string
  /**
   * Schemas the role may access. When present, this is a hard gate: a relation
   * whose schema is not listed is invisible regardless of any `tables` entry.
   * When omitted, schema gating is off and access is governed solely by `tables`.
   */
  schemas?: Record<string, SchemaPolicy>
  /** Per-relation policy. Overrides a schema's `defaultTablePolicy`. */
  tables: Record<string, TablePolicy>
  /** Read-only introspection of system catalogs (off unless enabled). */
  introspection?: IntrospectionPolicy
  /** Which functions a statement may call. Defaults to blocking dangerous ones. */
  functions?: FunctionPolicy
}

/**
 * Lets clients read system catalogs (`information_schema`, `pg_catalog`) so ORMs
 * and tools can introspect — but the rewriter filters the *rows* down to objects
 * the role can otherwise access, so hidden tables/columns never leak.
 */
export interface IntrospectionPolicy {
  enabled: boolean
  /** Introspection schemas. Defaults to `information_schema` + `pg_catalog`. */
  schemas?: readonly string[]
  /**
   * Catalog relations (by `"schema.relname"` or bare relname) to permit
   * *unfiltered*, opting into the leak. By default only relations the rewriter
   * can row-filter are allowed; everything else is denied (deny-most).
   */
  allowUnfiltered?: readonly string[]
}

const DEFAULT_INTROSPECTION_SCHEMAS = ['information_schema', 'pg_catalog'] as const

/** Normalize a (schema, relname) pair to the `tables` key form. */
export function relKey(schema: string, relname: string): string {
  return `${schema}.${relname}`
}

/** Resolve the effective schema for a possibly-unqualified relation. */
export function resolveSchema(
  model: PermissionModel,
  schema: string | undefined,
): string {
  return schema ?? model.defaultSchema ?? 'public'
}

/**
 * Whether the role may access a schema. With gating off (`schemas` omitted),
 * every schema is accessible and only `tables` governs access.
 *
 * Uses `Object.hasOwn`, NOT the `in` operator: a relation name comes from
 * attacker-controlled SQL, and `in` walks the prototype chain, so `'constructor'
 * in {}` / `'toString' in {}` are `true` — a schema named after an `Object.prototype`
 * member would otherwise test as accessible without an explicit grant.
 */
export function schemaAccessible(model: PermissionModel, schema: string): boolean {
  return model.schemas === undefined || Object.hasOwn(model.schemas, schema)
}

/** A schema's policy via an OWN-property lookup only (never an inherited
 *  `Object.prototype` member — see {@link schemaAccessible}). */
function ownSchemaPolicy(
  model: PermissionModel,
  schema: string,
): SchemaPolicy | undefined {
  return model.schemas !== undefined && Object.hasOwn(model.schemas, schema)
    ? model.schemas[schema]
    : undefined
}

/**
 * The effective policy for a relation: its explicit `tables` entry if present,
 * otherwise the `defaultTablePolicy` of its schema. Schema accessibility is a
 * separate, prior check — see {@link schemaAccessible}.
 */
export function effectiveTablePolicy(
  model: PermissionModel,
  schema: string | undefined,
  relname: string,
): TablePolicy | undefined {
  const resolved = resolveSchema(model, schema)
  const key = relKey(resolved, relname)
  // OWN-property lookups only: an attacker-named relation/schema must not resolve
  // to an inherited `Object.prototype` member (`constructor`, `toString`, …).
  const explicit = Object.hasOwn(model.tables, key) ? model.tables[key] : undefined
  return explicit ?? ownSchemaPolicy(model, resolved)?.defaultTablePolicy
}

/**
 * Postgres system columns: implicit on every table, never produced by a `*`
 * expansion, and a side channel if exposed — `xmin`/`xmax` enumerate write
 * transactions, `tableoid` discloses the originating partition, `ctid` the
 * physical row location. A `*` grant (`select: true`) therefore must NOT cover
 * them; they require an explicit column listing (matching "only explicit allows").
 */
const SYSTEM_COLUMNS: ReadonlySet<string> = new Set([
  'ctid', 'xmin', 'xmax', 'cmin', 'cmax', 'tableoid',
])

/** Does a column set permit a given column? */
export function columnAllowed(set: ColumnSet, column: string): boolean {
  if (SYSTEM_COLUMNS.has(column.toLowerCase())) {
    // Implicit system columns are excluded from the `*` wildcard; only an
    // explicit by-name grant exposes them.
    return set !== '*' && set.includes(column)
  }
  return set === '*' || set.includes(column)
}

/** Extract the readable column set from a select policy (false → none). */
export function selectColumns(policy: TablePolicy): ColumnSet | null {
  if (policy.select === undefined || policy.select === false) return null
  if (policy.select === true) return '*'
  return policy.select.columns
}

/** Whether a relation's readable columns are an explicit list (not all columns). */
export function isColumnRestricted(
  model: PermissionModel,
  schema: string | undefined,
  relname: string,
): boolean {
  const policy = effectiveTablePolicy(model, schema, relname)
  const cols = policy ? selectColumns(policy) : null
  return Array.isArray(cols)
}

/** Whether a relation is readable: its schema is accessible and it has a select policy. */
export function isRelationVisible(
  model: PermissionModel,
  schema: string,
  relname: string,
): boolean {
  if (!schemaAccessible(model, schema)) return false
  const policy = effectiveTablePolicy(model, schema, relname)
  return policy ? selectColumns(policy) !== null : false
}

/** Insertable column set, or null when INSERT is not permitted. */
export function insertColumns(policy: TablePolicy): ColumnSet | null {
  if (policy.insert === undefined || policy.insert === false) return null
  if (policy.insert === true) return '*'
  return policy.insert.columns
}

/** Updatable column set, or null when UPDATE is not permitted. */
export function updateColumns(policy: TablePolicy): ColumnSet | null {
  if (policy.update === undefined || policy.update === false) return null
  if (policy.update === true) return '*'
  return policy.update.columns
}

/** The set of enabled introspection schemas (empty when disabled). */
export function introspectionSchemas(model: PermissionModel): ReadonlySet<string> {
  if (!model.introspection?.enabled) return new Set()
  return new Set(model.introspection.schemas ?? DEFAULT_INTROSPECTION_SCHEMAS)
}

/**
 * Whether a relation is a readable system catalog. Matches an explicit
 * introspection schema, and treats unqualified `pg_*` names as `pg_catalog`
 * (which is implicitly on the search_path) when that schema is enabled.
 */
export function isIntrospectionRelation(
  model: PermissionModel,
  schema: string | undefined,
  relname: string,
): boolean {
  const schemas = introspectionSchemas(model)
  if (schema) return schemas.has(schema)
  if (relname.startsWith('pg_') && schemas.has('pg_catalog')) {
    // An explicit user-table grant for `<defaultSchema>.pg_foo` wins over the
    // name-prefix guess — otherwise a granted, column-restricted user table whose
    // name happens to start with `pg_` would be silently redirected to the system
    // catalog (dropping its restrictions) or wrongly denied. (Own-property check so
    // a `pg_`-named relation can't resolve to an inherited prototype member.)
    return !Object.hasOwn(model.tables, relKey(resolveSchema(model, undefined), relname))
  }
  return false
}
