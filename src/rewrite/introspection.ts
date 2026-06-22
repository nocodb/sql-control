/**
 * Introspection row-filter: when a client reads `information_schema` or
 * `pg_catalog`, restrict the rows to objects the role can otherwise access, so BI
 * tools and drivers only ever browse permitted schemas, tables, and columns. Each
 * supported catalog relation maps to a model-derived boolean predicate that is
 * injected via the same subquery wrap used for RLS.
 *
 * Covered: object-level `information_schema` views, per-column hiding in
 * `information_schema.columns`/`column_privileges`, and the `pg_catalog`
 * object-enumeration catalogs `pg_namespace` and `pg_class`. Other `pg_catalog`
 * tables (e.g. `pg_attribute`) are not yet filtered.
 */
import type { RangeVarInfo } from '../analyzer/ast'
import type { ParseResult } from '../analyzer/nodes'
import {
  isIntrospectionRelation,
  selectColumns,
  type ColumnSet,
  type PermissionModel,
} from '../policy/model'
import { catalogKey } from '../policy/system-catalogs'
import type { Node as PgNode } from '@pgsql/types'
import { parsePredicate } from './build'
import { wrapRelations } from './wrap'

interface TableGrant {
  schema: string
  table: string
  cols: ColumnSet
}
interface SchemaGrant {
  schema: string
  cols: ColumnSet
}

function quote(value: string): string {
  return `'${value.replace(/'/g, "''")}'`
}
function inList(values: readonly string[]): string {
  return values.map(quote).join(', ')
}

/** Schemas exposed via a `defaultTablePolicy` that grants select. */
function schemaGrants(model: PermissionModel): SchemaGrant[] {
  const out: SchemaGrant[] = []
  for (const [schema, policy] of Object.entries(model.schemas ?? {})) {
    const cols = policy.defaultTablePolicy ? selectColumns(policy.defaultTablePolicy) : null
    if (cols !== null) out.push({ schema, cols })
  }
  return out
}

function splitKey(key: string): { schema: string; table: string } {
  const dot = key.indexOf('.')
  return { schema: key.slice(0, dot), table: key.slice(dot + 1) }
}

/** Explicit `tables` entries that grant select, with their column set. */
function tableGrants(model: PermissionModel): TableGrant[] {
  const out: TableGrant[] = []
  for (const [key, policy] of Object.entries(model.tables)) {
    const cols = selectColumns(policy)
    if (cols !== null) out.push({ ...splitKey(key), cols })
  }
  return out
}

/** Explicit `tables` entries that revoke select. */
function deniedTables(model: PermissionModel): { schema: string; table: string }[] {
  return Object.entries(model.tables)
    .filter(([, policy]) => selectColumns(policy) === null)
    .map(([key]) => splitKey(key))
}

function tupleEq(schemaCol: string, tableCol: string, g: { schema: string; table: string }): string {
  return `(${schemaCol} = ${quote(g.schema)} AND ${tableCol} = ${quote(g.table)})`
}

/** Object visibility over (schema, table) identifying columns. */
function tableVisibility(model: PermissionModel, schemaCol: string, tableCol: string): string {
  const schemas = schemaGrants(model).map((g) => g.schema)
  const grants = tableGrants(model)
  const denied = deniedTables(model)

  const positives: string[] = []
  if (schemas.length) positives.push(`${schemaCol} IN (${inList(schemas)})`)
  for (const g of grants) positives.push(tupleEq(schemaCol, tableCol, g))
  const positive = positives.length ? `(${positives.join(' OR ')})` : 'false'

  if (denied.length === 0) return positive
  const negative = denied.map((d) => tupleEq(schemaCol, tableCol, d)).join(' OR ')
  return `${positive} AND NOT (${negative})`
}

/** Schema visibility over a single schema-name column. */
function schemaVisibility(model: PermissionModel, schemaCol: string): string {
  const schemas = new Set(schemaGrants(model).map((g) => g.schema))
  for (const g of tableGrants(model)) schemas.add(g.schema)
  if (schemas.size === 0) return 'false'
  return `${schemaCol} IN (${inList([...schemas])})`
}

/** Column visibility over (schema, table, column): a column is shown only if its
 *  table is visible and the column itself is readable. */
function columnVisibility(
  model: PermissionModel,
  schemaCol: string,
  tableCol: string,
  columnCol: string,
): string {
  const clauses: string[] = []

  for (const g of tableGrants(model)) {
    const head = `${schemaCol} = ${quote(g.schema)} AND ${tableCol} = ${quote(g.table)}`
    clauses.push(g.cols === '*' ? `(${head})` : `(${head} AND ${columnCol} IN (${inList(g.cols)}))`)
  }

  for (const sg of schemaGrants(model)) {
    // Explicit entries in this schema (grants and denials) are handled above /
    // excluded, since an explicit table policy overrides the schema default.
    const explicit = [
      ...tableGrants(model).filter((g) => g.schema === sg.schema).map((g) => g.table),
      ...deniedTables(model).filter((d) => d.schema === sg.schema).map((d) => d.table),
    ]
    const except = explicit.length ? ` AND ${tableCol} NOT IN (${inList(explicit)})` : ''
    const head = `${schemaCol} = ${quote(sg.schema)}`
    clauses.push(
      sg.cols === '*'
        ? `(${head}${except})`
        : `(${head} AND ${columnCol} IN (${inList(sg.cols)})${except})`,
    )
  }

  return clauses.length ? clauses.join(' OR ') : 'false'
}

/**
 * Browsable relation kinds: ordinary table, view, materialized view, foreign
 * table, partitioned table. Indexes (`i`), sequences (`S`), TOAST (`t`), and
 * composite types (`c`) are excluded — both because a client browses tables, not
 * those, and because a denied table's *dependent* objects (its index/sequence,
 * which carry different relnames) would otherwise slip past the name-based filter
 * under a schema-wide grant and leak the table's existence.
 */
const BROWSABLE_RELKINDS = "('r', 'v', 'm', 'f', 'p')"

/** `pg_class` visibility — correlate `relnamespace` to a schema name. */
function pgClassVisibility(model: PermissionModel): string {
  const inner = tableVisibility(model, 'ns.nspname', 'pg_class.relname')
  return (
    `pg_class.relkind IN ${BROWSABLE_RELKINDS} AND ` +
    `EXISTS (SELECT 1 FROM pg_catalog.pg_namespace ns WHERE ns.oid = pg_class.relnamespace AND (${inner}))`
  )
}

/** `pg_attribute` (column catalog) visibility — correlate `attrelid` to its
 *  table and schema, and filter by readable column (`attname`). */
function pgAttributeVisibility(model: PermissionModel): string {
  const inner = columnVisibility(model, 'n.nspname', 'c.relname', 'pg_attribute.attname')
  return (
    'EXISTS (SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ' +
    `ON n.oid = c.relnamespace WHERE c.oid = pg_attribute.attrelid ` +
    `AND c.relkind IN ${BROWSABLE_RELKINDS} AND (${inner}))`
  )
}

/**
 * `pg_type` visibility, over the alias `t`. Built-in types (in `pg_catalog` /
 * `information_schema`) are public and are exactly what a driver's type cache
 * needs, so they are always visible. A *composite* type (`typrelid <> 0` — Postgres
 * makes one per table) is visible only when its backing relation is, so `pg_type`
 * cannot leak the name of a table outside the model. Any other user-defined type
 * is visible only when its schema is permitted.
 */
function pgTypeVisibility(model: PermissionModel, t = 'pg_type'): string {
  const builtin =
    `EXISTS (SELECT 1 FROM pg_catalog.pg_namespace tn WHERE tn.oid = ${t}.typnamespace ` +
    `AND tn.nspname IN ('pg_catalog', 'information_schema'))`
  const composite =
    `(${t}.typrelid <> 0 AND EXISTS (SELECT 1 FROM pg_catalog.pg_class cc ` +
    `JOIN pg_catalog.pg_namespace cn ON cn.oid = cc.relnamespace ` +
    `WHERE cc.oid = ${t}.typrelid AND (${tableVisibility(model, 'cn.nspname', 'cc.relname')})))`
  const userType =
    `(${t}.typrelid = 0 AND EXISTS (SELECT 1 FROM pg_catalog.pg_namespace un ` +
    `WHERE un.oid = ${t}.typnamespace AND (${schemaVisibility(model, 'un.nspname')})))`
  return `(${builtin} OR ${composite} OR ${userType})`
}

/** `pg_enum` / `pg_range` follow their type's visibility (enum labels and range
 *  defs leak only if the type itself is visible). */
function pgTypeBackedVisibility(model: PermissionModel, oidCol: string): string {
  return (
    `EXISTS (SELECT 1 FROM pg_catalog.pg_type et WHERE et.oid = ${oidCol} ` +
    `AND (${pgTypeVisibility(model, 'et')}))`
  )
}

/** Supported catalog relations → predicate builder. */
const FILTERS: Record<string, (model: PermissionModel) => string> = {
  'pg_catalog.pg_type': (m) => pgTypeVisibility(m),
  'pg_catalog.pg_enum': (m) => pgTypeBackedVisibility(m, 'pg_enum.enumtypid'),
  'pg_catalog.pg_range': (m) => pgTypeBackedVisibility(m, 'pg_range.rngtypid'),
  'information_schema.tables': (m) => tableVisibility(m, 'table_schema', 'table_name'),
  'information_schema.views': (m) => tableVisibility(m, 'table_schema', 'table_name'),
  'information_schema.table_privileges': (m) => tableVisibility(m, 'table_schema', 'table_name'),
  'information_schema.columns': (m) => columnVisibility(m, 'table_schema', 'table_name', 'column_name'),
  'information_schema.column_privileges': (m) =>
    columnVisibility(m, 'table_schema', 'table_name', 'column_name'),
  'information_schema.schemata': (m) => schemaVisibility(m, 'schema_name'),
  'pg_catalog.pg_namespace': (m) => schemaVisibility(m, 'nspname'),
  'pg_catalog.pg_class': (m) => pgClassVisibility(m),
  'pg_catalog.pg_attribute': (m) => pgAttributeVisibility(m),
}

export async function applyIntrospectionFilter(
  parsed: ParseResult,
  model: PermissionModel,
  cteRefs: ReadonlySet<object>,
  relations: readonly RangeVarInfo[],
): Promise<boolean> {
  if (!model.introspection?.enabled) return false

  const predicates = new Map<string, PgNode>()
  for (const rel of relations) {
    if (!isIntrospectionRelation(model, rel.schema, rel.relname)) continue
    const key = catalogKey(rel.schema, rel.relname)
    const build = FILTERS[key]
    if (!build || predicates.has(key)) continue
    predicates.set(key, await parsePredicate(build(model)))
  }
  if (predicates.size === 0) return false

  return wrapRelations(parsed, cteRefs, (rel) =>
    predicates.get(catalogKey(rel.schema, rel.relname)) ?? null,
  )
}
