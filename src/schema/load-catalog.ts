/**
 * Build a {@link Catalog} by introspecting a live database. The caller supplies a
 * `query` runner (e.g. a `pg` pool) returning rows as arrays; this keeps the
 * loader dependency-free and testable. When a `model` is given, the catalog is
 * limited to the relations that model can see, so a per-tenant catalog never
 * carries another tenant's schema.
 */
import { isRelationVisible, type PermissionModel } from '../policy/model'
import { MemoryCatalog } from './memory-catalog'

/** Runs an introspection query, returning rows as arrays of text values. */
export type IntrospectionQuery = (
  sql: string,
) => Promise<readonly (readonly (string | null)[])[]>

const COLUMNS_SQL =
  'SELECT table_schema, table_name, column_name FROM information_schema.columns ' +
  'ORDER BY table_schema, table_name, ordinal_position'

const VIEWS_SQL = 'SELECT table_schema, table_name FROM information_schema.views'

const PARENTS_SQL =
  'SELECT DISTINCT n.nspname, c.relname FROM pg_catalog.pg_inherits i ' +
  'JOIN pg_catalog.pg_class c ON c.oid = i.inhparent ' +
  'JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace'

export interface LoadCatalogOptions {
  /** Restrict the catalog to relations visible to this model (object-level). */
  model?: PermissionModel
}

export async function loadCatalog(
  query: IntrospectionQuery,
  options: LoadCatalogOptions = {},
): Promise<MemoryCatalog> {
  const { model } = options
  const visible = (schema: string, relname: string): boolean =>
    model === undefined || isRelationVisible(model, schema, relname)

  const tables: Record<string, string[]> = {}
  for (const row of await query(COLUMNS_SQL)) {
    const [schema, table, column] = row
    if (!schema || !table || !column || !visible(schema, table)) continue
    const key = `${schema}.${table}`
    ;(tables[key] ??= []).push(column)
  }

  const views: string[] = []
  for (const row of await query(VIEWS_SQL)) {
    const [schema, table] = row
    if (!schema || !table || !visible(schema, table)) continue
    views.push(`${schema}.${table}`)
  }

  const parents: string[] = []
  for (const row of await query(PARENTS_SQL)) {
    const [schema, table] = row
    if (schema && table) parents.push(`${schema}.${table}`)
  }

  return new MemoryCatalog({ tables, views, parents })
}
