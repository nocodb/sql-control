/**
 * System catalogs that leak secrets or other roles' data and must stay blocked
 * even when introspection is enabled. Names are taken from the Postgres source
 * (`src/include/catalog`, `src/backend/catalog`); see test/corpus/system-relations.json.
 */

/** Catalogs whose rows expose credentials or other roles' private data. */
export const SENSITIVE_SYSTEM_RELATIONS: ReadonlySet<string> = new Set([
  'pg_authid', // role password hashes
  'pg_shadow', // view over pg_authid (passwords)
  'pg_user_mapping', // foreign-server options, incl. passwords
  'pg_user_mappings', // view over pg_user_mapping
  'pg_subscription', // subconninfo connection strings, incl. passwords
  'pg_statistic', // sampled column values (most_common_vals/histogram) from every table
  'pg_statistic_ext_data', // serialized extended-stats MCV lists = real multi-column values
  'pg_stats', // security-barrier view exposing pg_statistic's sampled values in the clear
  'pg_stats_ext', // same, for extended statistics
  'pg_stats_ext_exprs', // same, for expression statistics
  'pg_largeobject', // raw large-object contents
])

/** Whether a relation name is a sensitive catalog that must never be read. */
export function isSensitiveSystemRelation(relname: string): boolean {
  return SENSITIVE_SYSTEM_RELATIONS.has(relname.toLowerCase())
}

/**
 * Catalog relations the rewriter knows how to row-filter. With introspection on,
 * only these are permitted by default (deny-most); anything else leaks object
 * existence or data and must be opted into via `introspection.allowUnfiltered`.
 * Keep in sync with the predicate builders in `rewrite/introspection.ts`.
 */
export const FILTERABLE_CATALOGS: ReadonlySet<string> = new Set([
  'information_schema.tables',
  'information_schema.views',
  'information_schema.columns',
  'information_schema.table_privileges',
  'information_schema.column_privileges',
  'information_schema.schemata',
  'pg_catalog.pg_namespace',
  'pg_catalog.pg_class',
  'pg_catalog.pg_attribute',
  // Type catalogs real drivers (postgres.js, JDBC) read on connect to build their
  // OID→type-parser cache. Row-FILTERED, not passed through: built-in types (which
  // drivers actually need) plus the tenant's own permitted types — a composite type
  // is visible only if its backing relation is, so `pg_type` cannot leak the names
  // of tables/types outside the model. See rewrite/introspection.ts.
  'pg_catalog.pg_type',
  'pg_catalog.pg_range',
  'pg_catalog.pg_enum',
])

/** Normalize a catalog relation to its `"schema.relname"` key (pg_* ⇒ pg_catalog). */
export function catalogKey(schema: string | undefined, relname: string): string {
  const resolved = schema ?? (relname.startsWith('pg_') ? 'pg_catalog' : '')
  return `${resolved}.${relname}`
}
