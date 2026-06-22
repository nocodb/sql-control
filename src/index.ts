/** Public API surface of sql-control. */
export { analyze, type AnalyzeOptions } from './analyzer/index'
export type { Decision, Catalog, RequestContext } from './analyzer/types'
export { MemoryCatalog, type CatalogData } from './schema/memory-catalog'
export { loadCatalog, type IntrospectionQuery, type LoadCatalogOptions } from './schema/load-catalog'
export {
  createProxyServer,
  type ProxyServerOptions,
  type ProxyTlsOptions,
  type ScramAuth,
  type ScramUser,
} from './proxy/server'
export { handleQuery, type Backend, type QueryResult, type ResolvedPolicy } from './proxy/handler'
export type { FieldInfo } from './proxy/wire'
export { ViolationCode, type Violation } from './analyzer/errors'
export {
  SqlState,
  isSqlControlError,
  SQL_CONTROL_SQLSTATE_CLASS,
} from './proxy/sqlstate'
export type {
  PermissionModel,
  TablePolicy,
  SchemaPolicy,
  IntrospectionPolicy,
} from './policy/model'
