import type { Catalog } from '../analyzer/types'

export interface CatalogData {
  /** `"<schema>.<relname>"` → ordered column names. */
  tables: Record<string, readonly string[]>
  /** `"<schema>.<relname>"` entries that are views rather than tables. */
  views?: readonly string[]
  /** `"<schema>.<relname>"` entries that have inheritance/partition children. */
  parents?: readonly string[]
}

/**
 * A static, in-memory {@link Catalog}. Used in tests and anywhere the schema is
 * known up front; the live `information_schema` loader will implement the same
 * interface for the proxy.
 */
export class MemoryCatalog implements Catalog {
  private readonly views: ReadonlySet<string>
  private readonly parents: ReadonlySet<string>

  constructor(private readonly data: CatalogData) {
    this.views = new Set(data.views ?? [])
    this.parents = new Set(data.parents ?? [])
  }

  columns(schema: string, relname: string): readonly string[] | undefined {
    return this.data.tables[`${schema}.${relname}`]
  }

  isView(schema: string, relname: string): boolean {
    return this.views.has(`${schema}.${relname}`)
  }

  hasChildren(schema: string, relname: string): boolean {
    return this.parents.has(`${schema}.${relname}`)
  }
}
