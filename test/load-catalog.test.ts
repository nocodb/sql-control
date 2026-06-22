import { describe, expect, it } from 'vitest'
import { analyze } from '../src/analyzer/index'
import { ViolationCode } from '../src/analyzer/errors'
import { loadCatalog, type IntrospectionQuery } from '../src/schema/load-catalog'
import type { PermissionModel } from '../src/policy/model'

const columns: (readonly [string, string, string])[] = [
  ['app', 'users', 'id'],
  ['app', 'users', 'email'],
  ['app', 'users', 'password'],
  ['app', 'audit', 'id'],
  ['app', 'events', 'id'],
  ['app', 'events', 'ts'],
  ['secret', 'keys', 'id'],
]
const views: (readonly [string, string])[] = [['app', 'user_summary']]
// Rows pg_inherits yields: a relation that is a PARENT (has inheritance/partition
// children). `events` is partitioned; `users` is not.
const parents: (readonly [string, string])[] = [['app', 'events']]

// Distinguish all three introspection queries the loader runs — crucially the
// pg_inherits (parents) query, whose result drives the inheritance fail-closed check.
const query: IntrospectionQuery = async (sql) =>
  sql.includes('pg_inherits') ? parents : sql.includes('information_schema.views') ? views : columns

describe('loadCatalog', () => {
  it('builds a catalog from introspection rows', async () => {
    const catalog = await loadCatalog(query)
    expect(catalog.columns('app', 'users')).toEqual(['id', 'email', 'password'])
    expect(catalog.columns('secret', 'keys')).toEqual(['id'])
    expect(catalog.isView('app', 'user_summary')).toBe(true)
    expect(catalog.isView('app', 'users')).toBe(false)
  })

  it('loads inheritance/partition parents from pg_inherits (drives inheritance fail-closed)', async () => {
    const catalog = await loadCatalog(query)
    // The pg_inherits parent is recorded; a non-parent relation is not.
    expect(catalog.hasChildren('app', 'events')).toBe(true)
    expect(catalog.hasChildren('app', 'users')).toBe(false)
    expect(catalog.hasChildren('app', 'missing')).toBe(false)
  })

  it('parents are NOT model-filtered, so a granted parent still fails closed', async () => {
    // The loader must record a parent even when the catalog is model-restricted —
    // otherwise a model granting only the parent would lose the childlessness proof
    // and the inheritance read would fail OPEN. Restrict to `app`, grant `events`.
    const model: PermissionModel = {
      defaultSchema: 'app',
      schemas: { app: { defaultTablePolicy: { select: true } } },
      tables: { 'secret.keys': { select: false } },
    }
    const catalog = await loadCatalog(query, { model })
    expect(catalog.hasChildren('app', 'events')).toBe(true)
    // Reading the granted parent (not ONLY) also reads its partitions → denied.
    const d = await analyze('SELECT * FROM events', { model, catalog, context: { ctx: {} } })
    expect(d.allow).toBe(false)
    if (!d.allow) expect(d.violations[0]?.code).toBe(ViolationCode.InheritedRelationBlocked)
    // FROM ONLY targets just the parent → permitted.
    expect((await analyze('SELECT id FROM ONLY events', { model, catalog, context: { ctx: {} } })).allow).toBe(true)
  })

  it('restricts the catalog to relations the model can see', async () => {
    const model: PermissionModel = {
      schemas: { app: { defaultTablePolicy: { select: true } } },
      tables: { 'app.audit': { select: false } }, // denied; `secret` schema not granted
    }
    const catalog = await loadCatalog(query, { model })
    // visible: includes real (unfiltered) columns — the rewriter applies policy
    expect(catalog.columns('app', 'users')).toEqual(['id', 'email', 'password'])
    // hidden by policy: not loaded at all
    expect(catalog.columns('app', 'audit')).toBeUndefined()
    expect(catalog.columns('secret', 'keys')).toBeUndefined()
  })
})
