import { describe, expect, it } from 'vitest'
import { analyze } from '../src/analyzer/index'
import { ViolationCode } from '../src/analyzer/errors'
import { MemoryCatalog } from '../src/schema/memory-catalog'
import type { Catalog } from '../src/analyzer/types'
import type { PermissionModel } from '../src/policy/model'

/**
 * Inheritance/partition reads are fail-CLOSED: reading a parent (not `ONLY`) also
 * reads its children, so it is denied unless the catalog *proves* the relation is
 * childless (`hasChildren === false`). A catalog that can't answer leaves it
 * unproven and must deny — that was the one confirmed "could read forbidden data"
 * fail-open. `allowInherited` and `ONLY` are the explicit opt-ins.
 */
const model: PermissionModel = {
  tables: { 'public.parent': { select: { columns: ['id'] }, delete: true } },
}
const allowInheritedModel: PermissionModel = {
  tables: { 'public.parent': { select: { columns: ['id'] }, allowInherited: true } },
}
const an = (sql: string, catalog?: Catalog) => analyze(sql, { model, catalog, context: { ctx: {} } })

describe('inheritance read is fail-closed', () => {
  it('denies a parent read when the catalog proves it has children', async () => {
    const cat = new MemoryCatalog({ tables: { 'public.parent': ['id'] }, parents: ['public.parent'] })
    const d = await an('SELECT id FROM parent', cat)
    expect(d.allow).toBe(false)
    if (!d.allow) expect(d.violations[0]?.code).toBe(ViolationCode.InheritedRelationBlocked)
  })

  it('FAIL-CLOSED: denies when the catalog cannot prove childlessness (no hasChildren)', async () => {
    // A custom catalog that resolves columns but does not implement hasChildren —
    // childlessness is unprovable, so the read must be denied (this was the bug).
    const cantProve: Catalog = {
      columns: (_s, r) => (r === 'parent' ? ['id'] : undefined),
      isView: () => false,
    }
    const d = await an('SELECT id FROM parent', cantProve)
    expect(d.allow).toBe(false)
    if (!d.allow) expect(d.violations[0]?.code).toBe(ViolationCode.InheritedRelationBlocked)
  })

  it('allows a parent read when the catalog proves it is childless', async () => {
    const cat = new MemoryCatalog({ tables: { 'public.parent': ['id'] } }) // not in parents → childless
    expect((await an('SELECT id FROM parent', cat)).allow).toBe(true)
  })

  it('allows when allowInherited is set, even with children', async () => {
    const cat = new MemoryCatalog({ tables: { 'public.parent': ['id'] }, parents: ['public.parent'] })
    const d = await analyze('SELECT id FROM parent', { model: allowInheritedModel, catalog: cat, context: { ctx: {} } })
    expect(d.allow).toBe(true)
  })

  it('allows FROM ONLY parent (children excluded), even with children', async () => {
    const cat = new MemoryCatalog({ tables: { 'public.parent': ['id'] }, parents: ['public.parent'] })
    expect((await an('SELECT id FROM ONLY parent', cat)).allow).toBe(true)
  })
})

describe('inheritance write is fail-closed', () => {
  it('denies a DELETE on a parent the catalog cannot prove childless', async () => {
    const cantProve: Catalog = { columns: () => ['id'], isView: () => false }
    const d = await an('DELETE FROM parent WHERE id = 1', cantProve)
    expect(d.allow).toBe(false)
    if (!d.allow) expect(d.violations[0]?.code).toBe(ViolationCode.InheritedRelationBlocked)
  })
  it('allows DELETE FROM ONLY parent', async () => {
    const cat = new MemoryCatalog({ tables: { 'public.parent': ['id'] }, parents: ['public.parent'] })
    expect((await an('DELETE FROM ONLY parent WHERE id = 1', cat)).allow).toBe(true)
  })
})
