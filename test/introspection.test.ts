import { describe, expect, it } from 'vitest'
import { analyze } from '../src/analyzer/index'
import { ViolationCode } from '../src/analyzer/errors'
import type { PermissionModel } from '../src/policy/model'

const model: PermissionModel = {
  schemas: { app: { defaultTablePolicy: { select: true } } },
  tables: {
    'app.audit': { select: false }, // denied within an otherwise-open schema
    'app.users': { select: { columns: ['id', 'email'] } }, // column-restricted
    'public.shared': { select: true }, // explicit grant outside the open schema
  },
  introspection: { enabled: true },
}

async function rewritten(sql: string): Promise<string> {
  const decision = await analyze(sql, { model })
  if (!decision.allow) throw new Error(`denied: ${JSON.stringify(decision.violations)}`)
  return decision.sql.replace(/\s+/g, ' ')
}

describe('introspection row-filter', () => {
  it('filters information_schema.tables to permitted objects', async () => {
    const sql = await rewritten('SELECT table_name FROM information_schema.tables')
    expect(sql).toMatch(/FROM \( SELECT \* FROM information_schema\.tables WHERE/i)
    expect(sql).toMatch(/table_schema IN \('app'\)/)
    expect(sql).toMatch(/table_name = 'shared'/)
    expect(sql).toMatch(/NOT.*table_name = 'audit'/)
  })

  it('filters information_schema.schemata to accessible schemas', async () => {
    const sql = await rewritten('SELECT schema_name FROM information_schema.schemata')
    expect(sql).toMatch(/schema_name IN \('app', 'public'\)/)
  })

  it('hides non-readable columns in information_schema.columns', async () => {
    const sql = await rewritten('SELECT column_name FROM information_schema.columns')
    // restricted table: only its allowed columns
    expect(sql).toMatch(/table_name = 'users' AND column_name IN \('id', 'email'\)/)
    // schema-default tables: all columns, except the explicitly-handled ones
    expect(sql).toMatch(/table_name NOT IN \('users', 'audit'\)/)
  })

  it('filters pg_catalog.pg_namespace to accessible schemas', async () => {
    const sql = await rewritten('SELECT nspname FROM pg_catalog.pg_namespace')
    expect(sql).toMatch(/nspname IN \('app', 'public'\)/)
  })

  it('filters pg_catalog.pg_class via a correlated namespace lookup', async () => {
    const sql = await rewritten('SELECT relname FROM pg_catalog.pg_class')
    expect(sql).toMatch(/EXISTS \(SELECT 1 FROM pg_catalog\.pg_namespace/i)
    expect(sql).toMatch(/ns\.oid = pg_class\.relnamespace/)
    expect(sql).toMatch(/pg_class\.relname = 'audit'/) // denied table excluded
  })

  it('still blocks secret-bearing catalogs', async () => {
    const decision = await analyze('SELECT * FROM pg_authid', { model })
    expect(decision.allow).toBe(false)
    if (!decision.allow) expect(decision.violations[0]?.code).toBe(ViolationCode.SystemCatalogBlocked)
  })

  it('does not filter when introspection is disabled', async () => {
    const decision = await analyze('SELECT table_name FROM information_schema.tables', {
      model: { schemas: { app: {} }, tables: {} },
    })
    // information_schema not enabled -> treated as a normal (gated) relation
    expect(decision.allow).toBe(false)
  })
})
