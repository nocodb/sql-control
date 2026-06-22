import { describe, expect, it } from 'vitest'
import { analyze } from '../src/analyzer/index'
import { ViolationCode } from '../src/analyzer/errors'
import type { PermissionModel } from '../src/policy/model'

/** A tenant granted their whole `app` schema, with one table held back and one
 *  column-restricted, plus no access to the `internal` schema at all. */
const model: PermissionModel = {
  schemas: {
    app: { defaultTablePolicy: { select: true } },
  },
  tables: {
    'app.audit_log': { select: false },
    'app.users': { select: { columns: ['id', 'email'] } },
  },
}

const run = (sql: string) => analyze(sql, { model })
async function firstCode(sql: string): Promise<ViolationCode | undefined> {
  const decision = await run(sql)
  return decision.allow ? undefined : decision.violations[0]?.code
}

describe('schema-level access control', () => {
  it('grants a whole schema via the default table policy', async () => {
    expect((await run('SELECT * FROM app.orders')).allow).toBe(true)
    expect((await run('SELECT anything FROM app.widgets')).allow).toBe(true)
  })

  it('hard-gates relations in a schema the role cannot access', async () => {
    expect(await firstCode('SELECT * FROM internal.secrets')).toBe(
      ViolationCode.SchemaNotVisible,
    )
  })

  it('lets a table entry override the schema default to revoke access', async () => {
    expect(await firstCode('SELECT * FROM app.audit_log')).toBe(
      ViolationCode.RelationNotVisible,
    )
  })

  it('lets a table entry narrow columns under an open schema', async () => {
    expect((await run('SELECT id, email FROM app.users')).allow).toBe(true)
    expect(await firstCode('SELECT password FROM app.users')).toBe(
      ViolationCode.ColumnNotReadable,
    )
  })

  it('still gates the unqualified default schema', async () => {
    // `public` is not in `schemas`, so an unqualified name is gated out.
    expect(await firstCode('SELECT * FROM customers')).toBe(ViolationCode.SchemaNotVisible)
  })

  it('leaves gating off when schemas is omitted', async () => {
    const decision = await analyze('SELECT id FROM public.t', {
      model: { tables: { 'public.t': { select: true } } },
    })
    expect(decision.allow).toBe(true)
  })
})
