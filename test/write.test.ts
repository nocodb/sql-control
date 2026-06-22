import { describe, expect, it } from 'vitest'
import { analyze } from '../src/analyzer/index'
import { ViolationCode } from '../src/analyzer/errors'
import type { PermissionModel } from '../src/policy/model'

const model: PermissionModel = {
  tables: {
    'public.docs': {
      select: true,
      insert: { columns: ['title', 'body', 'owner_id'] },
      update: { columns: ['title', 'body'] },
      delete: true,
      rls: { select: 'owner_id = ctx.uid', update: 'archived = false', delete: 'archived = false' },
    },
    'public.readonly': { select: true }, // no write perms at all
  },
}

const ctx = { uid: 7 }
const run = (sql: string) => analyze(sql, { model, context: { ctx } })

async function firstCode(sql: string): Promise<ViolationCode | undefined> {
  const decision = await run(sql)
  return decision.allow ? undefined : decision.violations[0]?.code
}
async function rewritten(sql: string): Promise<string> {
  const decision = await run(sql)
  if (!decision.allow) throw new Error(`denied: ${JSON.stringify(decision.violations)}`)
  return decision.sql.replace(/\s+/g, ' ')
}

describe('INSERT', () => {
  it('allows inserting permitted columns', async () => {
    const d = await run("INSERT INTO docs (title, body, owner_id) VALUES ('a', 'b', 7)")
    expect(d.allow).toBe(true)
  })
  it('rejects a forbidden insert column', async () => {
    expect(await firstCode("INSERT INTO docs (title, secret) VALUES ('a', 'b')")).toBe(
      ViolationCode.ColumnNotWritable,
    )
  })
  it('rejects insert into a table with no insert permission', async () => {
    expect(await firstCode('INSERT INTO readonly (x) VALUES (1)')).toBe(
      ViolationCode.InsertNotAllowed,
    )
  })
  it('rejects an implicit column list into a column-restricted table', async () => {
    expect(await firstCode("INSERT INTO docs VALUES ('a', 'b', 7)")).toBe(
      ViolationCode.ColumnNotWritable,
    )
  })
})

describe('UPDATE', () => {
  it('allows updating permitted columns and injects the USING filter', async () => {
    const sql = await rewritten("UPDATE docs SET title = 'x' WHERE id = 5")
    expect(sql).toMatch(/id = 5/)
    expect(sql).toMatch(/docs\.owner_id = 7/)
    expect(sql).toMatch(/docs\.archived = false/)
  })
  it('qualifies the USING filter to the target alias', async () => {
    const sql = await rewritten("UPDATE docs d SET title = 'x' WHERE d.id = 1")
    expect(sql).toMatch(/d\.owner_id = 7/)
  })
  it('rejects updating a forbidden column', async () => {
    expect(await firstCode("UPDATE docs SET owner_id = 9 WHERE id = 1")).toBe(
      ViolationCode.ColumnNotWritable,
    )
  })
  it('rejects update on a table with no update permission', async () => {
    expect(await firstCode("UPDATE readonly SET x = 1")).toBe(ViolationCode.UpdateNotAllowed)
  })
})

describe('DELETE', () => {
  it('allows delete and injects the USING filter', async () => {
    const sql = await rewritten('DELETE FROM docs WHERE id = 1')
    expect(sql).toMatch(/docs\.owner_id = 7/)
    expect(sql).toMatch(/docs\.archived = false/)
  })
  it('rejects delete on a table with no delete permission', async () => {
    expect(await firstCode('DELETE FROM readonly')).toBe(ViolationCode.DeleteNotAllowed)
  })
})

describe('writes in context', () => {
  it('checks a data-modifying CTE write', async () => {
    expect(
      await firstCode('WITH w AS (DELETE FROM readonly RETURNING id) SELECT * FROM w'),
    ).toBe(ViolationCode.DeleteNotAllowed)
  })

  it('filters the read side of INSERT ... SELECT with RLS', async () => {
    const sql = await rewritten(
      'INSERT INTO docs (title, body, owner_id) SELECT title, body, owner_id FROM docs',
    )
    expect(sql).toMatch(/SELECT \* FROM public\.docs WHERE owner_id = 7 OFFSET 0/i)
  })
})
