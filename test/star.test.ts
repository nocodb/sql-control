import { describe, expect, it } from 'vitest'
import { analyze } from '../src/analyzer/index'
import { ViolationCode } from '../src/analyzer/errors'
import { MemoryCatalog } from '../src/schema/memory-catalog'
import type { PermissionModel } from '../src/policy/model'

const catalog = new MemoryCatalog({
  tables: {
    'public.users': ['id', 'email', 'password', 'created_at'],
    'public.orders': ['id', 'user_id', 'total', 'ts'],
  },
})

const model: PermissionModel = {
  tables: {
    'public.users': { select: { columns: ['id', 'email'] } },
    'public.orders': { select: true },
  },
}

async function rewritten(sql: string): Promise<string> {
  const decision = await analyze(sql, { model, catalog })
  if (!decision.allow) throw new Error(`denied: ${JSON.stringify(decision.violations)}`)
  return decision.sql
}

async function firstCode(sql: string): Promise<ViolationCode | undefined> {
  const decision = await analyze(sql, { model, catalog })
  return decision.allow ? undefined : decision.violations[0]?.code
}

describe('SELECT * expansion', () => {
  it('expands `*` on a restricted table to permitted columns', async () => {
    const sql = await rewritten('SELECT * FROM users')
    expect(sql).toMatch(/users\.id/)
    expect(sql).toMatch(/users\.email/)
    expect(sql).not.toMatch(/password/)
    expect(sql).not.toContain('*')
  })

  it('expands a qualified `t.*`', async () => {
    const sql = await rewritten('SELECT u.* FROM users u')
    expect(sql).toMatch(/u\.id/)
    expect(sql).toMatch(/u\.email/)
    expect(sql).not.toMatch(/password/)
  })

  it('expands `*` across a join, per source relation', async () => {
    const sql = await rewritten(
      'SELECT * FROM users u JOIN orders o ON o.user_id = u.id',
    )
    expect(sql).toMatch(/u\.id/)
    expect(sql).toMatch(/u\.email/)
    expect(sql).toMatch(/o\.user_id/)
    expect(sql).toMatch(/o\.total/)
    expect(sql).not.toMatch(/password/)
    expect(sql).not.toContain('*')
  })

  it('expands `*` inside a subquery scope', async () => {
    const sql = await rewritten('SELECT * FROM (SELECT * FROM users) t')
    expect(sql).toMatch(/users\.id/)
    expect(sql).toMatch(/users\.email/)
    expect(sql).not.toMatch(/password/)
  })

  it('leaves a fully-allowed `*` unexpanded when no catalog is provided', async () => {
    const decision = await analyze('SELECT * FROM orders', {
      model: { tables: { 'public.orders': { select: true } } },
    })
    expect(decision.allow).toBe(true)
    // the relation is schema-qualified (F6) but the wildcard is not expanded
    if (decision.allow) {
      expect(decision.sql).toMatch(/\*/)
      expect(decision.sql).not.toMatch(/orders\.\w/)
    }
  })

  it('still rejects an explicitly named forbidden column', async () => {
    expect(await firstCode('SELECT password FROM users')).toBe(ViolationCode.ColumnNotReadable)
  })

  it('fails closed when a restricted `*` cannot be expanded safely', async () => {
    // `users` is restricted but the set-returning function has no alias to
    // qualify, so the wildcard cannot be decomposed — deny rather than leak.
    expect(await firstCode('SELECT * FROM users, generate_series(1, 3)')).toBe(
      ViolationCode.RewriteFailed,
    )
  })
})
