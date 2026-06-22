import { describe, expect, it } from 'vitest'
import { analyze } from '../src/analyzer/index'
import { ViolationCode } from '../src/analyzer/errors'
import type { PermissionModel } from '../src/policy/model'

const model: PermissionModel = {
  defaultSchema: 'public',
  tables: {
    'public.users': { select: { columns: ['id', 'email', 'active'] } },
    'public.profiles': { select: true },
    'public.orders': { select: { columns: ['id', 'user_id', 'ts'] } },
  },
  introspection: { enabled: true },
}

const run = (sql: string) => analyze(sql, { model })

/** The code of the first violation, or undefined if the statement was allowed. */
async function firstCode(sql: string): Promise<ViolationCode | undefined> {
  const decision = await run(sql)
  return decision.allow ? undefined : decision.violations[0]?.code
}

describe('statement guard', () => {
  it('rejects DDL (schema-altering) statements', async () => {
    expect(await firstCode('DROP TABLE users')).toBe(ViolationCode.StatementNotAllowed)
    expect(await firstCode('ALTER TABLE users ADD COLUMN x int')).toBe(
      ViolationCode.StatementNotAllowed,
    )
    expect(await firstCode('CREATE TABLE t (id int)')).toBe(ViolationCode.StatementNotAllowed)
    expect(await firstCode('TRUNCATE users')).toBe(ViolationCode.StatementNotAllowed)
    expect(await firstCode('GRANT ALL ON users TO bob')).toBe(ViolationCode.StatementNotAllowed)
  })

  it('rejects statement stacking', async () => {
    expect(await firstCode('SELECT 1; DROP TABLE users')).toBe(ViolationCode.StatementStacking)
  })

  it('rejects unparseable input', async () => {
    expect(await firstCode('this is not sql')).toBe(ViolationCode.ParseError)
  })
})

describe('relation visibility', () => {
  it('allows a select over visible columns', async () => {
    expect((await run('SELECT id, email FROM users')).allow).toBe(true)
  })

  it('denies an invisible relation', async () => {
    expect(await firstCode('SELECT id FROM secrets')).toBe(ViolationCode.RelationNotVisible)
  })

  it('descends into subqueries', async () => {
    expect(
      await firstCode('SELECT id FROM users WHERE id IN (SELECT user_id FROM secrets)'),
    ).toBe(ViolationCode.RelationNotVisible)
  })

  it('allows a join across two visible relations', async () => {
    expect(
      (await run('SELECT u.email, p.user_id FROM users u JOIN profiles p ON p.user_id = u.id'))
        .allow,
    ).toBe(true)
  })
})

describe('column readability', () => {
  it('denies an explicitly named forbidden column', async () => {
    expect(await firstCode('SELECT password FROM users')).toBe(ViolationCode.ColumnNotReadable)
  })

  it('resolves unqualified columns when there is a single source', async () => {
    expect(await firstCode('SELECT email, ssn FROM users')).toBe(ViolationCode.ColumnNotReadable)
  })

  it('allows a wildcard for now (deferred to the rewriter)', async () => {
    const decision = await run('SELECT * FROM users')
    expect(decision.allow).toBe(true)
    if (decision.allow) expect(decision.notes.join(' ')).toMatch(/wildcard/)
  })
})

describe('introspection (information_schema)', () => {
  it('allows reading information_schema, deferring row filtering to the rewriter', async () => {
    const decision = await run(
      'SELECT table_name FROM information_schema.tables WHERE table_schema = $1',
    )
    expect(decision.allow).toBe(true)
    if (decision.allow) expect(decision.notes.join(' ')).toMatch(/introspection/)
  })

  it('denies introspection when it is not enabled', async () => {
    const decision = await analyze('SELECT table_name FROM information_schema.tables', {
      model: { tables: {} },
    })
    expect(decision.allow).toBe(false)
  })

  it('allows a non-sensitive catalog under introspection', async () => {
    expect((await run('SELECT relname FROM pg_catalog.pg_class')).allow).toBe(true)
  })

  it('blocks secret-bearing catalogs even with introspection enabled', async () => {
    expect(await firstCode('SELECT * FROM pg_authid')).toBe(ViolationCode.SystemCatalogBlocked)
    expect(await firstCode('SELECT rolname FROM pg_catalog.pg_shadow')).toBe(
      ViolationCode.SystemCatalogBlocked,
    )
    expect(await firstCode('SELECT subconninfo FROM pg_subscription')).toBe(
      ViolationCode.SystemCatalogBlocked,
    )
  })
})

describe('write detection', () => {
  it('enforces UPDATE permission (none granted here)', async () => {
    expect(await firstCode("UPDATE users SET email = 'x'")).toBe(ViolationCode.UpdateNotAllowed)
  })

  it('catches and checks a data-modifying CTE hidden inside a SELECT', async () => {
    expect(
      await firstCode(
        "WITH w AS (INSERT INTO users(email) VALUES ('a') RETURNING id) SELECT * FROM w",
      ),
    ).toBe(ViolationCode.InsertNotAllowed)
  })
})
