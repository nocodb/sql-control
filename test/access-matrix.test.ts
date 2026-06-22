import { describe, expect, it } from 'vitest'
import { analyze } from '../src/analyzer/index'
import { MemoryCatalog } from '../src/schema/memory-catalog'
import type { PermissionModel } from '../src/policy/model'

/**
 * Broad access-control matrices: write permissions (INSERT/UPDATE/DELETE × column
 * limits × RETURNING × ON CONFLICT × FROM/USING), join column resolution across
 * join shapes, and RLS-injection presence in every relation position. Each row is
 * a distinct enforcement scenario; a denied row that is ALLOWED is a real bypass.
 */
const catalog = new MemoryCatalog({
  tables: {
    'public.users': ['id', 'email', 'tenant', 'password'],
    'public.orders': ['id', 'user_id', 'total', 'tenant'],
    'public.notes': ['id', 'body', 'secret'],
    'public.audit': ['id', 'msg'],
  },
})
const model: PermissionModel = {
  tables: {
    'public.users': { select: { columns: ['id', 'email', 'tenant'] }, rls: { select: 'tenant = ctx.t' } },
    'public.orders': { select: true, rls: { select: 'tenant = ctx.t' } },
    'public.notes': {
      select: { columns: ['id', 'body'] },
      insert: { columns: ['body'] },
      update: { columns: ['body'] },
      delete: true,
    },
    'public.audit': { insert: { columns: ['msg'] } }, // write-only, no select
  },
}
const run = (sql: string) => analyze(sql, { model, catalog, context: { ctx: { t: 1 } } })
const allows = async (sql: string) => (await run(sql)).allow

// ── write permission matrix ───────────────────────────────────────────────────
const WRITES_ALLOWED: [string, string][] = [
  ['insert permitted col', "INSERT INTO notes (body) VALUES ('x')"],
  ['insert multi-row', "INSERT INTO notes (body) VALUES ('a'), ('b')"],
  ['insert select permitted', "INSERT INTO notes (body) SELECT body FROM notes"],
  ['insert write-only table', "INSERT INTO audit (msg) VALUES ('hi')"],
  ['update permitted col', "UPDATE notes SET body = 'x' WHERE id = 1"],
  ['update returning permitted', "UPDATE notes SET body = 'x' RETURNING id, body"],
  ['delete', 'DELETE FROM notes WHERE id = 1'],
  ['delete returning permitted', 'DELETE FROM notes WHERE id = 1 RETURNING id'],
  ['insert on conflict permitted', "INSERT INTO notes (body) VALUES ('x') ON CONFLICT (id) DO UPDATE SET body = 'y'"],
]
const WRITES_DENIED: [string, string][] = [
  ['insert forbidden col', "INSERT INTO notes (secret) VALUES ('x')"],
  ['insert implicit all cols', "INSERT INTO notes VALUES (1, 'b', 's')"],
  ['insert select forbidden read', 'INSERT INTO notes (body) SELECT secret FROM notes'],
  ['insert no-insert table', "INSERT INTO users (email) VALUES ('x')"],
  ['update forbidden col', "UPDATE notes SET secret = 'x'"],
  ['update no-update table', "UPDATE users SET email = 'x'"],
  ['update returning forbidden', "UPDATE notes SET body = 'x' RETURNING secret"],
  ['update where forbidden', "UPDATE notes SET body = 'x' WHERE secret = 'y'"],
  ['update multi-assign forbidden', "UPDATE notes SET (body, secret) = ('x', 'y')"],
  ['delete no-delete table', 'DELETE FROM users'],
  ['delete returning forbidden', 'DELETE FROM notes RETURNING secret'],
  ['delete where forbidden', "DELETE FROM notes WHERE secret = 'y'"],
  ['on conflict forbidden col', "INSERT INTO notes (id, body) VALUES (1, 'x') ON CONFLICT (id) DO UPDATE SET secret = 'y'"],
  ['insert returning forbidden', "INSERT INTO notes (body) VALUES ('x') RETURNING secret"],
  ['select from write-only table', 'SELECT msg FROM audit'],
  ['update from forbidden read', "UPDATE notes SET body = users.email FROM users WHERE users.password = 'x'"],
]

describe('write permission matrix: allowed', () => {
  it.each(WRITES_ALLOWED)('allows %s', async (_l, sql) => expect(await allows(sql), sql).toBe(true))
})
describe('write permission matrix: denied', () => {
  it.each(WRITES_DENIED)('denies %s', async (_l, sql) => expect(await allows(sql), sql).toBe(false))
})

// ── join column resolution across join shapes ─────────────────────────────────
const JOINS_ALLOWED: [string, string][] = [
  ['inner on', 'SELECT u.id, o.total FROM users u JOIN orders o ON o.user_id = u.id'],
  ['left join', 'SELECT u.email FROM orders o LEFT JOIN users u ON u.id = o.user_id'],
  ['right join', 'SELECT u.email FROM users u RIGHT JOIN orders o ON u.id = o.user_id'],
  ['full join', 'SELECT u.id FROM users u FULL JOIN orders o ON u.id = o.user_id'],
  ['cross join', 'SELECT u.email, o.total FROM users u CROSS JOIN orders o'],
  ['using id', 'SELECT total FROM users JOIN orders USING (id)'],
  ['using tenant', 'SELECT total FROM users JOIN orders USING (tenant)'],
  ['three-way', 'SELECT u.id, o.total, n.body FROM users u JOIN orders o ON o.user_id = u.id JOIN notes n ON n.id = u.id'],
  ['subquery join', 'SELECT t.email FROM (SELECT email FROM users) t JOIN orders o ON true'],
  ['self join', 'SELECT a.id FROM users a JOIN users b ON a.tenant = b.tenant'],
]
const JOINS_DENIED: [string, string][] = [
  ['on forbidden qualified', 'SELECT u.id FROM users u JOIN orders o ON u.password = o.id'],
  ['select forbidden qualified', 'SELECT u.password FROM users u JOIN orders o ON o.user_id = u.id'],
  ['ambiguous forbidden', 'SELECT password FROM users JOIN orders ON true'],
  ['cross join forbidden', 'SELECT u.password FROM users u CROSS JOIN orders o'],
  ['left join forbidden', 'SELECT u.password FROM orders o LEFT JOIN users u ON u.id = o.user_id'],
  ['using forbidden via notes', 'SELECT n.id FROM notes n JOIN notes n2 USING (secret)'],
  ['three-way forbidden', 'SELECT u.password FROM users u JOIN orders o ON o.user_id = u.id JOIN notes n ON n.id = u.id'],
  ['subquery exposes forbidden', 'SELECT t.password FROM (SELECT password FROM users) t'],
  ['join alias forbidden', 'SELECT x.password FROM (users u JOIN orders o ON true) x'],
]

describe('join column resolution: allowed', () => {
  it.each(JOINS_ALLOWED)('allows %s', async (_l, sql) => expect(await allows(sql), sql).toBe(true))
})
describe('join column resolution: denied', () => {
  it.each(JOINS_DENIED)('denies %s', async (_l, sql) => expect(await allows(sql), sql).toBe(false))
})

// ── RLS injected in every relation position ───────────────────────────────────
const RLS_POSITIONS: [string, string, number][] = [
  ['top-level', 'SELECT id FROM users', 1],
  ['where subquery', 'SELECT id FROM users WHERE id IN (SELECT user_id FROM orders)', 2],
  ['scalar subquery', 'SELECT id FROM users WHERE id > (SELECT count(*) FROM orders)', 2],
  ['exists', 'SELECT id FROM users u WHERE EXISTS (SELECT 1 FROM orders o WHERE o.user_id = u.id)', 2],
  ['join', 'SELECT u.id, o.total FROM users u JOIN orders o ON o.user_id = u.id', 2],
  ['self-join', 'SELECT a.id FROM users a JOIN users b ON a.tenant = b.tenant', 2],
  ['union arms', 'SELECT id FROM users UNION SELECT user_id FROM orders', 2],
  ['cte', 'WITH x AS (SELECT id FROM users) SELECT * FROM x', 1],
  ['lateral', 'SELECT u.id FROM users u, LATERAL (SELECT total FROM orders o WHERE o.user_id = u.id) z', 2],
  ['from subquery', 'SELECT t.id FROM (SELECT id FROM users) t', 1],
]

describe('RLS predicate is injected for every relation occurrence', () => {
  it.each(RLS_POSITIONS)('injects in %s', async (_l, sql, count) => {
    const d = await run(sql)
    expect(d.allow, sql).toBe(true)
    if (d.allow) expect((d.sql.match(/tenant = 1/g) ?? []).length, sql).toBe(count)
  })
})
