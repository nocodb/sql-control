import { describe, expect, it } from 'vitest'
import { analyze } from '../src/analyzer/index'
import { MemoryCatalog } from '../src/schema/memory-catalog'
import type { PermissionModel } from '../src/policy/model'

/**
 * Broad feature coverage across the SQL surface exercised by the Postgres
 * regression suite. `users.password` and `notes.secret` are the forbidden
 * columns; every "denies" query embeds one in some syntactic position to prove
 * the collector reaches it. A "denies" query that is ALLOWED is a real bypass.
 */
const model: PermissionModel = {
  tables: {
    'public.users': { select: { columns: ['id', 'email', 'age'] } },
    'public.orders': { select: true },
    'public.notes': {
      select: { columns: ['id', 'body'] },
      insert: { columns: ['body'] },
      update: { columns: ['body'] },
      delete: true,
    },
  },
}
const catalog = new MemoryCatalog({
  tables: {
    'public.users': ['id', 'email', 'age', 'password'],
    'public.orders': ['id', 'user_id', 'total'],
    'public.notes': ['id', 'body', 'secret'],
  },
})

const run = (sql: string) => analyze(sql, { model, catalog, context: { ctx: {} } })

const ALLOWED: [string, string][] = [
  ['simple', 'SELECT id, email FROM users'],
  ['where', 'SELECT id FROM users WHERE age > 18 AND email IS NOT NULL'],
  ['inner join', 'SELECT u.id, o.total FROM users u JOIN orders o ON o.user_id = u.id'],
  ['left join', 'SELECT u.email FROM orders o LEFT JOIN users u ON u.id = o.user_id'],
  ['cross join', 'SELECT u.email, o.total FROM users u CROSS JOIN orders o'],
  ['join using', 'SELECT total FROM users JOIN orders USING (id)'],
  ['scalar subquery', 'SELECT o.id FROM orders o WHERE o.total > (SELECT avg(age) FROM users)'],
  ['in subquery', 'SELECT id FROM orders WHERE user_id IN (SELECT id FROM users)'],
  ['exists', 'SELECT o.id FROM orders o WHERE EXISTS (SELECT 1 FROM users u WHERE u.id = o.user_id)'],
  ['cte', 'WITH x AS (SELECT id, email FROM users) SELECT * FROM x'],
  ['recursive cte', 'WITH RECURSIVE t(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM t WHERE n < 5) SELECT n FROM t'],
  ['union', 'SELECT id FROM users UNION SELECT id FROM orders'],
  ['intersect', 'SELECT id FROM users INTERSECT SELECT user_id FROM orders'],
  ['except all', 'SELECT id FROM users EXCEPT ALL SELECT user_id FROM orders'],
  ['window', 'SELECT id, row_number() OVER (PARTITION BY email ORDER BY age) FROM users'],
  ['agg group having', 'SELECT email, count(*) FROM users GROUP BY email HAVING count(*) > 1'],
  ['agg filter', 'SELECT count(*) FILTER (WHERE age > 18) FROM users'],
  ['agg order', 'SELECT array_agg(id ORDER BY age) FROM users'],
  ['grouping sets', 'SELECT count(*) FROM users GROUP BY GROUPING SETS ((email), (age))'],
  ['rollup', 'SELECT count(*) FROM users GROUP BY ROLLUP (email, age)'],
  ['lateral', 'SELECT o.id, x.email FROM orders o, LATERAL (SELECT email FROM users u WHERE u.id = o.user_id) x'],
  ['values', 'SELECT * FROM (VALUES (1), (2)) v(x)'],
  ['distinct', 'SELECT DISTINCT email FROM users'],
  ['distinct on', 'SELECT DISTINCT ON (email) id FROM users'],
  ['order limit offset', 'SELECT id FROM users ORDER BY email DESC LIMIT 5 OFFSET 2'],
  // ORDER BY / GROUP BY resolve to output aliases before table columns (Postgres),
  // so a bare alias reference there is not a table-column read.
  ['order by output alias', 'SELECT id AS x FROM users ORDER BY x'],
  ['group by output alias', 'SELECT email AS e, count(*) FROM users GROUP BY e'],
  ['group+order by alias', 'SELECT age AS a, count(*) AS c FROM users GROUP BY a ORDER BY a'],
  ['alias shadows a non-selected column name', 'SELECT id AS email FROM users ORDER BY email'],
  ['case', 'SELECT CASE WHEN age > 18 THEN email END FROM users'],
  ['array', 'SELECT ARRAY[id, age] FROM users'],
  ['json build', "SELECT jsonb_build_object('e', email) FROM users"],
  ['row ctor', 'SELECT ROW(id, email) FROM users'],
  ['for update', 'SELECT id FROM users FOR UPDATE'],
  ['for update of alias', 'SELECT id FROM users u FOR UPDATE OF u'],
  ['for share of name', 'SELECT email FROM users FOR SHARE OF users'],
  ['tablesample', 'SELECT id FROM users TABLESAMPLE BERNOULLI (10)'],
  ['cast', 'SELECT age::text FROM users'],
  ['coalesce', 'SELECT coalesce(email, \'?\') FROM users'],
  ['insert values', "INSERT INTO notes (body) VALUES ('x')"],
  ['insert multi-row', "INSERT INTO notes (body) VALUES ('a'), ('b')"],
  ['insert select', 'INSERT INTO notes (body) SELECT email FROM users'],
  ['update', "UPDATE notes SET body = 'x' WHERE id = 1"],
  ['update returning', "UPDATE notes SET body = 'x' RETURNING id, body"],
  ['delete', 'DELETE FROM notes WHERE id = 1'],
]

const DENIED: [string, string][] = [
  ['forbidden col', 'SELECT password FROM users'],
  ['col in where', "SELECT id FROM users WHERE password = 'x'"],
  ['col via join qualified', 'SELECT u.password FROM users u JOIN orders o ON o.user_id = u.id'],
  ['col via join ambiguous', 'SELECT password FROM users JOIN orders ON true'],
  ['col via cross join', 'SELECT u.password FROM users u CROSS JOIN orders o'],
  ['scalar subquery col', 'SELECT (SELECT password FROM users LIMIT 1)'],
  ['in subquery col', 'SELECT id FROM orders WHERE user_id IN (SELECT password FROM users)'],
  ['exists col', "SELECT o.id FROM orders o WHERE EXISTS (SELECT 1 FROM users u WHERE u.password = 'x')"],
  ['cte col', 'WITH x AS (SELECT password FROM users) SELECT * FROM x'],
  ['union arm col', 'SELECT id FROM users UNION SELECT password FROM users'],
  ['intersect arm col', 'SELECT email FROM users INTERSECT SELECT password FROM users'],
  ['window partition col', 'SELECT id, row_number() OVER (PARTITION BY password) FROM users'],
  ['window order col', 'SELECT id, rank() OVER (ORDER BY password) FROM users'],
  ['agg arg col', 'SELECT max(password) FROM users'],
  ['agg filter col', 'SELECT count(*) FILTER (WHERE password IS NOT NULL) FROM users'],
  ['agg order col', 'SELECT array_agg(id ORDER BY password) FROM users'],
  ['distinct agg col', 'SELECT count(DISTINCT password) FROM users'],
  ['grouping sets col', 'SELECT count(*) FROM users GROUP BY GROUPING SETS ((email), (password))'],
  ['cube col', 'SELECT count(*) FROM users GROUP BY CUBE (email, password)'],
  ['rollup col', 'SELECT count(*) FROM users GROUP BY ROLLUP (password)'],
  ['lateral col', 'SELECT o.id FROM orders o, LATERAL (SELECT password FROM users u WHERE u.id = o.user_id) x'],
  ['distinct col', 'SELECT DISTINCT password FROM users'],
  ['distinct on col', 'SELECT DISTINCT ON (password) id FROM users'],
  ['order by col', 'SELECT id FROM users ORDER BY password LIMIT 5'],
  // a forbidden column nested in a GROUP BY / ORDER BY *expression* (not a bare
  // alias reference) is still a real read and must be denied.
  ['group by expr col', 'SELECT count(*) FROM users GROUP BY lower(password)'],
  ['order by expr col', 'SELECT id FROM users ORDER BY password || email'],
  ['case col', 'SELECT CASE WHEN password IS NULL THEN 1 ELSE 0 END FROM users'],
  ['cast col', 'SELECT password::text FROM users'],
  ['array col', 'SELECT ARRAY[id, password] FROM users'],
  ['json col', "SELECT jsonb_build_object('p', password) FROM users"],
  ['row ctor col', 'SELECT ROW(id, password) FROM users'],
  ['tablesample col', 'SELECT password FROM users TABLESAMPLE SYSTEM (10)'],
  ['whole-row composite', 'SELECT users FROM users'],
  ['whole-row to_jsonb', 'SELECT to_jsonb(t) FROM users t'],
  ['system column ctid', 'SELECT ctid FROM users'],
  ['locking does not bypass column check', 'SELECT password FROM users u FOR UPDATE OF u'],
  ['insert forbidden col', "INSERT INTO notes (secret) VALUES ('x')"],
  ['insert implicit cols', "INSERT INTO notes VALUES (1, 'x', 'y')"],
  ['insert select forbidden read', 'INSERT INTO notes (body) SELECT password FROM users'],
  ['update forbidden col', "UPDATE notes SET secret = 'x'"],
  ['update returning forbidden', "UPDATE notes SET body = 'x' RETURNING secret"],
  ['delete on no-perm table', 'DELETE FROM users'],
  // data-modifying CTEs are permission-checked like top-level writes
  ['dm-cte write forbidden col', "WITH u AS (UPDATE notes SET secret = 'x' RETURNING id) SELECT * FROM u"],
  ['dm-cte delete no-perm', 'WITH d AS (DELETE FROM users RETURNING id) SELECT * FROM d'],
  // forbidden column hidden in less-obvious expression positions
  ['returning subquery col', "UPDATE notes SET body = 'x' RETURNING (SELECT password FROM users LIMIT 1)"],
  ['srf in target with forbidden col', 'SELECT generate_series(1, 3), password FROM users'],
  ['multi-assign update forbidden col', "UPDATE notes SET (body, secret) = ('x', 'y')"],
  ['forbidden col through join alias', 'SELECT x.secret FROM (notes n JOIN orders o ON true) x'],
]

describe('feature coverage: permitted queries', () => {
  it.each(ALLOWED)('allows %s', async (_label, sql) => {
    const decision = await run(sql)
    expect(decision.allow, sql).toBe(true)
  })
})

describe('feature coverage: forbidden access is denied', () => {
  it.each(DENIED)('denies %s', async (_label, sql) => {
    const decision = await run(sql)
    expect(decision.allow, sql).toBe(false)
  })
})
