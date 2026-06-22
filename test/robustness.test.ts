import { describe, expect, it } from 'vitest'
import { analyze } from '../src/analyzer/index'
import { MemoryCatalog } from '../src/schema/memory-catalog'
import type { PermissionModel } from '../src/policy/model'

/**
 * Robustness sweep over exotic-but-valid SQL shapes. The analyzer must never throw
 * on a parseable statement (an unhandled AST shape would be a fail-open / DoS risk);
 * it returns a decision. The permitted set is broad so the rewriter runs deeply
 * (RLS wrap, `*` expansion, qualification). A second group confirms a forbidden
 * column is still denied even when buried in one of these constructs.
 */
const catalog = new MemoryCatalog({
  tables: { 'public.t': ['id', 'a', 'secret'], 'public.doc': ['id', 'data'], 'public.nums': ['n'] },
})
const model: PermissionModel = {
  tables: {
    'public.t': { select: { columns: ['id', 'a'] }, rls: { select: 'id > 0' } },
    'public.doc': { select: true },
    'public.nums': { select: true },
  },
}
const run = (sql: string) => analyze(sql, { model, catalog, context: { ctx: {} } })

const EXOTIC_OK: [string, string][] = [
  ['ROWS FROM', 'SELECT * FROM ROWS FROM (generate_series(1,3), generate_series(4,6)) AS x(a, b)'],
  ['WITH ORDINALITY', 'SELECT * FROM generate_series(1,3) WITH ORDINALITY AS g(v, ord)'],
  ['GROUPING SETS + CUBE', 'SELECT a, count(*) FROM t GROUP BY GROUPING SETS ((a), (), CUBE(a))'],
  ['nested named windows', 'SELECT id, sum(a) OVER w1, avg(a) OVER w2 FROM t WINDOW w1 AS (PARTITION BY a), w2 AS (w1 ORDER BY id)'],
  ['json_table', "SELECT * FROM json_table('[{}]'::json, '$[*]' COLUMNS (id int PATH '$.id')) jt"],
  ['xmltable', "SELECT x.* FROM doc, XMLTABLE('/r' PASSING data COLUMNS c text) AS x"],
  ['array slice', 'SELECT (ARRAY[1,2,3])[1:2] FROM nums'],
  ['row comparison', 'SELECT id FROM t WHERE (id, a) > (1, 2)'],
  ['nested CTE chain', 'WITH a AS (SELECT id FROM t), b AS (SELECT id FROM a), c AS (SELECT id FROM b) SELECT id FROM c'],
  ['recursive CTE', 'WITH RECURSIVE r(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM r WHERE n < 5) SELECT n FROM r'],
  ['correlated scalar subquery', 'SELECT id, (SELECT count(*) FROM doc d WHERE d.id = t.id) FROM t'],
  ['CASE with EXISTS', 'SELECT CASE WHEN EXISTS (SELECT 1 FROM doc) THEN a ELSE 0 END FROM t'],
  ['cast chain', 'SELECT a::text::varchar FROM t'],
  ['jsonb path ops', "SELECT data #>> '{a,b}' FROM doc WHERE data @? '$.x'"],
  ['multi-row VALUES', "SELECT * FROM (VALUES (1,'a'), (2,'b')) AS v(x, y)"],
  ['TABLESAMPLE REPEATABLE', 'SELECT id FROM t TABLESAMPLE SYSTEM (10) REPEATABLE (42)'],
  ['FILTER + WITHIN GROUP', 'SELECT count(DISTINCT a) FILTER (WHERE id > 0), percentile_cont(0.5) WITHIN GROUP (ORDER BY a) FROM t'],
  ['set-op chain', 'SELECT id FROM t UNION SELECT id FROM doc INTERSECT SELECT id FROM doc EXCEPT SELECT n FROM nums'],
  ['lateral chain', 'SELECT * FROM t, LATERAL (SELECT count(*) c FROM doc WHERE doc.id = t.id) x, LATERAL (SELECT x.c + 1) y'],
]

const EXOTIC_FORBIDDEN: [string, string][] = [
  ['window frame offset', 'SELECT sum(a) OVER (ORDER BY id ROWS secret PRECEDING) FROM t'],
  ['ROWS FROM arg subquery', 'SELECT * FROM ROWS FROM (generate_series(1, (SELECT secret FROM t LIMIT 1))) g'],
  ['lateral with forbidden', 'SELECT x.v FROM t, LATERAL (SELECT t.secret AS v) x'],
  ['cast of forbidden', 'SELECT secret::text FROM t'],
]

describe('analyzer never throws on exotic-but-valid SQL', () => {
  it.each(EXOTIC_OK)('handles %s', async (_l, sql) => {
    const d = await run(sql)
    expect(typeof d.allow, sql).toBe('boolean')
    expect(d.allow, sql).toBe(true)
  })
})

describe('forbidden column denied even inside exotic constructs', () => {
  it.each(EXOTIC_FORBIDDEN)('denies %s', async (_l, sql) => {
    expect((await run(sql)).allow, sql).toBe(false)
  })
})
