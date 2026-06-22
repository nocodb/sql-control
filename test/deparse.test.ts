import { deparse, parse } from 'pgsql-parser'
import { describe, expect, it } from 'vitest'
import { analyze } from '../src/analyzer/index'
import { MemoryCatalog } from '../src/schema/memory-catalog'
import type { PermissionModel } from '../src/policy/model'

/**
 * Deparse fidelity: we analyze the original parse but forward the deparsed
 * (rewritten) SQL, so deparse must preserve meaning — operator precedence and
 * identifier quoting in particular.
 */
const FIDELITY_CASES = [
  'SELECT a FROM t WHERE x = 1 OR y = 2 AND z = 3', // mixed AND/OR precedence
  'SELECT a FROM t WHERE (x = 1 OR y = 2) AND z = 3',
  'SELECT a FROM t1 JOIN t2 ON t1.id = t2.id WHERE t1.x > 0 OR t2.y < 0',
  'WITH c AS (SELECT a FROM t WHERE p OR q) SELECT * FROM c',
  'UPDATE t SET a = 1 WHERE x = 1 OR y = 2',
  'SELECT a FROM t WHERE a IN (1, 2, 3) AND b = ANY(ARRAY[1, 2])',
  'SELECT "select", "from" FROM "group" WHERE "order" = 1', // quoted keyword identifiers
  'SELECT NOT (a AND b) OR c FROM t',
]

describe('deparse round-trip fidelity', () => {
  it.each(FIDELITY_CASES)('reaches a stable fixed point: %s', async (sql) => {
    const once = await deparse(await parse(sql))
    const twice = await deparse(await parse(once)) // must re-parse without error
    expect(twice).toBe(once)
  })
})

describe('rewrites quote identifiers that are keywords', () => {
  it('emits a quoted column name when expanding `*`', async () => {
    const model: PermissionModel = {
      tables: { 'public.t': { select: { columns: ['id', 'order'] } } }, // "order" is a keyword
    }
    const catalog = new MemoryCatalog({ tables: { 'public.t': ['id', 'order', 'secret'] } })
    const d = await analyze('SELECT * FROM t', { model, catalog })
    expect(d.allow).toBe(true)
    if (d.allow) {
      expect(d.sql).not.toMatch(/secret/)
      // forwarded SQL must re-parse cleanly (i.e. "order" was quoted)
      await expect(parse(d.sql)).resolves.toBeDefined()
    }
  })
})
