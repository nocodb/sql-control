import { describe, expect, it } from 'vitest'
import { analyze } from '../src/analyzer/index'
import { ViolationCode } from '../src/analyzer/errors'
import { DANGEROUS_FUNCTIONS } from '../src/policy/functions'
import type { PermissionModel } from '../src/policy/model'

/**
 * Position-independence of the function gate: a dangerous function must be denied
 * no matter where it appears, since the collector walks the whole AST. Each of the
 * DANGEROUS_FUNCTIONS is exercised in the target list, a WHERE predicate, and a
 * FROM table-function position (three distinct grammar paths). Generated from the
 * real set so new entries are covered automatically.
 */
const model: PermissionModel = { tables: { 'public.users': { select: { columns: ['id'] } } } }
const code = async (sql: string): Promise<ViolationCode | undefined> => {
  const d = await analyze(sql, { model, context: { ctx: {} } })
  return d.allow ? undefined : d.violations[0]?.code
}

const POSITIONS: [string, (fn: string) => string][] = [
  ['target list', (fn) => `SELECT ${fn}(NULL)`],
  ['WHERE predicate', (fn) => `SELECT id FROM users WHERE ${fn}(NULL) IS NOT NULL`],
  ['FROM table-function', (fn) => `SELECT * FROM ${fn}(NULL)`],
]

for (const [posLabel, build] of POSITIONS) {
  describe(`dangerous functions denied in ${posLabel}`, () => {
    const cases: [string, string][] = [...DANGEROUS_FUNCTIONS].map((fn) => [fn, build(fn)])
    it.each(cases)('denies %s', async (_fn, sql) => {
      expect(await code(sql)).toBe(ViolationCode.FunctionNotAllowed)
    })
  })
}
