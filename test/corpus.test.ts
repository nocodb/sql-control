import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import { analyze } from '../src/analyzer/index'
import { ViolationCode } from '../src/analyzer/errors'
import type { PermissionModel } from '../src/policy/model'

/**
 * Corpus-driven robustness tests. The fixtures are mined from the Postgres
 * regression suite by `scripts/build-corpus.ts`; regenerate with
 * `PG_DIR=../postgres node scripts/build-corpus.ts`.
 */
interface Entry {
  sql: string
  type: string
  file: string
}

const corpus: Entry[] = JSON.parse(
  readFileSync(new URL('./corpus/statements.json', import.meta.url), 'utf8'),
)

const DML = new Set(['SelectStmt', 'InsertStmt', 'UpdateStmt', 'DeleteStmt'])
const nonDml = corpus.filter((e) => !DML.has(e.type))
const dml = corpus.filter((e) => DML.has(e.type))

// Empty model: relations resolve to "not visible", which is fine here — these
// tests assert structural properties (blocked vs. doesn't-crash), not access.
const model: PermissionModel = { tables: {} }

describe('postgres regression corpus', () => {
  it('loaded a large corpus', () => {
    expect(corpus.length).toBeGreaterThan(10_000)
    expect(nonDml.length).toBeGreaterThan(1_000)
    expect(dml.length).toBeGreaterThan(1_000)
  })

  it(`blocks every non-DML statement (${nonDml.length}) with STATEMENT_NOT_ALLOWED`, async () => {
    const failures: { type: string; got: string; sql: string }[] = []
    for (const entry of nonDml) {
      let got: string
      try {
        const decision = await analyze(entry.sql, { model })
        got = decision.allow ? 'ALLOWED' : (decision.violations[0]?.code ?? 'NO_CODE')
      } catch (err) {
        got = `THREW: ${(err as Error).message}`
      }
      if (got !== ViolationCode.StatementNotAllowed) {
        failures.push({ type: entry.type, got, sql: entry.sql.slice(0, 100) })
      }
    }
    expect(failures.slice(0, 15)).toEqual([])
    expect(failures.length).toBe(0)
  }, 180_000)

  it(`analyzes every DML statement (${dml.length}) without throwing`, async () => {
    const throwers: { type: string; err: string; sql: string }[] = []
    for (const entry of dml) {
      try {
        const decision = await analyze(entry.sql, { model })
        if (typeof decision.allow !== 'boolean') {
          throwers.push({ type: entry.type, err: 'no decision', sql: entry.sql.slice(0, 100) })
        }
      } catch (err) {
        throwers.push({ type: entry.type, err: (err as Error).message, sql: entry.sql.slice(0, 100) })
      }
    }
    expect(throwers.slice(0, 15)).toEqual([])
    expect(throwers.length).toBe(0)
  }, 180_000)
})
