/**
 * Result-size guard: cap how many rows a SELECT can return so a permitted but
 * unbounded query (`SELECT * FROM huge_table`) cannot exhaust proxy/backend
 * memory. The cap is injected as the statement's own top-level `LIMIT`
 * (`maxRows + 1`), so ORDER BY is honored and the limit can't be flattened away —
 * and the extra `+1` lets the handler detect truncation and fail *loud* (an
 * error) rather than silently returning a short result. Only SELECT is capped
 * (LIMIT is not valid on INSERT/UPDATE/DELETE); their RETURNING size is bounded by
 * the handler's row-count check instead.
 */
import type { ParseResult } from '../analyzer/nodes'
import type { Node as PgNode } from '@pgsql/types'
import { constNode, view } from './build'

export function applyRowLimit(parsed: ParseResult, maxRows: number): boolean {
  if (!Number.isInteger(maxRows) || maxRows < 0) return false
  const stmt: PgNode | undefined = parsed.stmts?.[0]?.stmt
  const sel = view(stmt)?.SelectStmt
  if (!sel) return false // only SELECT / set-ops carry a top-level LIMIT
  const cap = maxRows + 1

  const existing = sel.limitCount
  if (existing === undefined || existing === null) {
    sel.limitCount = constNode(cap)
    sel.limitOption = 'LIMIT_OPTION_COUNT'
    return true
  }
  // Cap an existing *literal* limit so a client can't raise it past the guard.
  // A non-literal limit (a parameter/expression) is left as the client's intent.
  const literal = view(existing)?.A_Const?.ival?.ival
  if (typeof literal === 'number' && literal > cap) {
    sel.limitCount = constNode(cap)
    return true
  }
  return false
}
