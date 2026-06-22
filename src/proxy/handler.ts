/**
 * The bridge between the wire protocol and the analyzer: take a SQL string from
 * a client, authorize and rewrite it, run the safe version against the backend,
 * and serialize the result (or a refusal) back into wire-protocol bytes.
 */
import { analyze } from '../analyzer/index'
import type { Catalog, RequestContext } from '../analyzer/types'
import type { PermissionModel } from '../policy/model'
import { sqlStateForViolation } from './sqlstate'
import {
  commandComplete,
  concat,
  dataRow,
  errorResponse,
  readyForQuery,
  rowDescription,
  type ErrorFields,
  type FieldInfo,
} from './wire'

/** Extract a Postgres SQLSTATE from a thrown backend error, if it carries one. */
function backendSqlState(err: unknown): string {
  if (err && typeof err === 'object' && 'code' in err && typeof err.code === 'string') {
    return err.code
  }
  return 'XX000'
}

/**
 * Shape a thrown backend error into the fields sent to the client. The real
 * Postgres SQLSTATE is always preserved (so a client can still discriminate error
 * *classes* — e.g. a unique-violation 23505 from a connection error 08006). The
 * message, however, can name columns/constraints/relations the client cannot
 * otherwise see — e.g. a `NOT NULL` violation reveals a hidden column's name, a
 * unique violation reveals an index name — so unless the deployment opts into
 * `exposeBackendErrors`, the text is withheld. Shared by the simple- and
 * extended-protocol paths so the policy is enforced uniformly.
 */
export function backendError(err: unknown, expose: boolean): ErrorFields {
  const code = backendSqlState(err)
  if (!expose) return { code, message: 'database error (message withheld by policy)' }
  return { code, message: err instanceof Error ? err.message : String(err) }
}

/** The result of running an authorized statement against the backend Postgres. */
export interface QueryResult {
  fields: readonly FieldInfo[]
  rows: readonly (string | null)[][]
  /** Full command tag, e.g. `SELECT 3`, `UPDATE 1`, `INSERT 0 2`. */
  tag: string
}

/**
 * Executes already-authorized SQL against the real database. `params` carries
 * bound values for parameterized (`$1`) statements from the extended protocol.
 */
export type Backend = (
  sql: string,
  params?: readonly (string | null)[],
) => Promise<QueryResult>

/**
 * A *streaming* backend: instead of buffering the whole result, it yields rows
 * lazily so the proxy can forward each `DataRow` to the client as it arrives —
 * flat memory regardless of result size. The deployment implements it with a
 * server-side cursor (e.g. `pg`'s `Cursor` / `pg-query-stream`) held for the
 * single query's duration (a per-query checkout, not session affinity). `fields`
 * is known up front; `completed()` returns the command tag after `rows` is drained.
 */
export interface StreamResult {
  fields: readonly FieldInfo[]
  rows: AsyncIterable<readonly (string | null)[]>
  completed(): string
}
export type StreamBackend = (
  sql: string,
  params?: readonly (string | null)[],
) => Promise<StreamResult>

/** Everything a single connection needs to authorize a statement. */
export interface ResolvedPolicy {
  model: PermissionModel
  catalog?: Catalog
  context?: RequestContext
  /** Cap the rows a single statement may return (memory-DoS guard). A SELECT gets
   *  a top-level `LIMIT maxRows + 1`; a result that exceeds `maxRows` is refused
   *  (loud) rather than silently truncated. Recommended alongside a backend
   *  `statement_timeout` (set on the backend role) to also bound execution time. */
  maxRows?: number
  /** Forward raw backend error *messages* to the client (default `true`). A raw
   *  message can disclose schema the client can't otherwise see — a `NOT NULL`
   *  violation names a hidden column, a unique violation names an index. Set
   *  `false` for untrusted/multi-tenant deployments: the real SQLSTATE is still
   *  sent (error classes stay distinguishable) but the message text is withheld. */
  exposeBackendErrors?: boolean
}

/** SQLSTATE for an over-cap result (Postgres class 54 — program_limit_exceeded). */
export const ROW_LIMIT_EXCEEDED = '54000'

/** Whether a result blew past the configured cap (a SELECT gets `LIMIT maxRows+1`,
 *  so `maxRows + 1` rows means it was truncated; DML RETURNING is bounded here too). */
export function exceedsRowLimit(rowCount: number, maxRows: number | undefined): boolean {
  return maxRows !== undefined && rowCount > maxRows
}

/** The over-cap refusal message (shared by simple + extended protocol). */
export function rowLimitMessage(maxRows: number): string {
  return `result set exceeds the ${maxRows}-row limit; add a LIMIT clause or narrow the query`
}

/**
 * Handle one simple-query message and return the bytes to send to the client.
 * A denied statement never reaches the backend; a backend error is surfaced as
 * an `ErrorResponse`. Always terminates with `ReadyForQuery`.
 */
export async function handleQuery(
  sql: string,
  policy: ResolvedPolicy,
  backend: Backend,
): Promise<Uint8Array> {
  const decision = await analyze(sql, {
    model: policy.model,
    catalog: policy.catalog,
    context: policy.context,
    maxRows: policy.maxRows,
  })

  if (!decision.allow) {
    // sql-control's own error — stamped with the `SC` SQLSTATE class so clients
    // can tell a policy refusal from a database error (see `isSqlControlError`).
    const message = decision.violations.map((v) => v.message).join('; ')
    const code = sqlStateForViolation(decision.violations[0]?.code)
    return concat(errorResponse({ code, message }), readyForQuery())
  }

  let result: QueryResult
  try {
    result = await backend(decision.sql)
  } catch (err) {
    // A genuine database error — keep its real Postgres SQLSTATE; withhold the
    // message unless the deployment opts into exposing it.
    return concat(
      errorResponse(backendError(err, policy.exposeBackendErrors !== false)),
      readyForQuery(),
    )
  }

  // The SELECT was capped at `LIMIT maxRows + 1`; an over-cap result is refused
  // (loud) rather than silently returning a short answer.
  if (exceedsRowLimit(result.rows.length, policy.maxRows)) {
    return concat(
      errorResponse({ code: ROW_LIMIT_EXCEEDED, message: rowLimitMessage(policy.maxRows ?? 0) }),
      readyForQuery(),
    )
  }

  const messages: Uint8Array[] = []
  if (result.fields.length > 0) {
    messages.push(rowDescription(result.fields))
    for (const row of result.rows) messages.push(dataRow(row))
  }
  messages.push(commandComplete(result.tag), readyForQuery())
  return concat(...messages)
}

/**
 * Streaming counterpart of {@link handleQuery}: authorize the statement, then
 * yield wire chunks — `RowDescription`, a `DataRow` per row *as it arrives* from
 * the streaming backend, then `CommandComplete` + `ReadyForQuery`. pg-gateway
 * writes each chunk (handling TLS + backpressure), so memory stays flat for an
 * arbitrarily large result. The `maxRows` cap still applies: once it is exceeded
 * the stream stops with a loud `54000` (the rows already sent can't be unsent, so
 * the client gets a clear truncation error rather than a wrong "complete").
 */
export async function* streamQuery(
  sql: string,
  policy: ResolvedPolicy,
  stream: StreamBackend,
): AsyncGenerator<Uint8Array> {
  const decision = await analyze(sql, {
    model: policy.model,
    catalog: policy.catalog,
    context: policy.context,
    maxRows: policy.maxRows,
  })
  if (!decision.allow) {
    const message = decision.violations.map((v) => v.message).join('; ')
    yield errorResponse({ code: sqlStateForViolation(decision.violations[0]?.code), message })
    yield readyForQuery()
    return
  }

  let result: StreamResult
  try {
    result = await stream(decision.sql)
  } catch (err) {
    yield errorResponse(backendError(err, policy.exposeBackendErrors !== false))
    yield readyForQuery()
    return
  }

  try {
    if (result.fields.length > 0) yield rowDescription(result.fields)
    let count = 0
    for await (const row of result.rows) {
      if (policy.maxRows !== undefined && count >= policy.maxRows) {
        yield errorResponse({ code: ROW_LIMIT_EXCEEDED, message: rowLimitMessage(policy.maxRows) })
        yield readyForQuery()
        return // generator return() propagates to the backend iterator → cursor closed
      }
      yield dataRow(row)
      count++
    }
    yield commandComplete(result.completed())
    yield readyForQuery()
  } catch (err) {
    yield errorResponse(backendError(err, policy.exposeBackendErrors !== false))
    yield readyForQuery()
  }
}
