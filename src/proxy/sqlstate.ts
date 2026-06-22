/**
 * SQLSTATE codes sql-control emits for its *own* errors — policy refusals, failed
 * rewrites, authentication — under the custom class `SC`, which Postgres never
 * uses. This lets a client tell an sql-control error from a database error: the
 * proxy stamps these on its `ErrorResponse`s, while genuine backend errors keep
 * their real Postgres SQLSTATE. Use {@link isSqlControlError} to discriminate.
 */
import { ViolationCode } from '../analyzer/errors'

/** The SQLSTATE class (first two chars) sql-control stamps on its own errors. */
export const SQL_CONTROL_SQLSTATE_CLASS = 'SC'

/** SQLSTATE codes for errors that originate in sql-control, not the database. */
export enum SqlState {
  /** The statement was refused by policy (not permitted / visible / readable). */
  PolicyViolation = 'SC001',
  /** A required rewrite (e.g. `*` expansion, RLS) could not be applied safely. */
  RewriteFailed = 'SC002',
  /** The connection is not authenticated. */
  NotAuthenticated = 'SC003',
}

/**
 * Whether a SQLSTATE was produced by sql-control rather than the backend
 * database — i.e. the error is a policy/authorization error, not a real DB error.
 */
export function isSqlControlError(sqlState: string): boolean {
  return sqlState.startsWith(SQL_CONTROL_SQLSTATE_CLASS)
}

/** Map a refused statement's first violation to the SQLSTATE the proxy sends. */
export function sqlStateForViolation(code: ViolationCode | undefined): SqlState {
  return code === ViolationCode.RewriteFailed ? SqlState.RewriteFailed : SqlState.PolicyViolation
}
