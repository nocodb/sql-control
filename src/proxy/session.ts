/**
 * Per-connection protocol handler. Covers the simple query protocol (`Query`)
 * and the extended protocol (`Parse`/`Bind`/`Describe`/`Execute`/`Sync`) used by
 * most drivers for parameterized statements.
 *
 * Authorization happens at `Parse` (the SQL is known there); on failure the
 * server replies with an error and skips to `Sync`, per the protocol. The result
 * shape is unknown until the backend runs, so `RowDescription` is emitted at
 * `Execute` — which matches the unnamed portal flow drivers use for ad-hoc
 * queries. (Pre-execution `Describe` of a named statement is not yet supported.)
 */
import { analyze } from '../analyzer/index'
import {
  backendError,
  handleQuery,
  rowLimitMessage,
  streamQuery,
  type Backend,
  type ResolvedPolicy,
  type StreamBackend,
  type StreamResult,
} from './handler'
import { bodyReader, WireFormatError, type ByteReader } from './reader'
import { SqlState, sqlStateForViolation } from './sqlstate'
import {
  bindComplete,
  closeComplete,
  commandComplete,
  concat,
  dataRow,
  errorResponse,
  parseComplete,
  readyForQuery,
  rowDescription,
} from './wire'

/** Frontend message type bytes. */
const Msg = {
  Query: 0x51, // 'Q'
  Parse: 0x50, // 'P'
  Bind: 0x42, // 'B'
  Describe: 0x44, // 'D'
  Execute: 0x45, // 'E'
  Sync: 0x53, // 'S'
  Close: 0x43, // 'C'
  Flush: 0x48, // 'H'
  FunctionCall: 0x46, // 'F' — legacy fast-path; invokes a function by OID with NO SQL
} as const

const EMPTY = new Uint8Array(0)

interface Prepared {
  sql: string
}
interface Portal {
  sql: string
  params: (string | null)[]
}

export class ProxySession {
  private readonly statements = new Map<string, Prepared>()
  private readonly portals = new Map<string, Portal>()
  /** After an error, frontend messages are ignored until the next `Sync`. */
  private skipUntilSync = false

  constructor(
    private readonly policy: () => ResolvedPolicy | null,
    private readonly backend: Backend,
    /** Optional streaming backend; when set, simple queries stream row-by-row
     *  (flat memory) instead of buffering the whole result. */
    private readonly streamBackend?: StreamBackend,
  ) {}

  /** Handle one frontend message; `undefined` defers to pg-gateway (e.g. Terminate).
   *  An `AsyncIterable` return streams chunks (pg-gateway writes them as they come). */
  async handle(data: Uint8Array): Promise<Uint8Array | AsyncIterable<Uint8Array> | undefined> {
    switch (data[0]) {
      case Msg.Query:
        return this.onQuery(data)
      case Msg.Parse:
        return this.onParse(data)
      case Msg.Bind:
        return this.onBind(data)
      case Msg.Describe:
        return EMPTY // RowDescription is emitted at Execute (once the shape is known)
      case Msg.Execute:
        return this.onExecute(data)
      case Msg.Sync:
        this.skipUntilSync = false
        return readyForQuery()
      case Msg.Close:
        return this.onClose(data)
      case Msg.Flush:
        return EMPTY
      case Msg.FunctionCall:
        return this.onFunctionCall()
      default:
        return undefined
    }
  }

  /**
   * The legacy fast-path `FunctionCall` ('F') invokes a function directly by OID,
   * carrying NO SQL — so it would bypass the analyzer entirely (authorization,
   * RLS, the function denylist). We never execute it: refuse loudly with our own
   * `SC` SQLSTATE. pg-gateway also rejects an unhandled message, but owning it here
   * makes the "no fast-path function calls" guarantee explicit, properly coded, and
   * independent of pg-gateway's default behaviour.
   */
  private onFunctionCall(): Uint8Array {
    return concat(
      errorResponse({
        code: SqlState.PolicyViolation,
        message: 'fast-path function-call protocol is not supported (use a SQL query)',
      }),
      readyForQuery(),
    )
  }

  private notAuthenticated(): Uint8Array {
    this.skipUntilSync = true
    return errorResponse({
      severity: 'FATAL',
      code: SqlState.NotAuthenticated,
      message: 'not authenticated',
    })
  }

  private async onQuery(data: Uint8Array): Promise<Uint8Array | AsyncIterable<Uint8Array>> {
    const policy = this.policy()
    if (!policy) return concat(this.notAuthenticated(), readyForQuery())
    const sql = bodyReader(data).cstring()
    // Stream the result row-by-row when a streaming backend is configured;
    // otherwise buffer (handleQuery). Both run the same authorize + rewrite.
    return this.streamBackend
      ? streamQuery(sql, policy, this.streamBackend)
      : handleQuery(sql, policy, this.backend)
  }

  private async onParse(data: Uint8Array): Promise<Uint8Array> {
    // Honor the post-error skip window like Bind/Execute: a Parse here must not
    // run analysis, store a statement, or emit a stray ParseComplete until Sync.
    if (this.skipUntilSync) return EMPTY
    const reader = bodyReader(data)
    const name = reader.cstring()
    const sql = reader.cstring()

    const policy = this.policy()
    if (!policy) return this.notAuthenticated()

    const decision = await analyze(sql, {
      model: policy.model,
      catalog: policy.catalog,
      context: policy.context,
      maxRows: policy.maxRows,
    })
    if (!decision.allow) {
      // Same `SC` SQLSTATE class the simple-query path uses, so a policy refusal at
      // Parse is distinguishable from a database error regardless of protocol.
      this.skipUntilSync = true
      return errorResponse({
        code: sqlStateForViolation(decision.violations[0]?.code),
        message: decision.violations.map((v) => v.message).join('; '),
      })
    }
    this.statements.set(name, { sql: decision.sql })
    return parseComplete()
  }

  private onBind(data: Uint8Array): Uint8Array {
    if (this.skipUntilSync) return EMPTY
    const reader = bodyReader(data)
    const portalName = reader.cstring()
    const statementName = reader.cstring()
    const statement = this.statements.get(statementName)
    if (!statement) {
      this.skipUntilSync = true
      return errorResponse({ code: '26000', message: `prepared statement "${statementName}" does not exist` })
    }
    // The parameter section is attacker-controlled length-prefixed data: a count
    // or length that overruns the buffer must surface as a protocol error, not an
    // uncaught RangeError that escapes the message loop and drops the connection.
    let params: (string | null)[]
    try {
      params = readParams(reader)
    } catch (err) {
      this.skipUntilSync = true
      const message = err instanceof WireFormatError ? err.message : 'malformed Bind message'
      return errorResponse({ code: '08P01', message })
    }
    this.portals.set(portalName, { sql: statement.sql, params })
    return bindComplete()
  }

  private async onExecute(data: Uint8Array): Promise<Uint8Array | AsyncIterable<Uint8Array>> {
    if (this.skipUntilSync) return EMPTY
    const reader = bodyReader(data)
    const portal = this.portals.get(reader.cstring())
    if (!portal) {
      this.skipUntilSync = true
      return errorResponse({ code: '34000', message: 'portal does not exist' })
    }
    // The Execute message also carries a max-row count (the driver's stream
    // batch size); we don't honor a per-batch portal suspend (that needs the
    // portal pinned to one backend connection across round-trips = affinity).
    // Instead, when a streaming backend is configured we stream the whole result
    // out incrementally in this one Execute response — which a cursor client
    // (pg-query-stream / knex .stream) consumes as a real stream via TCP
    // backpressure, at flat memory.
    const stream = this.streamBackend
    if (stream) return this.streamExecute(portal, stream)
    try {
      const result = await this.backend(portal.sql, portal.params)
      // Same row-cap guard as the simple-query path (the SELECT carries
      // `LIMIT maxRows + 1`): refuse an over-cap result rather than truncate.
      const maxRows = this.policy()?.maxRows
      if (maxRows !== undefined && result.rows.length > maxRows) {
        this.skipUntilSync = true
        return errorResponse({ code: '54000', message: rowLimitMessage(maxRows) })
      }
      const messages: Uint8Array[] = []
      if (result.fields.length > 0) {
        messages.push(rowDescription(result.fields))
        for (const row of result.rows) messages.push(dataRow(row))
      }
      messages.push(commandComplete(result.tag))
      return concat(...messages)
    } catch (err) {
      this.skipUntilSync = true
      return errorResponse(backendError(err, this.policy()?.exposeBackendErrors !== false))
    }
  }

  /**
   * Stream an extended-protocol portal's result: RowDescription, a DataRow per row
   * as it arrives, then CommandComplete — and crucially *no* ReadyForQuery (the
   * extended protocol emits that only on Sync). The `maxRows` cap is a running
   * counter that ends the stream with a loud 54000; abandoning the iterator runs
   * the generator's cleanup, closing the backend cursor.
   */
  private async *streamExecute(portal: Portal, stream: StreamBackend): AsyncGenerator<Uint8Array> {
    const maxRows = this.policy()?.maxRows
    let result: StreamResult
    try {
      result = await stream(portal.sql, portal.params)
    } catch (err) {
      this.skipUntilSync = true
      yield errorResponse(backendError(err, this.policy()?.exposeBackendErrors !== false))
      return
    }
    try {
      if (result.fields.length > 0) yield rowDescription(result.fields)
      let count = 0
      for await (const row of result.rows) {
        if (maxRows !== undefined && count >= maxRows) {
          this.skipUntilSync = true
          yield errorResponse({ code: '54000', message: rowLimitMessage(maxRows) })
          return
        }
        yield dataRow(row)
        count++
      }
      yield commandComplete(result.completed())
    } catch (err) {
      this.skipUntilSync = true
      yield errorResponse(backendError(err, this.policy()?.exposeBackendErrors !== false))
    }
  }

  /**
   * `Close` ('S' = prepared statement, 'P' = portal). Frees the named resource so
   * a later Execute/Bind correctly reports it gone (34000/26000) and an
   * authenticated client cannot grow the statement/portal maps without bound.
   */
  private onClose(data: Uint8Array): Uint8Array {
    if (this.skipUntilSync) return EMPTY
    let kind: number
    let name: string
    try {
      const reader = bodyReader(data)
      kind = reader.byte()
      name = reader.cstring()
    } catch (err) {
      this.skipUntilSync = true
      const message = err instanceof WireFormatError ? err.message : 'malformed Close message'
      return errorResponse({ code: '08P01', message })
    }
    const STATEMENT = 0x53 // 'S'
    if (kind === STATEMENT) this.statements.delete(name)
    else this.portals.delete(name)
    return closeComplete()
  }
}

/** Read the parameter values from a `Bind` message (text format assumed). */
function readParams(reader: ByteReader): (string | null)[] {
  const formatCount = reader.int16()
  for (let i = 0; i < formatCount; i++) reader.int16()
  const count = reader.int16()
  const params: (string | null)[] = []
  for (let i = 0; i < count; i++) {
    const length = reader.int32()
    params.push(length === -1 ? null : reader.bytes(length).toString('utf8'))
  }
  return params
}
