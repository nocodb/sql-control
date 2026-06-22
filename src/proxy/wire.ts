/**
 * Minimal Postgres backend (server→client) message serializers for the simple
 * query protocol. Each message is a 1-byte type, an Int32 length (including
 * itself), then the body. Field values use the text format.
 *
 * @see https://www.postgresql.org/docs/current/protocol-message-formats.html
 */
import { Buffer } from 'node:buffer'

/** A result column descriptor. */
export interface FieldInfo {
  name: string
  /** Postgres type OID; defaults to `text` (25) when omitted. */
  dataTypeID?: number
}

const TEXT_OID = 25

function cstr(value: string): Buffer {
  return Buffer.concat([Buffer.from(value, 'utf8'), Buffer.from([0])])
}

function int16(value: number): Buffer {
  const b = Buffer.alloc(2)
  b.writeInt16BE(value)
  return b
}

function int32(value: number): Buffer {
  const b = Buffer.alloc(4)
  b.writeInt32BE(value)
  return b
}

/** Frame a message body with its type byte and length prefix. */
function frame(type: string, body: Buffer): Uint8Array {
  return Buffer.concat([Buffer.from(type, 'ascii'), int32(body.length + 4), body])
}

/** `RowDescription` (`T`): the columns of a result set. */
export function rowDescription(fields: readonly FieldInfo[]): Uint8Array {
  const parts: Buffer[] = [int16(fields.length)]
  for (const field of fields) {
    parts.push(
      cstr(field.name),
      int32(0), // table OID
      int16(0), // column attribute number
      int32(field.dataTypeID ?? TEXT_OID),
      int16(-1), // type size (variable)
      int32(-1), // type modifier
      int16(0), // text format
    )
  }
  return frame('T', Buffer.concat(parts))
}

/** `DataRow` (`D`): one result row; `null` encodes a SQL NULL. */
export function dataRow(values: readonly (string | null)[]): Uint8Array {
  const parts: Buffer[] = [int16(values.length)]
  for (const value of values) {
    if (value === null) {
      parts.push(int32(-1))
    } else {
      const bytes = Buffer.from(value, 'utf8')
      parts.push(int32(bytes.length), bytes)
    }
  }
  return frame('D', Buffer.concat(parts))
}

/** `CommandComplete` (`C`): the command tag, e.g. `SELECT 3` or `UPDATE 1`. */
export function commandComplete(tag: string): Uint8Array {
  return frame('C', cstr(tag))
}

export interface ErrorFields {
  severity?: 'ERROR' | 'FATAL'
  /** SQLSTATE code; defaults to `42501` (insufficient privilege). */
  code?: string
  message: string
}

/** `ErrorResponse` (`E`). */
export function errorResponse({ severity = 'ERROR', code = '42501', message }: ErrorFields): Uint8Array {
  const field = (tag: string, value: string): Buffer =>
    Buffer.concat([Buffer.from(tag, 'ascii'), cstr(value)])
  const body = Buffer.concat([
    field('S', severity),
    field('V', severity),
    field('C', code),
    field('M', message),
    Buffer.from([0]),
  ])
  return frame('E', body)
}

/** `ReadyForQuery` (`Z`): `I` idle, `T` in-transaction, `E` failed transaction. */
export function readyForQuery(status: 'I' | 'T' | 'E' = 'I'): Uint8Array {
  return frame('Z', Buffer.from(status, 'ascii'))
}

/** `ParseComplete` (`1`). */
export function parseComplete(): Uint8Array {
  return frame('1', Buffer.alloc(0))
}

/** `BindComplete` (`2`). */
export function bindComplete(): Uint8Array {
  return frame('2', Buffer.alloc(0))
}

/** `CloseComplete` (`3`). */
export function closeComplete(): Uint8Array {
  return frame('3', Buffer.alloc(0))
}

/** Concatenate a sequence of wire messages into one buffer. */
export function concat(...messages: readonly Uint8Array[]): Uint8Array {
  return Buffer.concat(messages.map((m) => Buffer.from(m)))
}
