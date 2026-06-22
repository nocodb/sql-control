/** A cursor over a frontend message buffer for parsing wire fields. */
import { Buffer } from 'node:buffer'

/**
 * A frontend message was truncated or claimed a field length the buffer can't
 * satisfy. Raised instead of a raw `RangeError` so the protocol handler can
 * recognise a malformed message and reply with a protocol-violation error
 * rather than letting the exception escape and tear down the connection.
 */
export class WireFormatError extends Error {}

export class ByteReader {
  private offset: number

  constructor(
    private readonly buf: Buffer,
    start = 0,
  ) {
    this.offset = start
  }

  /** Ensure `count` more bytes are available, else fail as a wire-format error. */
  private need(count: number): void {
    if (count < 0 || this.offset + count > this.buf.length) {
      throw new WireFormatError(
        `malformed message: need ${count} byte(s) at offset ${this.offset} of ${this.buf.length}`,
      )
    }
  }

  byte(): number {
    const value = this.buf[this.offset] ?? 0
    this.offset += 1
    return value
  }

  int16(): number {
    this.need(2)
    const value = this.buf.readInt16BE(this.offset)
    this.offset += 2
    return value
  }

  int32(): number {
    this.need(4)
    const value = this.buf.readInt32BE(this.offset)
    this.offset += 4
    return value
  }

  /** Read a null-terminated string. */
  cstring(): string {
    const end = this.buf.indexOf(0, this.offset)
    const stop = end === -1 ? this.buf.length : end
    const value = this.buf.subarray(this.offset, stop).toString('utf8')
    this.offset = stop + 1
    return value
  }

  /** Read `length` raw bytes (the caller has already handled the -1 NULL sentinel). */
  bytes(length: number): Buffer {
    this.need(length)
    const value = this.buf.subarray(this.offset, this.offset + length)
    this.offset += length
    return value
  }
}

/** A reader positioned just past a message's type byte and Int32 length header. */
export function bodyReader(data: Uint8Array): ByteReader {
  return new ByteReader(Buffer.from(data), 5)
}
