/**
 * Fuzzing the wire-protocol handler: a malformed/garbage frontend message must
 * NEVER throw an unhandled exception (that would tear down the connection — a DoS).
 * ProxySession.handle must always resolve to bytes or undefined. Deterministic
 * (seeded). Crank with FUZZ_ITERS=50000.
 */
import { Buffer } from 'node:buffer'
import { describe, expect, it } from 'vitest'
import { ProxySession } from '../src/proxy/session'
import type { Backend, ResolvedPolicy } from '../src/proxy/handler'
import type { PermissionModel } from '../src/policy/model'

function mulberry32(seed: number): () => number {
  return () => {
    seed = (seed + 0x6d2b79f5) | 0
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed)
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}
const ITERS = Number(process.env.FUZZ_ITERS ?? 4000)

const model: PermissionModel = { tables: { 'public.users': { select: { columns: ['id', 'email'] } } } }
const policy: ResolvedPolicy = { model, context: { ctx: {} } }
const backend: Backend = async () => ({ fields: [{ name: 'id' }], rows: [['1']], tag: 'SELECT 1' })

// frontend message type bytes the session branches on, plus some it defers
const TYPES = [0x51, 0x50, 0x42, 0x44, 0x45, 0x53, 0x43, 0x48, 0x46, 0x00, 0x5a, 0xff] // Q P B D E S C H F, junk

function randomBytes(n: number, rnd: () => number): Buffer {
  const b = Buffer.alloc(n)
  for (let i = 0; i < n; i++) b[i] = Math.floor(rnd() * 256)
  return b
}

/** A frame with a real-ish type byte + (often wrong) length header + random body. */
function randomFrame(rnd: () => number): Buffer {
  const type = TYPES[Math.floor(rnd() * TYPES.length)]!
  const bodyLen = Math.floor(rnd() * 40)
  const body = randomBytes(bodyLen, rnd)
  const claimedLen = rnd() < 0.5 ? body.length + 4 : Math.floor(rnd() * 80) // sometimes a lying length
  const head = Buffer.alloc(5)
  head[0] = type
  head.writeInt32BE(claimedLen, 1)
  return Buffer.concat([head, body])
}

describe('fuzz: wire-protocol robustness', () => {
  it('never throws on random byte buffers', async () => {
    const rnd = mulberry32(0xfeed)
    const session = new ProxySession(() => policy, backend)
    const failures: string[] = []
    for (let i = 0; i < ITERS; i++) {
      const data = randomBytes(Math.floor(rnd() * 64), rnd)
      try {
        const out = await session.handle(data)
        if (out !== undefined && !(out instanceof Uint8Array)) failures.push(`bad return @${i}`)
      } catch (e) {
        failures.push(`THREW @${i} on ${data.toString('hex').slice(0, 24)}: ${(e as Error).message}`)
      }
    }
    expect(failures.slice(0, 8)).toEqual([])
    expect(failures.length).toBe(0)
  })

  it('never throws on malformed framed messages (lying lengths, truncated bodies)', async () => {
    const rnd = mulberry32(0xdecade)
    const session = new ProxySession(() => policy, backend)
    const failures: string[] = []
    for (let i = 0; i < ITERS; i++) {
      const data = randomFrame(rnd)
      try {
        await session.handle(data)
      } catch (e) {
        failures.push(`THREW @${i} type=0x${data[0]?.toString(16)}: ${(e as Error).message}`)
      }
    }
    expect(failures.slice(0, 8)).toEqual([])
    expect(failures.length).toBe(0)
  })

  it('never throws on a realistic but corrupted Parse/Bind/Execute sequence', async () => {
    const rnd = mulberry32(0xabcdef)
    const failures: string[] = []
    for (let i = 0; i < Math.min(ITERS, 1500); i++) {
      const session = new ProxySession(() => policy, backend)
      // a Parse with random SQL bytes, a Bind claiming a random param count, an Execute
      const cstr = (s: string) => Buffer.concat([Buffer.from(s, 'utf8'), Buffer.from([0])])
      const frame = (t: string, body: Buffer) => {
        const h = Buffer.alloc(5)
        h[0] = t.charCodeAt(0)
        h.writeInt32BE(body.length + 4, 1)
        return Buffer.concat([h, body])
      }
      const sql = randomBytes(Math.floor(rnd() * 30), rnd).toString('latin1')
      const i16 = (n: number) => {
        const b = Buffer.alloc(2)
        b.writeInt16BE(n & 0xffff)
        return b
      }
      const seq = [
        frame('P', Buffer.concat([cstr('s'), cstr(sql), i16(0)])),
        frame('B', Buffer.concat([cstr(''), cstr('s'), i16(0), i16(Math.floor(rnd() * 5))])), // claims params, gives none
        frame('E', Buffer.concat([cstr(''), Buffer.alloc(4)])),
        frame('S', Buffer.alloc(0)),
      ]
      try {
        for (const f of seq) await session.handle(f)
      } catch (e) {
        failures.push(`THREW @${i}: ${(e as Error).message}`)
      }
    }
    expect(failures.slice(0, 8)).toEqual([])
    expect(failures.length).toBe(0)
  })
})
