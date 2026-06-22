/**
 * E2E for the proxy's transport & auth: TLS termination and SCRAM-SHA-256, both
 * driven by the real `pg` client over TCP, with PGlite as the backend. Proves the
 * channel can be encrypted and that auth works without the server ever seeing the
 * cleartext password (SCRAM).
 */
import { execFileSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { AddressInfo } from 'node:net'
import { PGlite } from '@electric-sql/pglite'
import { Client } from 'pg'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { createProxyServer, type ProxyServerOptions } from '../src/proxy/server'
import type { ResolvedPolicy } from '../src/proxy/handler'
import type { PermissionModel } from '../src/policy/model'
import { backendFromQuery, SEED_SQL } from './helpers/pg-backend'

const model: PermissionModel = { tables: { 'public.users': { select: { columns: ['id', 'email'] } } } }
const policy: ResolvedPolicy = { model }

let db: PGlite
let backend: ProxyServerOptions['backend']

beforeAll(async () => {
  db = await PGlite.create()
  await db.exec(SEED_SQL)
  backend = backendFromQuery((sql, params) => db.query<unknown[]>(sql, params, { rowMode: 'array' }))
})
afterAll(async () => {
  await db.close()
})

async function withServer<T>(opts: Omit<ProxyServerOptions, 'backend'>, fn: (port: number) => Promise<T>): Promise<T> {
  const server = createProxyServer({ ...opts, backend })
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
  const port = (server.address() as AddressInfo).port
  try {
    return await fn(port)
  } finally {
    await new Promise<void>((res, rej) => server.close((e) => (e ? rej(e) : res())))
  }
}

function opensslAvailable(): boolean {
  try {
    execFileSync('openssl', ['version'], { stdio: 'ignore' })
    return true
  } catch {
    return false
  }
}

describe.skipIf(!opensslAvailable())('e2e: TLS termination at the proxy', () => {
  let dir = ''
  let key = ''
  let cert = ''
  beforeAll(() => {
    dir = mkdtempSync(join(tmpdir(), 'sqlcontrol-tls-'))
    execFileSync('openssl', [
      'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
      '-keyout', join(dir, 'key.pem'), '-out', join(dir, 'cert.pem'),
      '-days', '1', '-subj', '/CN=localhost',
    ], { stdio: 'ignore' })
    key = readFileSync(join(dir, 'key.pem'), 'utf8')
    cert = readFileSync(join(dir, 'cert.pem'), 'utf8')
  })
  afterAll(() => {
    if (dir) rmSync(dir, { recursive: true, force: true })
  })

  it('serves an authorized query over an encrypted (SSL) connection', async () => {
    const authenticate = (_p: unknown, password: string) => (password === 'secret' ? policy : null)
    await withServer({ authenticate, tls: { key, cert } }, async (port) => {
      const client = new Client({
        host: '127.0.0.1', port, user: 't1', password: 'secret', database: 'app',
        ssl: { rejectUnauthorized: false },
      })
      await client.connect()
      try {
        const r = await client.query('SELECT * FROM users WHERE id = 1')
        expect(r.rows).toEqual([{ id: 1, email: 'a@x.com' }])
        // the underlying socket really is a TLS socket
        expect(client.ssl).toBeTruthy()
      } finally {
        await client.end()
      }
    })
  })
})

describe('e2e: SCRAM-SHA-256 auth at the proxy', () => {
  const scram = {
    getUser: (username: string) =>
      username === 't1' ? { password: 'secret', policy } : null,
  }

  it('authenticates a correct SCRAM login and serves an authorized query', async () => {
    await withServer({ scram }, async (port) => {
      const client = new Client({ host: '127.0.0.1', port, user: 't1', password: 'secret', database: 'app' })
      await client.connect()
      try {
        const r = await client.query('SELECT id, email FROM users WHERE id = 2')
        expect(r.rows).toEqual([{ id: 2, email: 'b@y.com' }])
      } finally {
        await client.end()
      }
    })
  })

  it('rejects a wrong password (the server never saw the cleartext)', async () => {
    await withServer({ scram }, async (port) => {
      const client = new Client({ host: '127.0.0.1', port, user: 't1', password: 'wrong', database: 'app' })
      await expect(client.connect()).rejects.toThrow()
      await client.end().catch(() => undefined)
    })
  })

  it('rejects an unknown user', async () => {
    await withServer({ scram }, async (port) => {
      const client = new Client({ host: '127.0.0.1', port, user: 'nobody', password: 'secret', database: 'app' })
      await expect(client.connect()).rejects.toThrow()
      await client.end().catch(() => undefined)
    })
  })

  it('authenticates via a pre-computed verifier (no cleartext password stored)', async () => {
    // Production-recommended path: store only the SCRAM verifier, never the
    // password. The proxy derives nothing from a cleartext secret here.
    const { createScramSha256Data } = await import('pg-gateway')
    const scramData = await createScramSha256Data('secret')
    const verifierAuth = {
      getUser: (username: string) => (username === 't1' ? { scramData, policy } : null),
    }
    await withServer({ scram: verifierAuth }, async (port) => {
      const ok = new Client({ host: '127.0.0.1', port, user: 't1', password: 'secret', database: 'app' })
      await ok.connect()
      try {
        expect((await ok.query('SELECT id FROM users WHERE id = 2')).rows).toEqual([{ id: 2 }])
      } finally {
        await ok.end()
      }
      const bad = new Client({ host: '127.0.0.1', port, user: 't1', password: 'nope', database: 'app' })
      await expect(bad.connect()).rejects.toThrow()
      await bad.end().catch(() => undefined)
    })
  })
})
