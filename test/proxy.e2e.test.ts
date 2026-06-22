import type { AddressInfo } from 'node:net'
import { Client } from 'pg'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import type { Backend, ResolvedPolicy } from '../src/proxy/handler'
import { createProxyServer } from '../src/proxy/server'
import type { ClientParameters } from 'pg-gateway'

const model = { tables: { 'public.users': { select: { columns: ['id', 'email'] } } } }

let lastSql = ''
let lastParams: readonly (string | null)[] | undefined
const backend: Backend = async (sql, params) => {
  lastSql = sql
  lastParams = params
  return {
    fields: [{ name: 'id' }, { name: 'email' }],
    rows: [
      ['1', 'a@x'],
      ['2', 'b@y'],
    ],
    tag: 'SELECT 2',
  }
}

const authenticate = (_params: ClientParameters, password: string): ResolvedPolicy | null =>
  password === 'secret' ? { model } : null

const server = createProxyServer({ authenticate, backend })
let port = 0

beforeAll(async () => {
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
  port = (server.address() as AddressInfo).port
})
afterAll(async () => {
  await new Promise<void>((resolve, reject) =>
    server.close((err) => (err ? reject(err) : resolve())),
  )
})

async function connect(password = 'secret'): Promise<Client> {
  const client = new Client({ host: '127.0.0.1', port, user: 'tenant', password, database: 'app' })
  await client.connect()
  return client
}

describe('proxy end-to-end (real pg client)', () => {
  it('authorizes, rewrites, and returns rows', async () => {
    const client = await connect()
    try {
      const res = await client.query('SELECT * FROM users')
      expect(res.rows).toEqual([
        { id: '1', email: 'a@x' },
        { id: '2', email: 'b@y' },
      ])
      expect(lastSql).toMatch(/users\.id/)
      expect(lastSql).not.toContain('*')
    } finally {
      await client.end()
    }
  })

  it('rejects a forbidden column with a Postgres error', async () => {
    const client = await connect()
    try {
      await expect(client.query('SELECT password FROM users')).rejects.toThrow(/password/)
    } finally {
      await client.end()
    }
  })

  it('blocks DDL', async () => {
    const client = await connect()
    try {
      await expect(client.query('DROP TABLE users')).rejects.toThrow(/not permitted/)
    } finally {
      await client.end()
    }
  })

  it('rejects a bad password at connect time', async () => {
    await expect(connect('wrong')).rejects.toThrow()
  })

  it('handles a parameterized query (extended protocol)', async () => {
    const client = await connect()
    try {
      const res = await client.query('SELECT * FROM users WHERE id = $1', ['1'])
      expect(res.rows).toEqual([
        { id: '1', email: 'a@x' },
        { id: '2', email: 'b@y' },
      ])
      expect(lastSql).toMatch(/users\.id/) // rewritten
      expect(lastSql).toMatch(/\$1/) // parameter preserved
      expect(lastParams).toEqual(['1']) // bound value forwarded
    } finally {
      await client.end()
    }
  })

  it('rejects a forbidden parameterized query', async () => {
    const client = await connect()
    try {
      await expect(
        client.query('SELECT password FROM users WHERE id = $1', ['1']),
      ).rejects.toThrow(/password/)
    } finally {
      await client.end()
    }
  })
})
