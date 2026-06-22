/**
 * E2E against PGlite — a real Postgres (WASM) running in-process, so this suite
 * needs no external services and runs everywhere (incl. CI). See e2e-suite.ts.
 */
import { PGlite } from '@electric-sql/pglite'
import { backendFromQuery, SEED_SQL } from './helpers/pg-backend'
import { defineE2eSuite } from './helpers/e2e-suite'

defineE2eSuite('PGlite', async () => {
  const db = await PGlite.create()
  await db.exec(SEED_SQL)
  return {
    backend: backendFromQuery((sql, params) => db.query<unknown[]>(sql, params, { rowMode: 'array' })),
    exec: (sql) => db.exec(sql).then(() => undefined),
    scalar: async (sql) => {
      const r = await db.query<unknown[]>(sql, [], { rowMode: 'array' })
      return r.rows[0]?.[0]
    },
    close: () => db.close(),
  }
})
