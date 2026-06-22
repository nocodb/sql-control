/**
 * E2E against a REAL Postgres server (node-pg Pool), the highest-fidelity run.
 * Gated on SQLCONTROL_TEST_PG (a connection string) so it skips when no server is
 * configured — CI sets it to a `services: postgres` container; locally point it at
 * any throwaway database, e.g.
 *   SQLCONTROL_TEST_PG=postgres://postgres:password@127.0.0.1:5432/sqlcontrol_e2e
 */
import { Pool } from 'pg'
import { backendFromQuery, SEED_SQL } from './helpers/pg-backend'
import { defineE2eSuite } from './helpers/e2e-suite'

const connectionString = process.env.SQLCONTROL_TEST_PG

defineE2eSuite(
  'real PG',
  async () => {
    const pool = new Pool({ connectionString, max: 8 })
    await pool.query(SEED_SQL)
    return {
      backend: backendFromQuery(async (sql, params) => {
        const r = await pool.query({ text: sql, values: params, rowMode: 'array' })
        return { rows: r.rows, fields: r.fields, affectedRows: r.rowCount ?? undefined, command: r.command }
      }),
      exec: (sql) => pool.query(sql).then(() => undefined),
      scalar: async (sql) => {
        const r = await pool.query({ text: sql, rowMode: 'array' })
        return r.rows[0]?.[0]
      },
      close: () => pool.end(),
    }
  },
  connectionString === undefined, // skip when not configured
)
