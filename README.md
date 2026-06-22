# sql-control

A SQL authorization layer for Postgres. It parses each statement into the real
Postgres AST (`libpg_query` via `pgsql-parser`), enforces a **default-deny**
permission model, rewrites the query to be safe, and serves it as a
**wire-protocol proxy** in front of Postgres.

## Running the proxy

You supply `authenticate` (connection → policy) and `backend` (run safe SQL):

```ts
import { Pool } from 'pg'
import { createProxyServer } from 'sql-control'

// least-privileged role. The identity type-parser returns raw Postgres text, so
// the proxy forwards results untouched (it rewrites SQL, never your data).
const pool = new Pool({
  host: 'db', user: 'sqlcontrol_app', password: '…',
  types: { getTypeParser: () => (v) => v },
})

createProxyServer({
  authenticate(params, password) {
    const tenant = lookupTenant(params.user, password) // your auth
    if (!tenant) return null
    return { model: tenant.policy, catalog: tenant.catalog,
             context: { ctx: { uid: tenant.id } }, maxRows: 10_000 }
  },
  async backend(sql, params) {
    const r = await pool.query({ text: sql, values: params, rowMode: 'array' })
    return { fields: r.fields, rows: r.rows, tag: `${r.command} ${r.rowCount ?? 0}` } // passthrough
  },
}).listen(5432)
```

Point a BI tool at it like a normal Postgres. Full runnable example (admin /
manager / rep org chart + RLS): [`examples/crm.test.ts`](examples/crm.test.ts).

## Architecture

```
wire proxy (pg-gateway)        ← terminates the PG protocol, intercepts SQL
  └─ analyze(sql, { model, catalog, context })   ← the brain (pure, testable)
       ├─ guard    parse · reject stacking · DML allow-list
       ├─ collect  one AST pass → relations, columns, functions, writes
       ├─ check    visibility + column read/write perms (catalog-resolved)
       └─ rewrite  expand `*` · inject RLS · filter catalogs · qualify → deparse
```

The analyzer is transport-agnostic (unit-testable without a DB or socket); the
proxy is a thin shell that calls it.

## Permission model

```ts
const policy: PermissionModel = {
  schemas: { tenant_42: { defaultTablePolicy: { select: true } } }, // hard schema gate
  tables: {
    'tenant_42.users': { select: { columns: ['id', 'email'] } },     // column allow-list
    'tenant_42.deals': {
      select: { columns: ['id', 'stage', 'owner_id'] },
      update: { columns: ['stage'] },
      rls: { select: 'owner_id = ctx.uid' },                         // row-level security
    },
    'tenant_42.audit_log': { select: false },                        // held back
  },
  introspection: { enabled: true }, // BI tools can introspect; rows are filtered to permitted objects
}
```

`authenticate` returns a `PermissionModel` **per connection**, so each tenant gets
its own policy (and `ctx.*` values for its RLS predicates).

## What it enforces

- **DML only** — `SELECT/INSERT/UPDATE/DELETE`; all DDL/utility (and `SELECT … INTO`) rejected.
- **Visibility** — a table/view not in the model is invisible.
- **Columns** — read/write allow-lists; `SELECT *` is rewritten to the permitted columns (fails closed).
- **Rows (RLS)** — predicates injected as `WHERE` / `WITH CHECK` on reads, writes, and `UPDATE…FROM`.
- **Functions & operators** — dangerous built-ins and non-built-in operators blocked by default.
- **Introspection** — catalog reads are row-filtered to permitted objects; secret catalogs stay blocked.

Checked everywhere — subqueries, joins, set-ops, CTEs, aggregates, every clause
position — and pinned by the security / fuzz / soak suites.

> **The one structural limit.** The analyzer sees the SQL, not what Postgres
> expands it into (views, rules, triggers, `DEFAULT`s, generated columns) — so the
> backstop is a **least-privileged backend role** + functions allowlist. The parser
> is the primary control; DB grants are defense in depth.

## Deploying

Read **[DEPLOYMENT.md](DEPLOYMENT.md)** first — the operator's contract
(least-privileged backend role, catalog, `search_path`, TLS, limits). A couple of
those are load-bearing for the security guarantee.
