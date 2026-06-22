# Deploying sql-control safely

sql-control parses, authorizes, and rewrites every statement before it reaches
Postgres. A few things are the **operator's responsibility** — get them right and
the parser is a hard boundary; get them wrong and protections degrade.

> The parser is the *primary* control; the backend role + your config are *defense
> in depth* — and a couple are load-bearing (§1, §2).

## Go-live checklist

- [ ] **Backend role is least-privileged** — reaches *only* what a tenant may ever touch (§1). *Most important.*
- [ ] **Catalog supplied** via `loadCatalog`, **refreshed on DDL** (§2).
- [ ] **`defaultSchema` set** per model; backend `search_path` pinned to match (§3).
- [ ] **TLS** at the proxy or a TLS LB (§4).
- [ ] **`maxRows`** on every policy + **`statement_timeout`** on the role (§5).
- [ ] **`functions: { mode: 'allowlist' }`** for untrusted tenants (§5).
- [ ] Clients use **autocommit DML** — no transactions/SET/SHOW ([Constraints](#constraints)).
- [ ] A **human pentest** has reviewed it.

## 1. Least-privileged backend role (required)

Postgres expands views, rules, triggers, `DEFAULT`s, and generated columns *after*
sql-control sees the statement — so it can't see the tables those reach. The
backstop is the role the proxy connects as: grant it *only* what your models
expose, so a hidden read fails at the database.

```sql
CREATE ROLE sqlcontrol_app LOGIN PASSWORD '...';        -- starts with no table privileges
GRANT USAGE  ON SCHEMA crm TO sqlcontrol_app;
GRANT SELECT (id, email) ON crm.users TO sqlcontrol_app; -- only the granted columns
GRANT SELECT, UPDATE     ON crm.deals TO sqlcontrol_app;
ALTER ROLE sqlcontrol_app SET statement_timeout = '15s';
ALTER ROLE sqlcontrol_app SET search_path = 'crm';       -- pin it (§3)
```

## 2. Supply a catalog — and refresh it (required)

The catalog tells the analyzer your schema's *shape* (columns, views, inheritance
children). It powers `*`-expansion, column resolution, and the inheritance check.
Introspect it from the live DB:

```ts
import { loadCatalog } from 'sql-control'
const catalog = await loadCatalog(
  async (sql) => (await pool.query({ text: sql, rowMode: 'array' })).rows,
  { model }, // restrict to relations this model can see
)
```

> **Refresh on DDL.** It's a snapshot — a stale catalog (e.g. a partition added
> later) can wrongly report a parent as childless and re-open the inheritance gap.
> Without *any* catalog the analyzer is in **degraded mode** (no `*`-expansion, no
> inheritance check) — don't run production without one.

## 3. Pin the schema

Set `defaultSchema` so unqualified names resolve to a known schema; the rewriter
then schema-qualifies every relation, so the backend's `search_path` can't redirect
a name to a different table. Pin the role's `search_path` to match (§1).

```ts
const model: PermissionModel = { defaultSchema: 'crm', tables: { /* ... */ } }
```

## 4. TLS + auth

Without TLS, passwords and data cross the wire in the clear. Terminate it at the
proxy (or a TLS-terminating load balancer):

```ts
createProxyServer({ authenticate, backend,
  tls: { key: readFileSync('server.key'), cert: readFileSync('server.crt') } })
```

Auth is `authenticate(params, password)` (cleartext — **only with TLS**) or `scram`
(SCRAM-SHA-256; the server never sees the cleartext — prefer a precomputed verifier
so you never store passwords).

## 5. Bound resources

- **`maxRows`** per policy — a larger result is refused (`54000`), not truncated.
- **`streamBackend`** (optional) — serve large results at flat memory by streaming
  row-by-row instead of buffering the whole set.
- **`statement_timeout`** on the role (§1) + a connection limit on the listener / LB.
- **`functions: { mode: 'allowlist' }`** for untrusted tenants.

```ts
const policy: ResolvedPolicy = { model, catalog, context: { ctx: { uid } }, maxRows: 10_000 }
```

## 6. Full setup

```ts
import { readFileSync } from 'node:fs'
import { Pool } from 'pg'
import { createProxyServer, loadCatalog } from 'sql-control'
import type { PermissionModel } from 'sql-control'

// identity type-parser → raw Postgres text, so the proxy forwards results untouched
const pool = new Pool({ connectionString: BACKEND_URL, types: { getTypeParser: () => (v) => v } })
const catalog = await loadCatalog(async (sql) => (await pool.query({ text: sql, rowMode: 'array' })).rows)

const modelForTenant = (uid: number): PermissionModel => ({
  defaultSchema: 'crm',
  functions: { mode: 'allowlist', list: [] },
  tables: {
    'crm.deals': {
      select: { columns: ['id', 'stage', 'owner_id'] },
      update: { columns: ['stage'] },
      rls: { select: 'owner_id = ctx.uid', update: 'owner_id = ctx.uid' },
    },
  },
})

createProxyServer({
  tls: { key: readFileSync('server.key'), cert: readFileSync('server.crt') },
  authenticate: async (params, password) => {
    const user = await lookupUser(params.user, password) // your auth
    return user && { model: modelForTenant(user.id), catalog,
                     context: { ctx: { uid: user.id } }, maxRows: 10_000 }
  },
  backend: async (sql, params) => {
    const r = await pool.query({ text: sql, values: params, rowMode: 'array' })
    return { fields: r.fields, rows: r.rows, tag: `${r.command} ${r.rowCount ?? 0}` } // passthrough
  },
}).listen(5432, '0.0.0.0')
```

Run several instances behind a load balancer for HA — the proxy is stateless per
connection.

## Constraints

The proxy accepts **only single-statement, autocommit DML** — by design (it keeps
the attack surface to four statement types):

- **No transactions** (`BEGIN`/`COMMIT`/`ROLLBACK`) — clients must use autocommit.
- **No session statements** (`SET`/`SHOW`/`RESET`/`DISCARD`).
- **No DDL / utility / COPY / multi-statement.**

Need transactions or session setup? Handle them in your app and send the proxy
plain autocommit DML.

## Residual risks

- **Stale catalog** → inheritance check can be fooled; refresh on DDL (§2).
- **DB-object opacity** → covered only by the least-priv role (§1) — verify its grants.