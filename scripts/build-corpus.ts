/**
 * Mine the Postgres source tree for (a) a corpus of real SQL statements drawn
 * from the regression suite and (b) the authoritative list of system-catalog
 * relations. Outputs JSON fixtures under test/corpus/ so the test suite stays
 * self-contained — the Postgres checkout is only needed at generation time.
 *
 *   PG_DIR=../postgres node scripts/build-corpus.ts
 */
import { readFileSync, readdirSync, writeFileSync, mkdirSync, existsSync } from 'node:fs'
import { join } from 'node:path'
import { parse } from 'pgsql-parser'

const PG = process.env.PG_DIR ?? join('..', 'postgres')
const OUT = join('test', 'corpus')

/** Drop psql meta-command lines (`\d`, `\set`, `\.`, …) — they aren't SQL. */
function stripPsql(sql: string): string {
  return sql
    .split('\n')
    .filter((line) => !/^\s*\\/.test(line))
    .join('\n')
}

/**
 * Split a script into top-level statements, respecting single/double quotes,
 * dollar-quoted bodies (`$tag$ … $tag$`), and line/block comments — so a
 * semicolon inside a function body never splits a statement.
 */
function splitStatements(sql: string): string[] {
  const out: string[] = []
  let buf = ''
  let inSingle = false
  let inDouble = false
  let dollar: string | null = null
  let line = false
  let block = 0
  for (let i = 0; i < sql.length; ) {
    const c = sql[i] ?? ''
    const c2 = sql[i + 1] ?? ''
    if (line) {
      buf += c
      if (c === '\n') line = false
      i++
    } else if (block > 0) {
      if (c === '*' && c2 === '/') { buf += '*/'; block--; i += 2 }
      else if (c === '/' && c2 === '*') { buf += '/*'; block++; i += 2 }
      else { buf += c; i++ }
    } else if (dollar !== null) {
      if (sql.startsWith(dollar, i)) { buf += dollar; i += dollar.length; dollar = null }
      else { buf += c; i++ }
    } else if (inSingle) {
      buf += c
      if (c === "'") { if (c2 === "'") { buf += c2; i += 2 } else { inSingle = false; i++ } }
      else i++
    } else if (inDouble) {
      buf += c
      if (c === '"') { if (c2 === '"') { buf += c2; i += 2 } else { inDouble = false; i++ } }
      else i++
    } else if (c === '-' && c2 === '-') { line = true; buf += '--'; i += 2 }
    else if (c === '/' && c2 === '*') { block = 1; buf += '/*'; i += 2 }
    else if (c === "'") { inSingle = true; buf += c; i++ }
    else if (c === '"') { inDouble = true; buf += c; i++ }
    else if (c === ';') { out.push(buf); buf = ''; i++ }
    else if (c === '$') {
      const m = /^\$([A-Za-z_]\w*)?\$/.exec(sql.slice(i, i + 64))
      if (m) { dollar = m[0]; buf += m[0]; i += m[0].length }
      else { buf += c; i++ }
    } else { buf += c; i++ }
  }
  if (buf.trim()) out.push(buf)
  return out
}

interface Entry {
  sql: string
  type: string
  file: string
}

async function buildStatementCorpus(): Promise<{ entries: Entry[]; skipped: number; byType: Record<string, number> }> {
  const regress = join(PG, 'src', 'test', 'regress', 'sql')
  const files = readdirSync(regress).filter((f) => f.endsWith('.sql')).sort()
  const seen = new Set<string>()
  const entries: Entry[] = []
  const byType: Record<string, number> = {}
  let skipped = 0

  for (const file of files) {
    const cleaned = stripPsql(readFileSync(join(regress, file), 'utf8'))
    for (const piece of splitStatements(cleaned)) {
      const sql = piece.trim()
      if (!sql || seen.has(sql)) continue
      let ast: { stmts?: { stmt?: Record<string, unknown> }[] }
      try {
        ast = await parse(sql)
      } catch {
        skipped++
        continue
      }
      const stmts = ast.stmts ?? []
      if (stmts.length !== 1) continue // keep one statement per entry
      const type = Object.keys(stmts[0]?.stmt ?? {})[0]
      if (!type) continue
      seen.add(sql)
      byType[type] = (byType[type] ?? 0) + 1
      entries.push({ sql, type, file })
    }
  }
  return { entries, skipped, byType }
}

function buildSystemRelations(): { pgCatalog: string[]; informationSchema: string[] } {
  const pgCatalog = new Set<string>()
  const catalogDir = join(PG, 'src', 'include', 'catalog')
  for (const f of readdirSync(catalogDir).filter((f) => f.endsWith('.h'))) {
    const txt = readFileSync(join(catalogDir, f), 'utf8')
    for (const m of txt.matchAll(/CATALOG\((\w+),/g)) pgCatalog.add(m[1] ?? '')
  }
  const sysViews = readFileSync(join(PG, 'src', 'backend', 'catalog', 'system_views.sql'), 'utf8')
  for (const m of sysViews.matchAll(/CREATE VIEW\s+(pg_\w+)/gi)) pgCatalog.add(m[1] ?? '')

  const infoSchema = new Set<string>()
  const infoSql = readFileSync(join(PG, 'src', 'backend', 'catalog', 'information_schema.sql'), 'utf8')
  for (const m of infoSql.matchAll(/CREATE VIEW\s+(\w+)/gi)) infoSchema.add(m[1] ?? '')

  return {
    pgCatalog: [...pgCatalog].filter(Boolean).sort(),
    informationSchema: [...infoSchema].filter(Boolean).sort(),
  }
}

async function main(): Promise<void> {
  if (!existsSync(PG)) {
    throw new Error(`Postgres checkout not found at ${PG}; set PG_DIR`)
  }
  if (!existsSync(OUT)) mkdirSync(OUT, { recursive: true })

  const { entries, skipped, byType } = await buildStatementCorpus()
  const relations = buildSystemRelations()

  writeFileSync(join(OUT, 'statements.json'), JSON.stringify(entries, null, 0) + '\n')
  writeFileSync(join(OUT, 'system-relations.json'), JSON.stringify(relations, null, 2) + '\n')

  const dml = ['SelectStmt', 'InsertStmt', 'UpdateStmt', 'DeleteStmt']
  const dmlCount = entries.filter((e) => dml.includes(e.type)).length
  const summary = {
    statements: entries.length,
    dml: dmlCount,
    nonDml: entries.length - dmlCount,
    skippedUnparseable: skipped,
    distinctTypes: Object.keys(byType).length,
    pgCatalogRelations: relations.pgCatalog.length,
    informationSchemaRelations: relations.informationSchema.length,
  }
  writeFileSync(join(OUT, 'summary.json'), JSON.stringify({ ...summary, byType }, null, 2) + '\n')

  console.log('corpus built:', JSON.stringify(summary, null, 2))
}

await main()
