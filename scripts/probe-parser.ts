import { parse, deparse } from 'pgsql-parser'

const sql = `WITH recent AS (SELECT id FROM orders WHERE ts > now())
SELECT u.*, p.email, count(*)
FROM users u JOIN profiles p ON p.user_id = u.id
WHERE u.active AND u.id IN (SELECT id FROM recent)`

const ast = await parse(sql)
console.log('=== top-level keys ===')
console.log(JSON.stringify(Object.keys(ast)))
console.log('=== stmts length ===', (ast as any).stmts?.length)
const stmt = (ast as any).stmts[0].stmt
console.log('=== stmt node type ===', Object.keys(stmt))
const sel = stmt.SelectStmt
console.log('=== SelectStmt keys ===', Object.keys(sel))
console.log('=== targetList[0] (u.*) ===')
console.log(JSON.stringify(sel.targetList[0], null, 1))
console.log('=== fromClause[0] (JOIN) shape ===')
console.log(JSON.stringify(sel.fromClause[0], null, 1).slice(0, 1200))

console.log('=== deparse round-trip ===')
console.log(await deparse(ast))

// confirm DDL detection: what node wraps a DROP?
const ddl = await parse('DROP TABLE users; SELECT 1')
console.log('=== multi-stmt count ===', (ddl as any).stmts.length)
console.log('=== stmt[0] node type ===', Object.keys((ddl as any).stmts[0].stmt))
