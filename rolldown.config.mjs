import { defineConfig } from 'rolldown'

// Bundle the library for Node. Runtime dependencies stay external — we ship our
// code, not theirs.
export default defineConfig({
  input: 'src/index.ts',
  platform: 'node',
  external: [/^node:/, /^pgsql-parser/, /^pg-gateway/, /^libpg-query/, /^@pgsql\//],
  output: {
    dir: 'dist',
    format: 'esm',
    sourcemap: true,
  },
})
