import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    hookTimeout: 30_000,
    testTimeout: 30_000,
    // Scratch probe / audit-harness files — never part of the canonical suite.
    exclude: [
      '**/node_modules/**',
      'test/_*.test.ts',
      'test/zz*.test.ts',
      'test/zhunt*.test.ts',
      'test/verify*.test.ts',
      'test/probe*.test.ts',
    ],
  },
})
