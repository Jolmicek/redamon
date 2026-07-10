import { defineConfig } from 'vitest/config'
import path from 'path'

export default defineConfig({
  resolve: {
    alias: {
      '@': path.resolve(__dirname, 'src'),
    },
  },
  test: {
    environment: 'jsdom',
    // Vitest's default exclude does not cover Next.js build output, so a stale
    // `next build` leaves duplicate *.test.* copies under .next/standalone that
    // get collected and run (against build artifacts). Never scan build output.
    exclude: ['**/node_modules/**', '**/dist/**', '**/.next/**'],
    css: { modules: { classNameStrategy: 'non-scoped' } },
    setupFiles: ['./vitest.setup.ts'],
    // React 19 strips `act` from the production build. The webapp container
    // bakes in NODE_ENV=production, so without this override every
    // render()-based test would fail with "React.act is not a function".
    env: { NODE_ENV: 'test' },
  },
})
