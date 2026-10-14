import { cloudflareTest, readD1Migrations } from '@cloudflare/vitest-pool-workers'
import { defineConfig } from 'vitest/config'

export default defineConfig(async () => {
  const migrations = await readD1Migrations(new URL('./migrations', import.meta.url).pathname)
  return {
    plugins: [
      cloudflareTest({
        main: './src/index.ts',
        miniflare: {
          compatibilityDate: '2026-08-22', // newest the bundled workerd supports
          compatibilityFlags: ['nodejs_compat'],
          d1Databases: ['DB'],
          bindings: {
            TEST_MIGRATIONS: migrations,
            BETTER_AUTH_SECRET: 'test-secret-test-secret-test-secret-0123',
            BETTER_AUTH_URL: 'https://auth.test',
            TRUSTED_ORIGINS: 'mishna://,https://mishna.test',
          },
        },
      }),
    ],
    root: new URL('.', import.meta.url).pathname,
    test: { include: ['test/**/*.test.ts'], setupFiles: ['./test/setup.ts'] },
  }
})
