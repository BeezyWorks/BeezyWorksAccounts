import { decodeJwt, decodeProtectedHeader, importPKCS8, jwtVerify } from 'jose'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { getAppleClientSecret, getAppleConfig, resetAppleSecretCache, revokeAppleToken } from '../src/apple'
import { createAuth } from '../src/auth'
import { appleEnv, baseEnv, call, PASSWORD, verifiedSession } from './helpers'

beforeEach(() => resetAppleSecretCache())
afterEach(() => vi.restoreAllMocks())

describe('apple client secret', () => {
  it('is null when unconfigured or incomplete', async () => {
    expect(getAppleConfig(baseEnv)).toBeNull()
    const e = await appleEnv()
    expect(getAppleConfig({ ...e, APPLE_KEY_ID: undefined })).toBeNull()
    expect(getAppleConfig({ ...e, APPLE_SERVICES_ID: '', APPLE_APP_BUNDLE_IDS: '' })).toBeNull()
  })

  it('collects audiences and signs a correctly shaped ES256 JWT', async () => {
    const e = await appleEnv()
    const cfg = getAppleConfig(e)!
    expect(cfg.audiences).toEqual(['app.baderech.services', 'app.baderech.mishna', 'app.baderech.siddur'])
    const jwt = await getAppleClientSecret(cfg, 1_800_000_000_000)
    expect(decodeProtectedHeader(jwt)).toMatchObject({ alg: 'ES256', kid: 'KEY1234567' })
    const c = decodeJwt(jwt)
    expect(c).toMatchObject({ iss: 'TEAM123456', sub: 'app.baderech.services', aud: 'https://appleid.apple.com' })
    expect(c.iat).toBe(1_800_000_000)
    const life = c.exp! - c.iat!
    expect(life).toBeGreaterThan(60 * 60 * 24 * 60)
    expect(life).toBeLessThanOrEqual(15_777_000) // Apple's 6-month cap
  })

  it('caches, then regenerates well before expiry', async () => {
    const cfg = getAppleConfig(await appleEnv())!
    const t0 = 1_800_000_000_000
    const a = await getAppleClientSecret(cfg, t0)
    expect(await getAppleClientSecret(cfg, t0 + 3600_000)).toBe(a)
    expect(await getAppleClientSecret(cfg, t0 + 100 * 86400_000)).toBe(a)
    const b = await getAppleClientSecret(cfg, t0 + 125 * 86400_000) // <30 days left
    expect(b).not.toBe(a)
    expect(decodeJwt(b).exp!).toBeGreaterThan(decodeJwt(a).exp!)
  })

  it('verifies against the public half of the key', async () => {
    const e = await appleEnv()
    const jwt = await getAppleClientSecret(getAppleConfig(e)!)
    const { createPublicKey } = await import('node:crypto').catch(() => ({ createPublicKey: undefined }))
    expect(jwt.split('.')).toHaveLength(3)
    expect(createPublicKey).toBeDefined()
    const pub = createPublicKey!(e.APPLE_PRIVATE_KEY!).export({ format: 'pem', type: 'spki' }) as string
    const { importSPKI } = await import('jose')
    await expect(jwtVerify(jwt, await importSPKI(pub, 'ES256'), { audience: 'https://appleid.apple.com' })).resolves.toBeTruthy()
    await importPKCS8(e.APPLE_PRIVATE_KEY!, 'ES256')
  })

  it('enables the apple provider with all audiences, and trusts appleid.apple.com', async () => {
    const auth = await createAuth(await appleEnv())
    expect(Object.keys(auth.options.socialProviders ?? {})).toEqual(['apple'])
    expect((auth.options.socialProviders as any).apple.audience).toEqual([
      'app.baderech.services',
      'app.baderech.mishna',
      'app.baderech.siddur',
    ])
    expect(auth.options.trustedOrigins).toContain('https://appleid.apple.com')
  })
})

describe('apple revoke', () => {
  it('posts to Apple, and failures are not fatal', async () => {
    const cfg = getAppleConfig(await appleEnv())!
    const f = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(new Response('', { status: 200 }))
    expect(await revokeAppleToken(cfg, 'r-token', 'refresh_token')).toBe(true)
    const [url, init] = f.mock.calls[0]
    expect(url).toBe('https://appleid.apple.com/auth/revoke')
    const body = new URLSearchParams((init as RequestInit).body as URLSearchParams)
    expect(body.get('token')).toBe('r-token')
    expect(body.get('token_type_hint')).toBe('refresh_token')
    expect(body.get('client_id')).toBe('app.baderech.services')
    expect(body.get('client_secret')?.split('.')).toHaveLength(3)

    f.mockResolvedValueOnce(new Response('bad', { status: 400 }))
    expect(await revokeAppleToken(cfg, 'x', 'access_token')).toBe(false)
    f.mockRejectedValueOnce(new Error('network'))
    expect(await revokeAppleToken(cfg, 'x', 'access_token')).toBe(false)
  })

  it('is called on user deletion when an apple account has a refresh token', async () => {
    const e = await appleEnv()
    const { token, user } = await verifiedSession()
    await e.DB.prepare(
      `INSERT INTO account (id, accountId, providerId, userId, refreshToken, createdAt, updatedAt)
       VALUES ('acc-apple-1', 'apple-sub-1', 'apple', ?, 'apple-refresh-token', ?, ?)`,
    )
      .bind(user.id, new Date().toISOString(), new Date().toISOString())
      .run()

    const real = globalThis.fetch
    const f = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url
      if (url === 'https://appleid.apple.com/auth/revoke') return new Response('', { status: 200 })
      return real(input as any, init)
    })
    const del = await call('POST', '/api/auth/delete-user', { password: PASSWORD }, { token, env: e })
    expect(del.status).toBe(200)
    const revokes = f.mock.calls.filter(([u]) => u === 'https://appleid.apple.com/auth/revoke')
    expect(revokes).toHaveLength(1)
    const body = new URLSearchParams((revokes[0][1] as RequestInit).body as URLSearchParams)
    expect(body.get('token')).toBe('apple-refresh-token')
    expect(await e.DB.prepare('SELECT id FROM user WHERE id = ?').bind(user.id).first()).toBeNull()
  })

  it('does not block deletion when revoke fails', async () => {
    const e = await appleEnv()
    const { token, user } = await verifiedSession()
    await e.DB.prepare(
      `INSERT INTO account (id, accountId, providerId, userId, accessToken, createdAt, updatedAt)
       VALUES ('acc-apple-2', 'apple-sub-2', 'apple', ?, 'apple-access-token', ?, ?)`,
    )
      .bind(user.id, new Date().toISOString(), new Date().toISOString())
      .run()
    const real = globalThis.fetch
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url
      if (url === 'https://appleid.apple.com/auth/revoke') throw new Error('apple down')
      return real(input as any, init)
    })
    const del = await call('POST', '/api/auth/delete-user', { password: PASSWORD }, { token, env: e })
    expect(del.status).toBe(200)
  })
})
