import { describe, expect, it } from 'vitest'
import worker from '../src/index'
import { baseEnv, ORIGIN } from './helpers'

const env = {
  ...baseEnv,
  TRUSTED_ORIGINS: `${baseEnv.TRUSTED_ORIGINS},https://siddur.one`,
  GOOGLE_CLIENT_ID: 'id',
  GOOGLE_CLIENT_SECRET: 's',
}
const RETURN = 'https://siddur.one/account/callback'
const send = (path: string, init: RequestInit = {}) => worker.fetch(new Request(`${ORIGIN}${path}`, init), env)
const start = (provider: string, ret = RETURN) =>
  send(`/start/${provider}?return=${encodeURIComponent(ret)}`, { headers: { 'cf-connecting-ip': '10.7.7.7' } })

describe('start', () => {
  it('redirects to the provider with the state cookie set first-party', async () => {
    const res = await start('google')
    expect(res.status).toBe(302)
    const location = new URL(res.headers.get('location')!)
    expect(location.host).toBe('accounts.google.com')
    expect(res.headers.get('cache-control')).toBe('no-store')
    const cookies = res.headers.getSetCookie()
    expect(cookies.some((c) => /state=/.test(c))).toBe(true)

    // The provider's callback, carrying that cookie, gets past the state check (it then fails
    // exchanging the fake code with Google — anything but a state error is the point here).
    const cookie = cookies.map((c) => c.split(';')[0]).join('; ')
    const state = location.searchParams.get('state')!
    const cb = await send(`/api/auth/callback/google?state=${state}&code=fake`, { headers: { cookie } })
    expect(cb.status).toBe(302)
    expect(cb.headers.get('location')).not.toMatch(/state/)
    expect(cb.headers.get('location')).toMatch(/^https:\/\/siddur\.one\/account\/callback\?error=/)

    // Without the cookie it's the state mismatch we used to hit.
    const bare = await send(`/api/auth/callback/google?state=${state}&code=fake`)
    expect(bare.headers.get('location')).toMatch(/state/)
  })

  it('rejects unknown providers and untrusted return URLs', async () => {
    expect((await start('github')).status).toBe(404)
    expect((await start('google', 'https://evil.test/cb')).status).toBe(400)
    expect((await send('/start/google')).status).toBe(400)
  })
})
