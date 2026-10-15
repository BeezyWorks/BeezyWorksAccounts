import { describe, expect, it } from 'vitest'
import worker from '../src/index'
import { baseEnv, call, lastMail, ORIGIN, PASSWORD, signUp } from './helpers'

const WEB = 'https://mishna.test' // a trusted https origin standing in for https://siddur.one
const RETURN = `${WEB}/account/callback`
const env = { ...baseEnv, TRUSTED_ORIGINS: `${baseEnv.TRUSTED_ORIGINS},https://siddur.one` }

const send = (path: string, init: RequestInit = {}) =>
  worker.fetch(new Request(`${ORIGIN}${path}`, init), env)

/** Sign up, verify, sign in; returns the session cookie header (what a browser on the auth origin holds). */
async function cookieSession() {
  const { email } = await signUp()
  const link = new URL(lastMail().link)
  await call('GET', link.pathname + link.search)
  const res = await send('/api/auth/sign-in/email', {
    method: 'POST',
    headers: { 'content-type': 'application/json', origin: ORIGIN, 'cf-connecting-ip': '10.9.9.9' },
    body: JSON.stringify({ email, password: PASSWORD }),
  })
  expect(res.status).toBe(200)
  const cookie = res.headers.getSetCookie().map((c) => c.split(';')[0]).join('; ')
  return { email, cookie }
}

describe('handoff', () => {
  it('trades a cookie session for a one-time token, then a usable bearer', async () => {
    const { cookie } = await cookieSession()
    const res = await send(`/handoff?return=${encodeURIComponent('https://siddur.one/account/callback')}`, { headers: { cookie } })
    expect(res.status).toBe(302)
    expect(res.headers.get('cache-control')).toBe('no-store')
    expect(res.headers.get('referrer-policy')).toBe('no-referrer')
    const loc = new URL(res.headers.get('location')!)
    expect(loc.origin + loc.pathname).toBe('https://siddur.one/account/callback')
    const ott = new URLSearchParams(loc.hash.slice(1)).get('ott')!
    expect(ott).toBeTruthy()

    const verify = () =>
      send('/api/auth/one-time-token/verify', {
        method: 'POST',
        headers: { 'content-type': 'application/json', origin: 'https://siddur.one' },
        body: JSON.stringify({ token: ott }),
      })
    const v = await verify()
    expect(v.status).toBe(200)
    expect(v.headers.get('access-control-allow-origin')).toBe('https://siddur.one')
    // The bearer plugin turns the session cookie it sets into this header.
    const bearer = v.headers.get('set-auth-token')!
    expect(bearer).toBeTruthy()
    const body: any = await v.json()
    expect(body.user.email).toBeTruthy()

    const auth = { authorization: `Bearer ${bearer}` }
    const sess = await send('/api/auth/get-session', { headers: auth })
    expect(((await sess.json()) as any).user.email).toBe(body.user.email)
    const data = await send('/api/data/siddur', { headers: auth })
    expect(data.status).toBe(200)

    // single use
    expect((await verify()).status).toBe(400)
  })

  it('rejects untrusted or malformed return URLs', async () => {
    const { cookie } = await cookieSession()
    for (const r of ['https://evil.test/x', 'mishnaapp://cb', 'javascript:alert(1)', 'not a url', '']) {
      const res = await send(`/handoff?return=${encodeURIComponent(r)}`, { headers: { cookie } })
      expect(res.status).toBe(400)
      expect(res.headers.get('location')).toBeNull()
    }
    expect((await send('/handoff', { headers: { cookie } })).status).toBe(400)
  })

  it('reports no_session without a cookie', async () => {
    const res = await send(`/handoff?return=${encodeURIComponent(RETURN)}`)
    expect(res.status).toBe(302)
    expect(res.headers.get('location')).toBe(`${RETURN}#error=no_session`)
  })

  it('accepts the handoff URL as a social sign-in callbackURL', async () => {
    const social = { ...env, GOOGLE_CLIENT_ID: 'id', GOOGLE_CLIENT_SECRET: 's' }
    const post = (callbackURL: string) =>
      worker.fetch(
        new Request(`${ORIGIN}/api/auth/sign-in/social`, {
          method: 'POST',
          headers: { 'content-type': 'application/json', origin: 'https://siddur.one', 'cf-connecting-ip': '10.8.8.8' },
          body: JSON.stringify({ provider: 'google', callbackURL, disableRedirect: true }),
        }),
        social,
      )
    const ok = await post(`${ORIGIN}/handoff?return=https://siddur.one/account/callback`)
    expect(ok.status).toBe(200)
    expect(((await ok.json()) as any).url).toContain('accounts.google.com')
    expect((await post('https://evil.test/handoff')).status).toBe(403)
  })

  it('deletes an account with only a fresh session (no password)', async () => {
    const { cookie } = await cookieSession()
    const res = await send('/api/auth/delete-user', {
      method: 'POST',
      headers: { 'content-type': 'application/json', origin: ORIGIN, cookie },
      body: '{}',
    })
    expect(res.status).toBe(200)
    expect(((await res.json()) as any).message).toBe('User deleted')
  })
})
