import { describe, expect, it } from 'vitest'
import worker from '../src/index'
import { baseEnv, call, lastMail, ORIGIN, PASSWORD, signUp } from './helpers'

const WEB = 'https://mishna.test' // a trusted https origin standing in for https://siddur.one
const RETURN = `${WEB}/account/callback`
const env = { ...baseEnv, TRUSTED_ORIGINS: `${baseEnv.TRUSTED_ORIGINS},https://siddur.one` }

const send = (path: string, init: RequestInit = {}) =>
  worker.fetch(new Request(`${ORIGIN}${path}`, init), env)

let sessN = 1

/** Sign up, verify, sign in; returns the session cookie header (what a browser on the auth origin holds). */
async function cookieSession() {
  const { email } = await signUp()
  const link = new URL(lastMail().link)
  await call('GET', link.pathname + link.search)
  const res = await send('/api/auth/sign-in/email', {
    method: 'POST',
    headers: { 'content-type': 'application/json', origin: ORIGIN, 'cf-connecting-ip': `10.9.${Math.floor(sessN / 250)}.${sessN++ % 250}` },
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
    for (const r of ['https://evil.test/x', 'unlistedapp://cb', 'javascript:alert(1)', 'not a url', '']) {
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

describe('verification link back into an app', () => {
  it('signs in on verify and hands the session to the callbackURL', async () => {
    const handoff = `${ORIGIN}/handoff?return=${encodeURIComponent('https://siddur.one/account/callback')}`
    const res = await send('/api/auth/sign-up/email', {
      method: 'POST',
      headers: { 'content-type': 'application/json', origin: 'https://siddur.one', 'cf-connecting-ip': '10.9.9.8' },
      body: JSON.stringify({ email: `verify${Date.now()}@example.test`, password: PASSWORD, name: 'V', callbackURL: handoff }),
    })
    expect(res.status).toBe(200)
    const link = new URL(lastMail().link)
    expect(link.searchParams.get('callbackURL')).toBe(handoff)

    const verified = await send(link.pathname + link.search)
    expect(verified.status).toBe(302)
    expect(verified.headers.get('location')).toBe(handoff)
    const cookie = verified.headers.getSetCookie().map((c) => c.split(';')[0]).join('; ')
    expect(cookie).toContain('session_token')

    const back = await send(new URL(handoff).pathname + new URL(handoff).search, { headers: { cookie } })
    const loc = new URL(back.headers.get('location')!)
    expect(loc.origin + loc.pathname).toBe('https://siddur.one/account/callback')
    expect(new URLSearchParams(loc.hash.slice(1)).get('ott')).toBeTruthy()
  })
})

describe('native (custom-scheme) handoff', () => {
  const NATIVE = 'siddurone://account/callback'
  const nenv = { ...env, TRUSTED_ORIGINS: `${env.TRUSTED_ORIGINS},siddurone://` }
  const nsend = (path: string, init: RequestInit = {}) => worker.fetch(new Request(`${ORIGIN}${path}`, init), nenv)

  it('puts the one-time token in the query; verify (no Origin) yields a bearer, once', async () => {
    const { cookie } = await cookieSession()
    const res = await nsend(`/handoff?return=${encodeURIComponent(NATIVE)}`, { headers: { cookie } })
    expect(res.status).toBe(302)
    const loc = new URL(res.headers.get('location')!)
    expect(loc.protocol).toBe('siddurone:')
    expect(loc.hash).toBe('')
    expect(loc.searchParams.get('ott')).toBeTruthy()
    expect(res.headers.get('location')).toMatch(/^siddurone:\/\/account\/callback\?ott=/)

    const verify = () =>
      nsend('/api/auth/one-time-token/verify', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ token: loc.searchParams.get('ott') }),
      })
    const v = await verify()
    expect(v.status).toBe(200)
    const bearer = v.headers.get('set-auth-token')!
    expect(bearer).toBeTruthy()
    const sess = await nsend('/api/auth/get-session', { headers: { authorization: `Bearer ${bearer}` } })
    expect(((await sess.json()) as any).user.email).toBeTruthy()
    expect((await verify()).status).toBe(400)
  })

  it('reports no_session in the query', async () => {
    const res = await nsend(`/handoff?return=${encodeURIComponent(NATIVE)}`)
    expect(res.status).toBe(302)
    expect(res.headers.get('location')).toBe(`${NATIVE}?error=no_session`)
  })

  it('rejects unlisted, forbidden and malformed schemes', async () => {
    const { cookie } = await cookieSession()
    const bad = [
      'otherapp://cb', // not listed
      'javascript:alert(1)',
      'data:text/html,hi',
      'file:///etc/passwd',
      'siddurone:/account/callback', // scheme not in `scheme://` form
      'siddurone:account/callback',
      'siddurone://user:pw@account/callback',
      'http://siddurone//cb', // http(s) shaped as custom
      '//account/callback',
      'siddurone',
    ]
    for (const r of bad) {
      const res = await nsend(`/handoff?return=${encodeURIComponent(r)}`, { headers: { cookie } })
      expect(res.status, r).toBe(400)
      expect(res.headers.get('location')).toBeNull()
    }
    // Listing an http scheme in custom form must not make it acceptable either.
    const odd = { ...nenv, TRUSTED_ORIGINS: `${nenv.TRUSTED_ORIGINS},javascript://,https://,file://` }
    for (const r of ['javascript://x/%0aalert(1)', 'file:///etc/passwd', 'https://evil.test/x']) {
      const res = await worker.fetch(new Request(`${ORIGIN}/handoff?return=${encodeURIComponent(r)}`, { headers: { cookie } }), odd)
      expect(res.status, r).toBe(400)
    }
    // Without siddurone:// listed, it is rejected.
    const res = await send(`/handoff?return=${encodeURIComponent(NATIVE)}`, { headers: { cookie } })
    expect(res.status).toBe(400)
  })

  it('verification email callbackURL may be a handoff to a custom scheme (sign-up has no Origin)', async () => {
    const handoff = `${ORIGIN}/handoff?return=${encodeURIComponent(NATIVE)}`
    const res = await nsend('/api/auth/sign-up/email', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'cf-connecting-ip': '10.9.9.7' },
      body: JSON.stringify({ email: `native${Date.now()}@example.test`, password: PASSWORD, name: 'N', callbackURL: handoff }),
    })
    expect(res.status).toBe(200)
    const link = new URL(lastMail().link)
    expect(link.searchParams.get('callbackURL')).toBe(handoff)

    // The mail app opens the link in a browser: no Origin, no cookies.
    const verified = await nsend(link.pathname + link.search)
    expect(verified.status).toBe(302)
    expect(verified.headers.get('location')).toBe(handoff)
    const cookie = verified.headers.getSetCookie().map((c) => c.split(';')[0]).join('; ')
    expect(cookie).toContain('session_token')

    const back = await nsend(new URL(handoff).pathname + new URL(handoff).search, { headers: { cookie } })
    expect(back.headers.get('location')).toMatch(/^siddurone:\/\/account\/callback\?ott=/)
  })
})
