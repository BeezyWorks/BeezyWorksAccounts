import { describe, expect, it } from 'vitest'
import { devOutbox } from '../src/email'
import { createAuth } from '../src/auth'
import { baseEnv, call, lastMail, PASSWORD, signUp, uniqueEmail, verifiedSession } from './helpers'

describe('health and pages', () => {
  it('GET /health', async () => {
    const r = await call('GET', '/health')
    expect(r.status).toBe(200)
    expect(r.data).toEqual({ ok: true })
  })

  it('serves /verified and /reset-password, escaping the token', async () => {
    const v = await call('GET', '/verified')
    expect(v.status).toBe(200)
    expect(v.data).toContain('Email verified')

    const evil = `"><script>alert(1)</script>`
    const r = await call('GET', `/reset-password?token=${encodeURIComponent(evil)}`)
    expect(r.status).toBe(200)
    expect(r.data).toContain('Choose a new password')
    expect(r.data).not.toContain('<script>alert(1)')
    expect(r.data).toContain('&lt;script&gt;alert(1)')

    const none = await call('GET', '/reset-password')
    expect(none.data).toContain('missing its token')
  })
})

describe('email + password', () => {
  it('sign-up -> verification link -> verify -> sign-in', async () => {
    const { status, email } = await signUp()
    expect(status).toBe(200)
    const mail = lastMail()
    expect(mail.to).toBe(email)
    expect(mail.subject).toMatch(/verify/i)
    expect(mail.text).toContain(mail.link)
    expect(mail.link).toContain('/api/auth/verify-email?token=')
    expect(mail.link).toContain(encodeURIComponent('https://auth.test/verified'))

    const link = new URL(mail.link)
    const v = await call('GET', link.pathname + link.search)
    expect(v.status).toBe(302)
    expect(v.headers.get('location')).toBe('https://auth.test/verified')

    const si = await call('POST', '/api/auth/sign-in/email', { email, password: PASSWORD })
    expect(si.status).toBe(200)
    expect(si.headers.get('set-auth-token')).toBeTruthy()
    expect(si.data.user.emailVerified).toBe(true)
  })

  it('blocks sign-in before verification', async () => {
    const { email } = await signUp()
    const si = await call('POST', '/api/auth/sign-in/email', { email, password: PASSWORD })
    expect(si.status).toBe(403)
    expect(si.headers.get('set-auth-token')).toBeNull()
  })

  it('updateUser sets names and keeps `name` in sync', async () => {
    const { token, user } = await verifiedSession()
    expect(user.firstName ?? null).toBeNull()

    let r = await call('POST', '/api/auth/update-user', { firstName: 'Moshe', lastName: 'Cohen' }, { token })
    expect(r.status).toBe(200)
    let me = await call('GET', '/api/auth/get-session', undefined, { token })
    expect(me.data.user).toMatchObject({ firstName: 'Moshe', lastName: 'Cohen', name: 'Moshe Cohen' })

    r = await call('POST', '/api/auth/update-user', { displayName: 'Rabbi Moshe' }, { token })
    expect(r.status).toBe(200)
    me = await call('GET', '/api/auth/get-session', undefined, { token })
    expect(me.data.user).toMatchObject({ displayName: 'Rabbi Moshe', firstName: 'Moshe', name: 'Rabbi Moshe' })
  })

  it('password reset flow', async () => {
    const { email } = await verifiedSession()
    const req = await call('POST', '/api/auth/request-password-reset', { email })
    expect(req.status).toBe(200)
    const mail = lastMail()
    expect(mail.subject).toMatch(/reset/i)
    const token = new URL(mail.link).searchParams.get('token')!
    expect(new URL(mail.link).pathname).toBe('/reset-password')

    const bad = await call('POST', '/api/auth/reset-password', { newPassword: 'new-password-123', token: 'nope' })
    expect(bad.status).toBe(400)

    const ok = await call('POST', '/api/auth/reset-password', { newPassword: 'new-password-123', token })
    expect(ok.status).toBe(200)

    expect((await call('POST', '/api/auth/sign-in/email', { email, password: PASSWORD })).status).toBe(401)
    const si = await call('POST', '/api/auth/sign-in/email', { email, password: 'new-password-123' })
    expect(si.status).toBe(200)
  })

  it('deletes the user', async () => {
    const { token, email } = await verifiedSession()
    const del = await call('POST', '/api/auth/delete-user', { password: PASSWORD }, { token })
    expect(del.status).toBe(200)
    const row = await baseEnv.DB.prepare('SELECT id FROM user WHERE email = ?').bind(email).first()
    expect(row).toBeNull()
    expect((await call('POST', '/api/auth/sign-in/email', { email, password: PASSWORD })).status).toBe(401)
  })

  it('rate limits, storing counters in the database', async () => {
    const email = uniqueEmail()
    const statuses: number[] = []
    for (let i = 0; i < 5; i++) {
      statuses.push((await call('POST', '/api/auth/sign-in/email', { email, password: 'x' }, { ip: '203.0.113.9' })).status)
    }
    expect(statuses).toContain(429)
    const row = await baseEnv.DB.prepare('SELECT count(*) AS n FROM rateLimit').first<{ n: number }>()
    expect(row!.n).toBeGreaterThan(0)
  })

  it('records emails in the dev outbox only without RESEND_API_KEY', () => {
    expect(devOutbox.length).toBeGreaterThan(0)
    expect(baseEnv.RESEND_API_KEY).toBeUndefined()
  })
})

describe('configuration', () => {
  it('has no social providers when unconfigured', async () => {
    const auth = await createAuth(baseEnv)
    expect(Object.keys(auth.options.socialProviders ?? {})).toEqual([])
    const r = await call('POST', '/api/auth/sign-in/social', { provider: 'google', callbackURL: 'https://auth.test/verified' })
    expect(r.status).toBeGreaterThanOrEqual(400)
    const r2 = await call('POST', '/api/auth/sign-in/social', { provider: 'apple', callbackURL: 'https://auth.test/verified' })
    expect(r2.status).toBeGreaterThanOrEqual(400)
  })

  it('enables google only with both secrets', async () => {
    expect(Object.keys((await createAuth({ ...baseEnv, GOOGLE_CLIENT_ID: 'id' })).options.socialProviders ?? {})).toEqual([])
    const auth = await createAuth({ ...baseEnv, GOOGLE_CLIENT_ID: 'id', GOOGLE_CLIENT_SECRET: 's' })
    expect(Object.keys(auth.options.socialProviders ?? {})).toEqual(['google'])
    const map = (auth.options.socialProviders as any).google.mapProfileToUser
    expect(map({ given_name: 'Sara', family_name: 'Levi' })).toEqual({ firstName: 'Sara', lastName: 'Levi' })
  })

  it('applies trusted origins, cookie domain, rate limit, linking', async () => {
    const auth = await createAuth({ ...baseEnv, COOKIE_DOMAIN: 'baderech.app' })
    expect(auth.options.trustedOrigins).toEqual(expect.arrayContaining(['mishna://', 'https://mishna.test']))
    expect(auth.options.advanced?.crossSubDomainCookies).toEqual({ enabled: true, domain: 'baderech.app' })
    expect(auth.options.rateLimit).toMatchObject({ enabled: true, storage: 'database' })
    expect(auth.options.account?.accountLinking?.trustedProviders).toEqual(['google', 'apple'])
    expect(uniqueEmail()).toContain('@')
  })
})
