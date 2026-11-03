import { createHash, randomBytes } from 'node:crypto'
import { calculateJwkThumbprint, createLocalJWKSet, exportJWK, generateKeyPair, jwtVerify, SignJWT } from 'jose'
import { requireMcpAuth } from '@better-auth/mcp'
import { describe, expect, it } from 'vitest'
import { createAuth, MCP_RESOURCE } from '../src/auth'
import worker from '../src/index'
import { baseEnv, call, ORIGIN, PASSWORD, signUp, lastMail, verifiedSession } from './helpers'

const REDIRECT = 'https://claude.example/api/mcp/auth_callback'
const ISSUER = `${ORIGIN}/api/auth`
const b64u = (b: Buffer) => b.toString('base64url')

/** A tiny browser: keeps cookies, never follows redirects on its own. */
class Browser {
  jar = new Map<string, string>()
  async fetch(path: string, init: RequestInit = {}) {
    const headers = new Headers(init.headers)
    headers.set('cf-connecting-ip', `10.9.${Math.floor(Math.random() * 250)}.${Math.floor(Math.random() * 250)}`)
    if (this.jar.size) headers.set('cookie', [...this.jar].map(([k, v]) => `${k}=${v}`).join('; '))
    const res = await worker.fetch(new Request(new URL(path, ORIGIN), { ...init, headers, redirect: 'manual' }), baseEnv)
    for (const c of res.headers.getSetCookie()) {
      const [kv] = c.split(';')
      const i = kv.indexOf('=')
      this.jar.set(kv.slice(0, i), kv.slice(i + 1))
    }
    return res
  }
  post(path: string, body: unknown) {
    return this.fetch(path, {
      method: 'POST',
      headers: { 'content-type': 'application/json', origin: ORIGIN },
      body: JSON.stringify(body),
    })
  }
}

async function registerClient(extra: Record<string, unknown> = {}) {
  const r = await call('POST', '/api/auth/oauth2/register', {
    client_name: 'Claude',
    redirect_uris: [REDIRECT],
    token_endpoint_auth_method: 'none',
    grant_types: ['authorization_code', 'refresh_token'],
    response_types: ['code'],
    scope: 'openid offline_access beitecha:write',
    ...extra,
  })
  return r
}

const pkce = () => {
  const verifier = b64u(randomBytes(32))
  return { verifier, challenge: b64u(createHash('sha256').update(verifier).digest()) }
}

/** Full authorization-code + PKCE flow through the Worker pages' API calls; returns the token response. */
async function authorize(opts: { clientId: string; scope?: string; resource?: string; dpopJkt?: string }) {
  const { email } = await signUp()
  const link = new URL(lastMail().link)
  await call('GET', link.pathname + link.search)

  const b = new Browser()
  const { verifier, challenge } = pkce()
  const q = new URLSearchParams({
    response_type: 'code',
    client_id: opts.clientId,
    redirect_uri: REDIRECT,
    scope: opts.scope ?? 'openid offline_access beitecha:write',
    state: 'xyz',
    code_challenge: challenge,
    code_challenge_method: 'S256',
    resource: opts.resource ?? MCP_RESOURCE,
  })
  if (opts.dpopJkt) q.set('dpop_jkt', opts.dpopJkt)
  // 1. Not signed in: bounced to our sign-in page with a signed query.
  const a1 = await b.fetch(`/api/auth/oauth2/authorize?${q}`)
  expect(a1.status).toBe(302)
  const signIn = new URL(a1.headers.get('location')!, ORIGIN)
  expect(signIn.pathname).toBe('/oauth/sign-in')
  expect(signIn.searchParams.get('sig')).toBeTruthy()
  // The sign-in page itself renders.
  expect((await b.fetch(signIn.pathname + signIn.search)).status).toBe(200)
  // 2. The page forwards the signed params as oauth_query.
  const names = signIn.searchParams.getAll('ba_param')
  const oauth_query = new URLSearchParams(
    [...signIn.searchParams].filter(([k]) => k === 'sig' || k === 'ba_param' || names.includes(k)),
  ).toString()
  const si = await b.post('/api/auth/sign-in/email', { email, password: PASSWORD, oauth_query })
  expect(si.status).toBe(200)
  const siBody: any = await si.json()
  expect(siBody.redirect).toBe(true)
  const consent = new URL(siBody.url, ORIGIN)
  expect(consent.pathname).toBe('/oauth/consent')
  expect((await b.fetch(consent.pathname + consent.search)).status).toBe(200)
  // 3. Consent.
  const cnames = consent.searchParams.getAll('ba_param')
  const cq = new URLSearchParams(
    [...consent.searchParams].filter(([k]) => k === 'sig' || k === 'ba_param' || cnames.includes(k)),
  ).toString()
  const pub = await b.fetch(`/api/auth/oauth2/public-client?client_id=${opts.clientId}`)
  expect(((await pub.json()) as any).client_name).toBe('Claude')
  const co = await b.post('/api/auth/oauth2/consent', { accept: true, oauth_query: cq })
  expect(co.status).toBe(200)
  const back = new URL(((await co.json()) as any).url)
  expect(back.origin + back.pathname).toBe(REDIRECT)
  expect(back.searchParams.get('state')).toBe('xyz')
  const code = back.searchParams.get('code')!
  expect(code).toBeTruthy()
  return { code, verifier, email, browser: b }
}

async function token(form: Record<string, string>, headers: Record<string, string> = {}) {
  const res = await worker.fetch(
    new Request(`${ORIGIN}/api/auth/oauth2/token`, {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        'cf-connecting-ip': `10.8.${Math.floor(Math.random() * 250)}.${Math.floor(Math.random() * 250)}`,
        ...headers,
      },
      body: new URLSearchParams(form),
    }),
    baseEnv,
  )
  return { status: res.status, data: (await res.json()) as any }
}

const jwks = async () => createLocalJWKSet((await call('GET', '/api/auth/jwks')).data)

describe('oauth discovery', () => {
  it('publishes authorization server metadata at both issuer-path aliases', async () => {
    for (const path of [
      '/.well-known/oauth-authorization-server/api/auth',
      '/api/auth/.well-known/oauth-authorization-server',
      '/api/auth/.well-known/openid-configuration',
    ]) {
      const r = await call('GET', path)
      expect(r.status, path).toBe(200)
      expect(r.data).toMatchObject({
        issuer: ISSUER,
        authorization_endpoint: `${ISSUER}/oauth2/authorize`,
        token_endpoint: `${ISSUER}/oauth2/token`,
        registration_endpoint: `${ISSUER}/oauth2/register`,
        jwks_uri: `${ISSUER}/jwks`,
      })
      expect(r.data.code_challenge_methods_supported).toEqual(['S256'])
      expect(r.data.scopes_supported).toEqual(expect.arrayContaining(['beitecha:write', 'offline_access']))
      expect(r.data.grant_types_supported).toEqual(expect.arrayContaining(['authorization_code', 'refresh_token']))
      expect(r.data.scopes_supported).not.toContain('email')
    }
  })

  it('publishes protected resource metadata for the MCP resource', async () => {
    const r = await call('GET', '/.well-known/oauth-protected-resource')
    expect(r.status).toBe(200)
    expect(r.data.resource).toBe(MCP_RESOURCE)
    expect(r.data.authorization_servers).toEqual([ISSUER])
    expect(r.data.scopes_supported).toContain('beitecha:write')
  })

  it('serves a JWKS Beitecha can verify with', async () => {
    const r = await call('GET', '/api/auth/jwks')
    expect(r.status).toBe(200)
    expect(r.data.keys.length).toBeGreaterThan(0)
    expect(r.data.keys[0]).not.toHaveProperty('d')
  })
})

describe('oauth pages', () => {
  it('render with the same hardening as the other pages', async () => {
    for (const p of ['/oauth/sign-in', '/oauth/consent']) {
      const res = await worker.fetch(new Request(`${ORIGIN}${p}`), baseEnv)
      expect(res.status).toBe(200)
      expect(res.headers.get('content-security-policy')).toContain("default-src 'none'")
      expect(res.headers.get('cache-control')).toBe('no-store')
      expect(await res.text()).toContain('<title>')
    }
  })
})

describe('authorization code + PKCE', () => {
  it('rejects registration of an unknown resource and an out-of-policy scope', async () => {
    const r = await registerClient({ scope: 'openid email' })
    expect(r.status).toBeGreaterThanOrEqual(400)
  })

  it('issues an audience- and scope-bound JWT, refreshes it, and rotates the refresh token', async () => {
    const reg = await registerClient()
    expect(reg.status).toBe(201)
    const clientId = reg.data.client_id as string
    expect(reg.data.client_secret).toBeUndefined()

    const { code, verifier } = await authorize({ clientId })
    const t = await token({
      grant_type: 'authorization_code',
      code,
      code_verifier: verifier,
      redirect_uri: REDIRECT,
      client_id: clientId,
      resource: MCP_RESOURCE,
    })
    expect(t.status).toBe(200)
    expect(t.data.token_type.toLowerCase()).toBe('bearer')
    expect(t.data.refresh_token).toBeTruthy()
    const { payload } = await jwtVerify(t.data.access_token, await jwks(), { issuer: ISSUER, audience: MCP_RESOURCE })
    expect(payload.scope).toContain('beitecha:write')
    expect(payload.azp).toBe(clientId)
    expect(payload.sub).toBeTruthy()

    const r = await token({ grant_type: 'refresh_token', refresh_token: t.data.refresh_token, client_id: clientId, resource: MCP_RESOURCE })
    expect(r.status).toBe(200)
    expect(r.data.refresh_token).toBeTruthy()
    const refreshed = await jwtVerify(r.data.access_token, await jwks(), { issuer: ISSUER, audience: MCP_RESOURCE })
    expect(refreshed.payload.scope).toContain('beitecha:write')
    expect(refreshed.payload.sub).toBe(payload.sub)

    // The code is single use (and replaying it is an attack signal).
    expect(
      (await token({ grant_type: 'authorization_code', code, code_verifier: verifier, redirect_uri: REDIRECT, client_id: clientId, resource: MCP_RESOURCE })).status,
    ).toBeGreaterThanOrEqual(400)

    // A token for Beitecha is not a Baderech session: no bearer-session use anywhere.
    const s = await call('GET', '/api/auth/get-session', undefined, { token: t.data.access_token })
    expect(s.data).toBeNull()
    expect((await call('GET', '/api/data/anything', undefined, { token: t.data.access_token })).status).toBe(401)
  })

  it('does not issue a token without PKCE, with a wrong verifier, or for another resource', async () => {
    const clientId = (await registerClient()).data.client_id as string
    const noPkce = await new Browser().fetch(
      `/api/auth/oauth2/authorize?${new URLSearchParams({ response_type: 'code', client_id: clientId, redirect_uri: REDIRECT, scope: 'openid', state: 's' })}`,
    )
    expect(noPkce.headers.get('location') ?? '').not.toContain('/oauth/sign-in')

    const { code } = await authorize({ clientId })
    const bad = await token({ grant_type: 'authorization_code', code, code_verifier: 'x'.repeat(50), redirect_uri: REDIRECT, client_id: clientId, resource: MCP_RESOURCE })
    expect(bad.status).toBeGreaterThanOrEqual(400)

    const other = await new Browser().fetch(
      `/api/auth/oauth2/authorize?${new URLSearchParams({ response_type: 'code', client_id: clientId, redirect_uri: REDIRECT, scope: 'openid', state: 's', code_challenge: 'a'.repeat(43), code_challenge_method: 'S256', resource: 'https://evil.example/mcp' })}`,
    )
    expect(other.headers.get('location') ?? '').not.toContain('/oauth/sign-in')
  })

  it('rejects an unregistered redirect uri', async () => {
    const clientId = (await registerClient()).data.client_id as string
    const res = await new Browser().fetch(
      `/api/auth/oauth2/authorize?${new URLSearchParams({ response_type: 'code', client_id: clientId, redirect_uri: 'https://evil.example/cb', scope: 'openid', state: 's', code_challenge: 'a'.repeat(43), code_challenge_method: 'S256', resource: MCP_RESOURCE })}`,
    )
    expect(res.headers.get('location') ?? '').not.toContain('evil.example')
  })

  it('a denied consent returns access_denied to the client', async () => {
    const clientId = (await registerClient()).data.client_id as string
    const { email } = await signUp()
    await call('GET', new URL(lastMail().link).pathname + new URL(lastMail().link).search)
    const b = new Browser()
    const { challenge } = pkce()
    const a1 = await b.fetch(
      `/api/auth/oauth2/authorize?${new URLSearchParams({ response_type: 'code', client_id: clientId, redirect_uri: REDIRECT, scope: 'openid beitecha:write', state: 's', code_challenge: challenge, code_challenge_method: 'S256', resource: MCP_RESOURCE })}`,
    )
    const si = new URL(a1.headers.get('location')!, ORIGIN)
    const names = si.searchParams.getAll('ba_param')
    const oq = (u: URL, n: string[]) =>
      new URLSearchParams([...u.searchParams].filter(([k]) => k === 'sig' || k === 'ba_param' || n.includes(k))).toString()
    const r1: any = await (await b.post('/api/auth/sign-in/email', { email, password: PASSWORD, oauth_query: oq(si, names) })).json()
    const consent = new URL(r1.url, ORIGIN)
    const r2: any = await (
      await b.post('/api/auth/oauth2/consent', { accept: false, oauth_query: oq(consent, consent.searchParams.getAll('ba_param')) })
    ).json()
    const back = new URL(r2.url)
    expect(back.searchParams.get('error')).toBe('access_denied')
    expect(back.searchParams.get('code')).toBeNull()
  })
})

describe('existing sign-in is untouched', () => {
  it('still hands out session bearer tokens that work on get-session', async () => {
    const { token: t, user } = await verifiedSession()
    expect((await call('GET', '/api/auth/get-session', undefined, { token: t })).data.user.id).toBe(user.id)
    expect((await call('GET', '/api/data/x', undefined, { token: t })).status).toBe(200)
  })
})

describe('d1: dpop replay protection', () => {
  it('stores proof ids in D1 and refuses a replayed proof', async () => {
    const clientId = (await registerClient({ dpop_bound_access_tokens: true })).data.client_id as string
    const { publicKey, privateKey } = await generateKeyPair('ES256', { extractable: true })
    const jwk = await exportJWK(publicKey)
    const jkt = await calculateJwkThumbprint(jwk)
    const proof = async (htm: string, htu: string, extra: Record<string, unknown> = {}, jti = crypto.randomUUID()) =>
      new SignJWT({ htm, htu, jti, ...extra })
        .setProtectedHeader({ alg: 'ES256', typ: 'dpop+jwt', jwk })
        .setIssuedAt()
        .sign(privateKey)

    const { code, verifier } = await authorize({ clientId, dpopJkt: jkt })
    const t = await token(
      { grant_type: 'authorization_code', code, code_verifier: verifier, redirect_uri: REDIRECT, client_id: clientId, resource: MCP_RESOURCE },
      { dpop: await proof('POST', `${ISSUER}/oauth2/token`) },
    )
    expect(t.status, JSON.stringify(t.data)).toBe(200)
    expect(t.data.token_type.toLowerCase()).toBe('dpop')

    const auth = await createAuth(baseEnv)
    const handler = requireMcpAuth(auth, async (_req, claims) => Response.json({ sub: claims.sub }), {
      resource: MCP_RESOURCE,
      issuer: ISSUER,
      jwksUrl: `${ISSUER}/jwks`,
      requiredScopes: ['beitecha:write'],
    })
    const ath = createHash('sha256').update(t.data.access_token).digest('base64url')
    const jti = crypto.randomUUID()
    const call1 = async () =>
      handler(
        new Request(MCP_RESOURCE, {
          method: 'POST',
          headers: { authorization: `DPoP ${t.data.access_token}`, dpop: await proof('POST', MCP_RESOURCE, { ath }, jti) },
        }),
      )
    const origFetch = globalThis.fetch
    // requireMcpAuth fetches the JWKS over HTTP; serve it from this Worker.
    globalThis.fetch = (async (input: any, init?: any) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url
      if (url === `${ISSUER}/jwks`) return worker.fetch(new Request(url), baseEnv)
      return origFetch(input, init)
    }) as typeof fetch
    try {
      const first = await call1()
      expect(first.status, await first.clone().text()).toBe(200)
      expect(((await first.json()) as any).sub).toBeTruthy()
      const replay = await call1()
      expect(replay.status).toBe(401)
      // Proof ids live in the existing verification table (no extra schema).
      const rows = await baseEnv.DB.prepare("SELECT COUNT(*) AS n FROM verification WHERE identifier LIKE 'dpop-proof:%'").first<{ n: number }>()
      expect(rows!.n).toBeGreaterThan(0)
    } finally {
      globalThis.fetch = origFetch
    }
  })
})
