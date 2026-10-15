import { AUTH_BASE_PATH, createAuth } from './auth'
import { trustedHttpOrigin } from './cors'
import type { Env } from './env'

const headers = { 'cache-control': 'no-store', 'referrer-policy': 'no-referrer' }
const PROVIDERS = new Set(['google', 'apple'])

const plain = (body: string, status: number) =>
  new Response(body, { status, headers: { ...headers, 'content-type': 'text/plain; charset=utf-8' } })

/**
 * Starts web social sign-in from a top-level navigation on the auth origin:
 * `GET /start/:provider?return=<url>`. Better Auth keeps the OAuth state in a cookie, and a
 * cookie set on a cross-site fetch from another site (e.g. siddur.one) is dropped by the
 * browser, so starting with `POST /api/auth/sign-in/social` from that site always ends in
 * "state mismatch". Here the cookie is first-party. After the provider, the user goes through
 * /handoff back to `return` with a one-time token; failures land on `return?error=<code>`.
 */
export async function handleStart(request: Request, env: Env, provider: string): Promise<Response> {
  if (!PROVIDERS.has(provider)) return plain('Unknown provider', 404)
  const url = new URL(request.url)
  const returnTo = url.searchParams.get('return')
  let target: URL | null = null
  try {
    target = returnTo ? new URL(returnTo) : null
  } catch {
    // invalid
  }
  if (!target || !trustedHttpOrigin(target.origin, env)) return plain('Invalid return URL', 400)
  target.hash = ''

  const handoff = new URL('/handoff', url.origin)
  handoff.searchParams.set('return', target.toString())

  const auth = await createAuth(env)
  const forwarded = new Headers({ 'content-type': 'application/json', origin: url.origin })
  for (const name of ['cookie', 'user-agent', 'cf-connecting-ip', 'x-forwarded-for']) {
    const value = request.headers.get(name)
    if (value) forwarded.set(name, value)
  }
  const res = await auth.handler(
    new Request(new URL(`${AUTH_BASE_PATH}/sign-in/social`, url.origin), {
      method: 'POST',
      headers: forwarded,
      body: JSON.stringify({
        provider,
        callbackURL: handoff.toString(),
        errorCallbackURL: target.toString(),
        disableRedirect: true,
      }),
    }),
  )
  const body = (await res.json().catch(() => null)) as { url?: string } | null
  if (!res.ok || !body?.url) {
    console.error('[start] sign-in/social failed', res.status, body)
    target.searchParams.set('error', 'start_failed')
    return new Response(null, { status: 302, headers: { ...headers, location: target.toString() } })
  }
  const out = new Headers({ ...headers, location: body.url })
  for (const cookie of res.headers.getSetCookie()) out.append('set-cookie', cookie)
  return new Response(null, { status: 302, headers: out })
}
