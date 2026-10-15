import { createAuth } from './auth'
import { trustedHttpOrigin } from './cors'
import type { Env } from './env'

const headers = { 'cache-control': 'no-store', 'referrer-policy': 'no-referrer' }

/**
 * Web social sign-in ends with a session cookie on the auth origin, which a page on another
 * site (e.g. siddur.one) cannot use. The page sends the browser here after sign-in; we trade
 * the cookie session for a one-time token and bounce back to `return` with it in the fragment
 * (never sent to a server). The page then POSTs it to /api/auth/one-time-token/verify.
 */
export async function handleHandoff(request: Request, env: Env): Promise<Response> {
  const returnTo = new URL(request.url).searchParams.get('return')
  let target: URL | null = null
  try {
    target = returnTo ? new URL(returnTo) : null
  } catch {
    // invalid
  }
  if (!target || !trustedHttpOrigin(target.origin, env)) {
    return new Response('Invalid return URL', { status: 400, headers: { ...headers, 'content-type': 'text/plain; charset=utf-8' } })
  }
  target.hash = ''
  const base = target.toString()

  let fragment = 'error=no_session'
  try {
    const auth = await createAuth(env)
    const session = await auth.api.getSession({ headers: request.headers })
    if (session?.user) {
      const { token } = await auth.api.generateOneTimeToken({ headers: request.headers })
      fragment = `ott=${encodeURIComponent(token)}`
    }
  } catch (e) {
    console.error('[handoff] failed', e instanceof Error ? e.message : e)
    fragment = 'error=handoff_failed'
  }
  return new Response(null, { status: 302, headers: { ...headers, location: `${base}#${fragment}` } })
}
