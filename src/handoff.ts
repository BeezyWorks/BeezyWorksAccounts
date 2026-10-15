import { createAuth } from './auth'
import { parseReturnTarget, withResult } from './cors'
import type { Env } from './env'

const headers = { 'cache-control': 'no-store', 'referrer-policy': 'no-referrer' }

/**
 * Web social sign-in ends with a session cookie on the auth origin, which a page on another
 * site (e.g. siddur.one) cannot use. The page sends the browser here after sign-in; we trade
 * the cookie session for a one-time token and bounce back to `return` with it in the fragment
 * (never sent to a server). The page then POSTs it to /api/auth/one-time-token/verify.
 * Custom-scheme (native app) returns get `?ott=` / `?error=` in the query instead, since
 * fragments are unreliable through iOS/Android deep links and expo-router.
 */
export async function handleHandoff(request: Request, env: Env): Promise<Response> {
  const target = parseReturnTarget(new URL(request.url).searchParams.get('return'), env)
  if (!target) {
    return new Response('Invalid return URL', { status: 400, headers: { ...headers, 'content-type': 'text/plain; charset=utf-8' } })
  }

  let result: Record<string, string> = { error: 'no_session' }
  try {
    const auth = await createAuth(env)
    const session = await auth.api.getSession({ headers: request.headers })
    if (session?.user) {
      const { token } = await auth.api.generateOneTimeToken({ headers: request.headers })
      result = { ott: token }
    }
  } catch (e) {
    console.error('[handoff] failed', e instanceof Error ? e.message : e)
    result = { error: 'handoff_failed' }
  }
  return new Response(null, { status: 302, headers: { ...headers, location: withResult(target, result, 'fragment') } })
}
