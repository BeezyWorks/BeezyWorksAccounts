import { AUTH_BASE_PATH, createAuth } from './auth'
import { DATA_BASE_PATH, handleData } from './data'
import { CORS_METHODS, withCors, allowedOrigin } from './cors'
import { handleHandoff } from './handoff'
import { handleStart } from './start'
import type { Env } from './env'
import { resetPasswordPage, verifiedPage } from './pages'

export type { Env } from './env'

const html = (body: string) =>
  new Response(body, {
    headers: {
      'content-type': 'text/html; charset=utf-8',
      'cache-control': 'no-store',
      'referrer-policy': 'no-referrer',
      'content-security-policy':
        "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; form-action 'none'; base-uri 'none'",
    },
  })

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url)
    const { pathname } = url

    if (pathname === '/health') return Response.json({ ok: true })
    if (request.method === 'GET' || request.method === 'HEAD') {
      if (pathname === '/reset-password') return html(resetPasswordPage(url.searchParams.get('token')))
      if (pathname === '/verified') return html(verifiedPage())
      if (pathname === '/handoff') return handleHandoff(request, env)
      if (pathname.startsWith('/start/')) return handleStart(request, env, pathname.slice('/start/'.length))
    }
    const isAuth = pathname === AUTH_BASE_PATH || pathname.startsWith(`${AUTH_BASE_PATH}/`)
    const isData = pathname === DATA_BASE_PATH || pathname.startsWith(`${DATA_BASE_PATH}/`)
    if (isAuth || isData) {
      const origin = allowedOrigin(request, env)
      if (request.method === 'OPTIONS' && request.headers.has('access-control-request-method')) {
        const res = new Response(null, {
          status: 204,
          headers: {
            'access-control-allow-methods': CORS_METHODS,
            'access-control-allow-headers': 'content-type, authorization',
            'access-control-max-age': '86400',
          },
        })
        return withCors(res, origin)
      }
      if (isData) return withCors(await handleData(request, env), origin)
      const auth = await createAuth(env)
      return withCors(await auth.handler(request), origin)
    }
    return new Response('Not found', { status: 404 })
  },
}
