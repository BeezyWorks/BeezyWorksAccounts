import { AUTH_BASE_PATH, createAuth } from './auth'
import { DATA_BASE_PATH, handleData } from './data'
import { parseList, type Env } from './env'
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

const CORS_METHODS = 'GET, POST, PUT, DELETE, OPTIONS'

/** The request's Origin if it is an http(s) origin listed in TRUSTED_ORIGINS, else null. */
function allowedOrigin(request: Request, env: Env): string | null {
  const origin = request.headers.get('origin')
  if (!origin) return null
  try {
    const u = new URL(origin)
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return null
    return parseList(env.TRUSTED_ORIGINS).includes(u.origin) ? u.origin : null
  } catch {
    return null
  }
}

/** Better Auth only emits Access-Control-Expose-Headers (bearer plugin), so own the rest here. */
function withCors(res: Response, origin: string | null): Response {
  const out = new Response(res.body, res)
  out.headers.append('vary', 'Origin')
  if (!origin) return out
  const expose = new Set(
    (out.headers.get('access-control-expose-headers') ?? '').split(',').map((h) => h.trim().toLowerCase()).filter(Boolean),
  )
  expose.add('set-auth-token')
  out.headers.set('access-control-allow-origin', origin)
  out.headers.set('access-control-allow-credentials', 'true')
  out.headers.set('access-control-expose-headers', [...expose].join(', '))
  return out
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url)
    const { pathname } = url

    if (pathname === '/health') return Response.json({ ok: true })
    if (request.method === 'GET' || request.method === 'HEAD') {
      if (pathname === '/reset-password') return html(resetPasswordPage(url.searchParams.get('token')))
      if (pathname === '/verified') return html(verifiedPage())
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
