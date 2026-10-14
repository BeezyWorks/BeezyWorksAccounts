import { AUTH_BASE_PATH, createAuth } from './auth'
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
    }
    if (pathname === AUTH_BASE_PATH || pathname.startsWith(`${AUTH_BASE_PATH}/`)) {
      const auth = await createAuth(env)
      return auth.handler(request)
    }
    return new Response('Not found', { status: 404 })
  },
}
