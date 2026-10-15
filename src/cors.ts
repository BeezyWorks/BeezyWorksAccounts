import { parseList, type Env } from './env'

export const CORS_METHODS = 'GET, POST, PUT, DELETE, OPTIONS'

/** The request's Origin if it is an http(s) origin listed in TRUSTED_ORIGINS, else null. */
export function allowedOrigin(request: Request, env: Env): string | null {
  return trustedHttpOrigin(request.headers.get('origin'), env)
}

/** The origin of `value` if it is an http(s) URL whose origin is listed in TRUSTED_ORIGINS, else null. */
export function trustedHttpOrigin(value: string | null, env: Env): string | null {
  if (!value) return null
  const origin = value
  try {
    const u = new URL(origin)
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return null
    return parseList(env.TRUSTED_ORIGINS).includes(u.origin) ? u.origin : null
  } catch {
    return null
  }
}

/** Better Auth only emits Access-Control-Expose-Headers (bearer plugin), so own the rest here. */
export function withCors(res: Response, origin: string | null): Response {
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

