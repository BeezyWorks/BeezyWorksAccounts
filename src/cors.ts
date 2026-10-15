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

/** Schemes that are never a valid app return target, even if someone lists them. */
const FORBIDDEN_SCHEMES = new Set(['http', 'https', 'javascript', 'data', 'file', 'blob', 'about', 'vbscript', 'ws', 'wss', 'ftp'])

/** A validated `return` URL: an exact-origin http(s) URL, or a custom-scheme app deep link. */
export interface ReturnTarget {
  url: URL
  /** True for custom-scheme (native app) returns; results go in the query, not the fragment. */
  native: boolean
}

/**
 * Validate a `return` URL for /start and /handoff. http(s) must match a TRUSTED_ORIGINS origin
 * exactly; a custom scheme must be listed there as `scheme://` (e.g. `siddurone://`). Anything
 * else, including unparseable values, returns null.
 */
export function parseReturnTarget(value: string | null, env: Env): ReturnTarget | null {
  if (!value) return null
  let url: URL
  try {
    url = new URL(value)
  } catch {
    return null
  }
  if (url.protocol === 'http:' || url.protocol === 'https:') {
    return trustedHttpOrigin(url.origin, env) ? { url, native: false } : null
  }
  const scheme = url.protocol.slice(0, -1)
  if (FORBIDDEN_SCHEMES.has(scheme) || !/^[a-z][a-z0-9+.-]*:\/\//i.test(value) || url.username || url.password) return null
  const listed = parseList(env.TRUSTED_ORIGINS).some((o) => o.toLowerCase() === `${scheme}://`)
  return listed ? { url, native: true } : null
}

/** Append result params to a return URL: query for native deep links, `fragment` for web when asked. */
export function withResult(target: ReturnTarget, params: Record<string, string>, where: 'fragment' | 'query'): string {
  const u = new URL(target.url)
  u.hash = ''
  if (where === 'query' || target.native || Object.keys(params).length === 0) {
    for (const [k, v] of Object.entries(params)) u.searchParams.set(k, v)
    return u.toString()
  }
  return `${u.toString()}#${new URLSearchParams(params).toString()}`
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

