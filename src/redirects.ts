import { parseList, type Env } from './env'

/**
 * Redirect URIs a dynamically registered OAuth client may use (`MCP_REDIRECT_URIS`, comma-separated).
 * Entries: an exact URI; `https://host/path/*` (any suffix after the prefix); or
 * `http://localhost:*` (any port and path, for dev; the defaults leave loopback out).
 */
export function redirectAllowed(uri: unknown, env: Env): boolean {
  if (typeof uri !== 'string' || uri.includes('#')) return false
  let u: URL
  try {
    u = new URL(uri)
  } catch {
    return false
  }
  if (u.username || u.password || (u.protocol !== 'https:' && u.protocol !== 'http:')) return false
  return parseList(env.MCP_REDIRECT_URIS).some((entry) => {
    if (entry.endsWith(':*')) {
      const base = entry.slice(0, -2)
      return u.protocol + '//' + u.hostname === base && u.port !== ''
    }
    if (entry.endsWith('*')) return uri.startsWith(entry.slice(0, -1)) && !uri.slice(entry.length - 1).includes('..')
    return uri === entry
  })
}

/** Pre-handler for POST /api/auth/oauth2/register: a 400 `invalid_redirect_uri` response, or null to continue. */
export async function checkRegistration(request: Request, env: Env): Promise<Response | null> {
  const body = (await request.clone().json().catch(() => null)) as { redirect_uris?: unknown } | null
  const uris = body?.redirect_uris
  const bad = !Array.isArray(uris) || uris.length === 0 || uris.find((u) => !redirectAllowed(u, env))
  if (!bad) return null
  return Response.json(
    {
      error: 'invalid_redirect_uri',
      error_description: 'This redirect URI is not on the list of apps allowed to connect to BeezyWorks apps.',
    },
    { status: 400, headers: { 'cache-control': 'no-store' } },
  )
}
