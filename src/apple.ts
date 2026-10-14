import { importPKCS8, SignJWT } from 'jose'
import { parseList, type Env } from './env'

const APPLE_ISSUER = 'https://appleid.apple.com'
/** Apple allows up to 6 months; use ~5 and refresh with a 30-day margin. */
const LIFETIME_SECONDS = 60 * 60 * 24 * 150
const REFRESH_MARGIN_SECONDS = 60 * 60 * 24 * 30

export interface AppleConfig {
  teamId: string
  keyId: string
  privateKey: string
  /** client_id used for web/Android flows and as the JWT `sub`. */
  clientId: string
  /** All accepted id-token audiences (services id + iOS bundle ids). */
  audiences: string[]
}

/** Apple is enabled only when the key material and at least one client id are present. */
export function getAppleConfig(env: Env): AppleConfig | null {
  const bundleIds = parseList(env.APPLE_APP_BUNDLE_IDS)
  const servicesId = env.APPLE_SERVICES_ID?.trim() || undefined
  const clientId = servicesId ?? bundleIds[0]
  if (!env.APPLE_TEAM_ID || !env.APPLE_KEY_ID || !env.APPLE_PRIVATE_KEY || !clientId) return null
  return {
    teamId: env.APPLE_TEAM_ID,
    keyId: env.APPLE_KEY_ID,
    privateKey: env.APPLE_PRIVATE_KEY.replace(/\\n/g, '\n'),
    clientId,
    audiences: [...new Set([...(servicesId ? [servicesId] : []), ...bundleIds])],
  }
}

interface Cached {
  fingerprint: string
  token: string
  exp: number
}
let cached: Cached | undefined

/** Test helper. */
export function resetAppleSecretCache() {
  cached = undefined
}

/**
 * The Apple "client secret": a short-lived ES256 JWT signed with the .p8 key.
 * Cached in module scope and regenerated 30 days before it expires, so nobody
 * has to rotate anything by hand.
 */
export async function getAppleClientSecret(cfg: AppleConfig, nowMs = Date.now()): Promise<string> {
  const now = Math.floor(nowMs / 1000)
  const fingerprint = `${cfg.teamId}|${cfg.keyId}|${cfg.clientId}|${cfg.privateKey.length}`
  if (cached && cached.fingerprint === fingerprint && cached.exp - REFRESH_MARGIN_SECONDS > now) {
    return cached.token
  }
  const key = await importPKCS8(cfg.privateKey, 'ES256')
  const exp = now + LIFETIME_SECONDS
  const token = await new SignJWT({})
    .setProtectedHeader({ alg: 'ES256', kid: cfg.keyId })
    .setIssuer(cfg.teamId)
    .setSubject(cfg.clientId)
    .setAudience(APPLE_ISSUER)
    .setIssuedAt(now)
    .setExpirationTime(exp)
    .sign(key)
  cached = { fingerprint, token, exp }
  return token
}

/**
 * Revoke an Apple token (required by App Store guidelines on account deletion).
 * Never throws: failures are logged and deletion proceeds.
 */
export async function revokeAppleToken(
  cfg: AppleConfig,
  token: string,
  hint: 'refresh_token' | 'access_token',
): Promise<boolean> {
  try {
    const body = new URLSearchParams({
      client_id: cfg.clientId,
      client_secret: await getAppleClientSecret(cfg),
      token,
      token_type_hint: hint,
    })
    const res = await fetch(`${APPLE_ISSUER}/auth/revoke`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body,
    })
    if (!res.ok) {
      console.error(`[apple] token revoke failed (${res.status})`)
      return false
    }
    return true
  } catch (e) {
    console.error('[apple] token revoke error', e instanceof Error ? e.message : e)
    return false
  }
}
