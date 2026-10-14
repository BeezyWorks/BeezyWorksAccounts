/** Worker bindings: D1, plain vars (wrangler.jsonc) and secrets (`wrangler secret put`). */
export interface Env {
  DB: D1Database

  // Secrets
  BETTER_AUTH_SECRET: string
  RESEND_API_KEY?: string
  GOOGLE_CLIENT_ID?: string
  GOOGLE_CLIENT_SECRET?: string
  APPLE_TEAM_ID?: string
  APPLE_KEY_ID?: string
  /** Contents of the Apple .p8 key (literal "\n" sequences are accepted). */
  APPLE_PRIVATE_KEY?: string

  // Vars
  BETTER_AUTH_URL: string
  EMAIL_FROM?: string
  /** Comma-separated origins / app schemes, e.g. `mishna://,https://mishna.baderech.app`. */
  TRUSTED_ORIGINS?: string
  /** Parent domain for cross-subdomain cookies, e.g. `baderech.app`. */
  COOKIE_DOMAIN?: string
  /** Apple Services ID (web/Android client_id). */
  APPLE_SERVICES_ID?: string
  /** Comma-separated iOS bundle IDs whose native id tokens are accepted. */
  APPLE_APP_BUNDLE_IDS?: string
}

export const DEFAULT_EMAIL_FROM = 'Baderech <noreply@baderech.app>'

export function parseList(value: string | undefined): string[] {
  return (value ?? '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)
}
