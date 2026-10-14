import { env } from 'cloudflare:workers'
import { exportPKCS8, generateKeyPair } from 'jose'
import worker from '../src/index'
import type { Env } from '../src/env'
import { devOutbox } from '../src/email'

export const baseEnv = env as unknown as Env
export const ORIGIN = 'https://auth.test'

export async function call(
  method: string,
  path: string,
  body?: unknown,
  opts: { token?: string; env?: Env; ip?: string } = {},
) {
  const res = await worker.fetch(
    new Request(`${ORIGIN}${path}`, {
      method,
      headers: {
        'content-type': 'application/json',
        origin: ORIGIN,
        // Distinct client per call unless a test pins one (rate limits are per IP).
        'cf-connecting-ip': opts.ip ?? `10.0.${Math.floor(ipN / 250) % 250}.${ipN++ % 250}`,
        ...(opts.token ? { authorization: `Bearer ${opts.token}` } : {}),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
      redirect: 'manual',
    }),
    opts.env ?? baseEnv,
  )
  const text = await res.text()
  let data: any = null
  try {
    data = text ? JSON.parse(text) : null
  } catch {
    data = text
  }
  return { status: res.status, data, headers: res.headers }
}

let ipN = 1
let n = 0
export const uniqueEmail = () => `user${Date.now()}${n++}@example.test`
export const PASSWORD = 'correct-horse-battery'

export const lastMail = () => devOutbox[devOutbox.length - 1]

export async function signUp(email = uniqueEmail(), extra: Record<string, unknown> = {}) {
  const r = await call('POST', '/api/auth/sign-up/email', { email, password: PASSWORD, name: 'Temp', ...extra })
  return { email, ...r }
}

/** Sign up, follow the captured verification link, sign in; returns a bearer token. */
export async function verifiedSession(extra: Record<string, unknown> = {}) {
  const { email } = await signUp(undefined, extra)
  const link = new URL(lastMail().link)
  await call('GET', link.pathname + link.search)
  const si = await call('POST', '/api/auth/sign-in/email', { email, password: PASSWORD })
  if (si.status !== 200) throw new Error(`sign-in failed ${si.status} ${JSON.stringify(si.data)}`)
  const token = si.headers.get('set-auth-token') as string
  return { email, token, user: si.data.user }
}

export async function appleKeyPem() {
  const { privateKey } = await generateKeyPair('ES256', { extractable: true })
  return exportPKCS8(privateKey)
}

export async function appleEnv(): Promise<Env> {
  return {
    ...baseEnv,
    APPLE_TEAM_ID: 'TEAM123456',
    APPLE_KEY_ID: 'KEY1234567',
    APPLE_PRIVATE_KEY: await appleKeyPem(),
    APPLE_SERVICES_ID: 'app.baderech.services',
    APPLE_APP_BUNDLE_IDS: 'app.baderech.mishna, app.baderech.siddur',
  }
}
