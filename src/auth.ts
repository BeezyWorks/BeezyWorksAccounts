import { expo } from '@better-auth/expo'
import { betterAuth } from 'better-auth'
import { bearer, oneTimeToken } from 'better-auth/plugins'
import { decodeJwt } from 'jose'
import { deleteUserData } from './data'
import { getAppleClientSecret, getAppleConfig, revokeAppleToken } from './apple'
import { resetMail, sendMail, verificationMail } from './email'
import { parseList, type Env } from './env'
import { displayNameOf } from './names'

export const AUTH_BASE_PATH = '/api/auth'

const str = (v: unknown) => (typeof v === 'string' && v.trim() ? v.trim() : undefined)

/** Never log tokens; rewrite Better Auth's verify link so it always lands on our page. */
function verificationLink(url: string, baseURL: string): string {
  const u = new URL(url)
  const cb = u.searchParams.get('callbackURL')
  if (!cb || cb === '/') u.searchParams.set('callbackURL', `${baseURL}/verified`)
  return u.toString()
}

/**
 * Build the auth instance for one request. Bindings only exist per request on
 * Workers, so this is called from the fetch handler (and is cheap).
 */
export async function createAuth(env: Env) {
  const baseURL = env.BETTER_AUTH_URL.replace(/\/$/, '')
  const apple = getAppleConfig(env)
  const appleSecret = apple ? await getAppleClientSecret(apple) : undefined
  const googleOn = Boolean(env.GOOGLE_CLIENT_ID && env.GOOGLE_CLIENT_SECRET)
  const cookieDomain = env.COOKIE_DOMAIN?.trim()

  const auth = betterAuth({
    appName: 'BeezyWorks Accounts',
    baseURL,
    basePath: AUTH_BASE_PATH,
    secret: env.BETTER_AUTH_SECRET,
    // D1 is supported natively: pass the binding directly.
    database: env.DB,
    trustedOrigins: [
      ...parseList(env.TRUSTED_ORIGINS),
      ...(apple ? ['https://appleid.apple.com'] : []), // Apple posts the callback (form_post)
    ],
    plugins: [expo(), bearer(), oneTimeToken({ expiresIn: 3 })],

    emailAndPassword: {
      enabled: true,
      requireEmailVerification: true,
      minPasswordLength: 8,
      sendResetPassword: async ({ user, token }) => {
        // Always send people to the worker-hosted page, whatever redirectTo the app passed.
        const link = `${baseURL}/reset-password?token=${encodeURIComponent(token)}`
        await sendMail(env, resetMail(user.email, str(user.name), link))
      },
    },
    emailVerification: {
      sendOnSignUp: true,
      sendVerificationEmail: async ({ user, url }) => {
        await sendMail(env, verificationMail(user.email, str(user.name), verificationLink(url, baseURL)))
      },
    },

    socialProviders: {
      ...(googleOn
        ? {
            google: {
              clientId: env.GOOGLE_CLIENT_ID!,
              clientSecret: env.GOOGLE_CLIENT_SECRET!,
              mapProfileToUser: (p: { given_name?: string; family_name?: string }) => ({
                firstName: str(p.given_name),
                lastName: str(p.family_name),
              }),
            },
          }
        : {}),
      ...(apple
        ? {
            apple: {
              clientId: apple.clientId,
              clientSecret: appleSecret!,
              // Native expo-apple-authentication tokens carry the bundle id as `aud`.
              audience: apple.audiences,
              // Apple sends the name only on first consent (form_post `user` / native `idToken.user`).
              getUserInfo: async (token: {
                idToken?: string
                user?: { name?: { firstName?: string; lastName?: string } }
              }) => {
                if (!token.idToken) return null
                const profile = decodeJwt(token.idToken) as Record<string, any>
                const firstName = str(token.user?.name?.firstName)
                const lastName = str(token.user?.name?.lastName)
                const name = `${firstName ?? ''} ${lastName ?? ''}`.trim() || str(profile.name) || ''
                return {
                  user: {
                    name,
                    email: profile.email as string,
                    emailVerified: profile.email_verified === true || profile.email_verified === 'true',
                    firstName,
                    lastName,
                  },
                  data: { ...profile, name },
                } as any
              },
            },
          }
        : {}),
    },

    account: {
      accountLinking: { enabled: true, trustedProviders: ['google', 'apple'] },
    },

    user: {
      additionalFields: {
        firstName: { type: 'string', required: false, input: true },
        lastName: { type: 'string', required: false, input: true },
        displayName: { type: 'string', required: false, input: true },
      },
      deleteUser: {
        enabled: true,
        // The FK cascade should already do this; delete explicitly in case D1 does not enforce it.
        afterDelete: async (user) => {
          await deleteUserData(env, user.id)
        },
        beforeDelete: async (user) => {
          if (!apple) return
          try {
            const rows = await env.DB.prepare(
              'SELECT accessToken, refreshToken FROM account WHERE userId = ? AND providerId = ?',
            )
              .bind(user.id, 'apple')
              .all<{ accessToken: string | null; refreshToken: string | null }>()
            for (const row of rows.results) {
              if (row.refreshToken) await revokeAppleToken(apple, row.refreshToken, 'refresh_token')
              else if (row.accessToken) await revokeAppleToken(apple, row.accessToken, 'access_token')
            }
          } catch (e) {
            console.error('[apple] revoke lookup failed', e instanceof Error ? e.message : e)
          }
        },
      },
    },

    databaseHooks: {
      user: {
        create: {
          before: async (user) => {
            const name = displayNameOf(user) || user.name
            return { data: { ...user, name: name || user.email.split('@')[0] } }
          },
        },
        update: {
          before: async (data, ctx) => {
            const touched = ['firstName', 'lastName', 'displayName'].some((k) => k in data)
            if (!touched) return
            const existing = (ctx?.context?.session?.user ?? {}) as Record<string, any>
            const merged = { ...existing, ...data }
            const name = displayNameOf(merged)
            return { data: name ? { ...data, name } : data }
          },
        },
      },
    },

    rateLimit: { enabled: true, storage: 'database' },

    advanced: {
      ...(cookieDomain ? { crossSubDomainCookies: { enabled: true, domain: cookieDomain } } : {}),
      // Cloudflare's client IP header, used for rate limiting.
      ipAddress: { ipAddressHeaders: ['cf-connecting-ip'] },
    },
  })
  return auth
}
