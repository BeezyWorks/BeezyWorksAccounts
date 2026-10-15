# BeezyWorks Accounts

Shared account/auth service for the Baderech family of Expo apps (Mishna, the
siddur, Mikros Baderech). A Cloudflare Worker running [Better Auth](https://better-auth.com)
on D1, served at `https://auth.baderech.app`.

Features: email + password (verification required, password reset), Google and
Apple sign-in (each enabled only when configured), account linking, account
deletion (revokes Apple tokens first), bearer tokens for native apps and other
domains, cross-subdomain cookies for `*.baderech.app`, database-backed rate limiting.

Provider console setup (Google, Apple, Resend, DNS) is in [`docs/SETUP.md`](docs/SETUP.md).

## Endpoints

| Path | Purpose |
| --- | --- |
| `/api/auth/*` | Better Auth (sign-up, sign-in, sign-out, session, update-user, link/unlink social, delete-user, password reset, social callbacks, ...). Use the `@better-auth/expo` client. |
| `GET /reset-password?token=...` | Self-contained password-reset form; POSTs to `/api/auth/reset-password`. Reset emails link here. |
| `GET /verified` | Landing page after email verification (default `callbackURL`). |
| `GET /api/data/:namespace` | Auth required (bearer token or cookie). `200 { namespace, revision, updatedAt, data }`; nothing stored yet gives `{ namespace, revision: 0, updatedAt: null, data: null }`. |
| `PUT /api/data/:namespace` | Auth required. Body `{ data, baseRevision? }` (`data` is any JSON value, `null` included; max 256 KB, else 413). If `baseRevision` is given and differs from the current revision (0 when nothing is stored) the response is `409` with the current record (same shape as GET); otherwise the value is stored with `revision = current + 1`, `updatedAt = Date.now()` (ms) and the new record is returned. Omit `baseRevision` to overwrite. The check and write are one SQL statement. |
| `GET /handoff?return=<url>` | Web social sign-in handoff. `return` must be an http(s) URL whose origin is in `TRUSTED_ORIGINS`, or a custom-scheme app URL whose `scheme://` is listed there (see Native apps); else 400 plain text. With a cookie session, 302 to `<return>#ott=<one-time token>` (valid 3 minutes); with none, 302 to `<return>#error=no_session`. `no-store`, `no-referrer`. |
| `GET /health` | `{ "ok": true }` |

Notes for clients:

- Web social sign-in from another site (e.g. https://siddur.one, where cookies on the auth
  origin are third-party): `POST /api/auth/sign-in/social { provider, callbackURL:
  "https://auth.baderech.app/handoff?return=https://siddur.one/account/callback",
  disableRedirect: true }`, navigate to the returned `url`; after sign-in the browser lands on
  `/handoff`, then on `return#ott=...`. The page reads the fragment and calls
  `POST /api/auth/one-time-token/verify { token }` (CORS applies). The token is single use and
  the response carries the bearer token in the `set-auth-token` header (body is `{ session, user }`);
  send it as `Authorization: Bearer <token>` to `/api/auth/*` and `/api/data/*`. Failures come back
  as `return#error=no_session`.
- Native apps (iOS/Android, custom URL scheme such as `siddurone://`, which must be listed in
  `TRUSTED_ORIGINS` as `siddurone://`). `return` on `/start/:provider` and `/handoff` may be
  `siddurone://account/callback` (any path; no credentials; the scheme must be listed in the form
  `scheme://`; `javascript:`, `data:`, `file:` and friends are always refused). Results go in the
  **query**, not the fragment, because fragments are unreliable through deep links and expo-router:
  - Google/Apple via the browser: open
    `https://auth.baderech.app/start/google?return=siddurone%3A%2F%2Faccount%2Fcallback` (or `/start/apple`)
    with `WebBrowser.openAuthSessionAsync(url, 'siddurone://account/callback')`. It ends at
    `siddurone://account/callback?ott=<one-time token>` (single use, valid 3 minutes), or
    `siddurone://account/callback?error=<code>` with `no_session`, `handoff_failed`, `start_failed`,
    or a Better Auth provider code (e.g. `access_denied`, `state_not_found`), which Better Auth
    appends to the `errorCallbackURL` that `/start` sets to the return URL.
  - Then `POST https://auth.baderech.app/api/auth/one-time-token/verify` with JSON `{ "token": ott }`
    (no Origin or cookies needed). The bearer is the `set-auth-token` response header; use it as
    `Authorization: Bearer <token>`. Single use: a second verify is 400.
  - Email verification: `POST /api/auth/sign-up/email` with `callbackURL:
    "https://auth.baderech.app/handoff?return=siddurone%3A%2F%2Faccount%2Fcallback"`. No Origin
    header is needed (the handoff URL is on the auth origin). The mail's link signs the user in and
    redirects through `/handoff` to `siddurone://account/callback?ott=...`; if the link is opened
    where there is no session cookie (e.g. the in-app browser's jar differs from the mail app's)
    the result is `?error=no_session`.
  - Native Apple sign-in (`expo-apple-authentication`), no browser: `POST /api/auth/sign-in/social`
    with no Origin and no cookies, body
    `{ "provider": "apple", "idToken": { "token": <identityToken>, "nonce": <raw nonce, optional>,
    "user": { "name": { "firstName", "lastName" } } } }`. `user` comes from the credential's
    `fullName` and is only available on the very first authorization; pass it then or the name is
    lost. The token's `aud` must be in `APPLE_APP_BUNDLE_IDS` (or the services id), issuer
    `https://appleid.apple.com`, age under 1 hour. Nonce: if `idToken.nonce` is sent it must equal
    the token's `nonce` claim exactly, or the claim must equal the lowercase **hex** SHA-256 of it.
    So the usual pattern works: send `sha256hex(raw)` as `nonce` to `AppleAuthentication.signInAsync`
    and `raw` to the server (base64 digests do not match). If omitted, no nonce check happens
    (replay protection is then only the 1 hour age limit), so always send it. 200 response:
    `{ redirect: false, token, user }` with the bearer in the `set-auth-token` header; 401 for a bad
    token/audience/nonce.
- Account deletion (`POST /api/auth/delete-user`): a bearer or cookie session is enough when
  the session is fresh (created within the last 24 h, Better Auth's default `freshAge`) and the body
  is `{}`. Otherwise it fails with 400 `SESSION_EXPIRED`; credential users can instead send
  `{ password }` at any session age. No email confirmation is configured.

- App data (`/api/data/:namespace`): a per-user, per-namespace JSON store the server treats as
  opaque, so apps (`siddur`, `mishna`, shared ones like `shared.events`) can sync through the
  account. `namespace` must match `^[a-z][a-z0-9._-]{0,63}$` (else 400). Errors are
  `{ "error": "..." }`: 401 no session, 400 bad namespace / invalid JSON / missing `data` /
  bad `baseRevision`, 405 any method but GET/PUT, 413 body over 256 KB. Rows are deleted with
  the account. Table: `app_data` (`migrations/0002_app_data.sql`).
- CORS (`/api/auth/*` and `/api/data/*`): origins listed in `TRUSTED_ORIGINS` that are http(s)
  (e.g. `https://siddur.one`) get `Access-Control-Allow-Origin` (echoed), `Allow-Credentials: true`,
  `Expose-Headers: set-auth-token` and `Vary: Origin`; OPTIONS preflights return 204 with methods
  `GET, POST, PUT, DELETE, OPTIONS` and headers `content-type, authorization`. Other origins get none.
  Better Auth itself only emits `Expose-Headers` (bearer plugin), so the Worker adds the rest.

- Display name: `displayName ?? \`${firstName} ${lastName}\``, falling back to `name`.
  Better Auth's `name` is kept in sync server-side (displayName, else "first last",
  else the existing name) whenever `firstName`/`lastName`/`displayName` change.
- `firstName`, `lastName`, `displayName` are nullable and settable with `updateUser`.
- Apple's name is only sent on first sign-in; Google's `given_name`/`family_name` are mapped.
- Native apps can sign in with `signIn.social({ provider: "apple", idToken: { token, user } })`
  (pass `user` from `expo-apple-authentication` so the name is stored).
- Sign-up/verification callbacks may pass their own `callbackURL` (an app deep link,
  which must be in `TRUSTED_ORIGINS`); the default is `/verified`.

## Environment

Defaults for vars live in `wrangler.jsonc`; secrets are set with `wrangler secret put`
(locally: `.dev.vars`, see `.dev.vars.example`). Never commit secrets.

| Name | Kind | Purpose |
| --- | --- | --- |
| `BETTER_AUTH_SECRET` | secret | Signing/encryption secret (`openssl rand -base64 32`). |
| `BETTER_AUTH_URL` | var | Public base URL, `https://auth.baderech.app`. |
| `RESEND_API_KEY` | secret | Resend API key. If unset, emails are logged (to, subject, link) instead of sent. |
| `EMAIL_FROM` | var | From address, default `Baderech <noreply@baderech.app>`. |
| `TRUSTED_ORIGINS` | var | Comma-separated origins/schemes, e.g. `mishnaapp://,https://mishna.baderech.app`. |
| `COOKIE_DOMAIN` | var | Parent domain for cross-subdomain cookies, e.g. `baderech.app`. Empty = off. |
| `GOOGLE_CLIENT_ID` | secret | Google OAuth client id (Google enabled only with both). |
| `GOOGLE_CLIENT_SECRET` | secret | Google OAuth client secret. |
| `APPLE_SERVICES_ID` | var | Apple Services ID (web/Android `client_id`). |
| `APPLE_APP_BUNDLE_IDS` | var | Comma-separated iOS bundle IDs; native id tokens for these are accepted. |
| `APPLE_TEAM_ID` | secret | Apple developer Team ID. |
| `APPLE_KEY_ID` | secret | Key ID of the Sign in with Apple key. |
| `APPLE_PRIVATE_KEY` | secret | Contents of the `.p8` file (literal `\n` is accepted). |

Apple is enabled only when the team id, key id, private key and at least one of
services id / bundle id are set. The client-secret JWT is generated at runtime
(ES256, ~150 day lifetime, cached per isolate, regenerated 30 days before expiry), so
there is no manual rotation.

## Local development

```
pnpm install
cp .dev.vars.example .dev.vars   # fill in at least BETTER_AUTH_SECRET
pnpm db:migrate:local
pnpm dev                         # http://localhost:8787
pnpm typecheck
pnpm test
```

Without `RESEND_API_KEY` verification and reset links are printed to the console.

## Migrations

`migrations/` holds D1 SQL (`wrangler d1 migrations`). `0001_better_auth.sql` was
generated with Better Auth's `getMigrations()` for the config in `src/auth.ts`. If
you change plugins or fields, generate the new SQL and add a new numbered migration.

## Deploy

```
wrangler d1 create beezyworks-accounts      # put the printed database_id in wrangler.jsonc
pnpm db:migrate:remote                      # wrangler d1 migrations apply beezyworks-accounts --remote
wrangler secret put BETTER_AUTH_SECRET
wrangler secret put RESEND_API_KEY
wrangler secret put GOOGLE_CLIENT_ID
wrangler secret put GOOGLE_CLIENT_SECRET
wrangler secret put APPLE_TEAM_ID
wrangler secret put APPLE_KEY_ID
wrangler secret put APPLE_PRIVATE_KEY < AuthKey_XXXXXXXXXX.p8
pnpm deploy                                 # wrangler deploy
```

`wrangler.jsonc` routes `auth.baderech.app` as a Workers custom domain (the
`baderech.app` zone must be on Cloudflare).

## Adding an app

1. Add its scheme/origin to `TRUSTED_ORIGINS` (e.g. `siddur://`, `https://siddur.baderech.app`).
2. Add its iOS bundle ID to `APPLE_APP_BUNDLE_IDS`.
3. Use the `@better-auth/expo` client with `baseURL: "https://auth.baderech.app"` and
   its `scheme`; store the session in `expo-secure-store`.
4. Redeploy (`pnpm deploy`).
