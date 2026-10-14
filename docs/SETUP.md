# BeezyWorksAccounts setup guide

A click-through checklist for standing up the shared auth service
(Better Auth on a Cloudflare Worker + D1) at `https://auth.baderech.app`,
base path `/api/auth`, used by Mishna, the siddur app and Mikros Baderech.

Portals get renamed often. Where a label below is marked **(unverified)** I
could not confirm it against current docs; trust what you see on screen.

## 1. Overview and order of operations

Do the steps in this order, because later steps need values from earlier ones:

1. **Cloudflare** - create D1, generate `BETTER_AUTH_SECRET`, deploy the Worker on `auth.baderech.app` (Apple's domain check and Google's redirect need the live URL).
2. **Resend** - verify `baderech.app` for sending, get `RESEND_API_KEY`.
3. **Google** - one Web OAuth client (browser redirect only) -> `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET`.
4. **Apple** - App IDs, Services ID, key, email-relay registration.
5. Put all secrets with `wrangler secret put`, set vars in `wrangler.jsonc`, redeploy.

### Values you will collect

| Value | Kind | Where it comes from | Where it goes |
|---|---|---|---|
| D1 database id | config | `wrangler d1 create` output | `wrangler.jsonc` -> `d1_databases[].database_id` |
| `BETTER_AUTH_URL` = `https://auth.baderech.app` | var | fixed | `wrangler.jsonc` `vars` |
| `EMAIL_FROM` = `Baderech <noreply@baderech.app>` | var | fixed | `wrangler.jsonc` `vars` |
| `COOKIE_DOMAIN` = `baderech.app` | var | fixed | `wrangler.jsonc` `vars` |
| `TRUSTED_ORIGINS` e.g. `mishna://,https://mishna.baderech.app` | var | each app's URL scheme + web origin | `wrangler.jsonc` `vars` |
| `APPLE_SERVICES_ID` e.g. `app.baderech.auth` | var | Apple Identifiers -> Services ID | `wrangler.jsonc` `vars` |
| `APPLE_APP_BUNDLE_IDS` (comma-separated) | var | each app's iOS bundle ID | `wrangler.jsonc` `vars` |
| `BETTER_AUTH_SECRET` | secret | `openssl rand -base64 32` | `wrangler secret put` |
| `RESEND_API_KEY` | secret | Resend -> API Keys | `wrangler secret put` |
| `GOOGLE_CLIENT_ID` | secret | Google Auth Platform -> Clients | `wrangler secret put` |
| `GOOGLE_CLIENT_SECRET` | secret | Google Auth Platform -> Clients (shown once) | `wrangler secret put` |
| `APPLE_TEAM_ID` | secret | Apple Developer -> Membership details | `wrangler secret put` |
| `APPLE_KEY_ID` | secret | Apple Keys page | `wrangler secret put` |
| `APPLE_PRIVATE_KEY` | secret | contents of the downloaded `.p8` (once only) | `wrangler secret put` |

The Worker builds Apple's client-secret JWT itself from `APPLE_TEAM_ID`,
`APPLE_KEY_ID`, `APPLE_PRIVATE_KEY` and `APPLE_SERVICES_ID`, so there is no
6-month manual secret rotation (Apple caps client-secret JWTs at ~6 months).

## 2. Cloudflare

Prereqs: `pnpm install` in the repo, `pnpm exec wrangler login`.

1. Create the database:
   ```
   pnpm exec wrangler d1 create beezyworks-accounts
   ```
   Copy the printed `database_id` into `wrangler.jsonc`:
   ```jsonc
   "d1_databases": [
     { "binding": "DB", "database_name": "beezyworks-accounts", "database_id": "<paste-id>", "migrations_dir": "migrations" }
   ]
   ```
   (Binding name/dir must match what the repo's code expects; check the existing file.)
2. Apply migrations to the remote database:
   ```
   pnpm exec wrangler d1 migrations apply beezyworks-accounts --remote
   ```
3. Generate the auth secret and store it:
   ```
   openssl rand -base64 32
   pnpm exec wrangler secret put BETTER_AUTH_SECRET     # paste the output
   ```
   Keep a copy in your password manager. Changing it later invalidates sessions.
4. Set the non-secret vars in `wrangler.jsonc` under `"vars"`: `BETTER_AUTH_URL`, `EMAIL_FROM`, `APPLE_SERVICES_ID`, `APPLE_APP_BUNDLE_IDS`, `TRUSTED_ORIGINS`, `COOKIE_DOMAIN` (values in the table above).
5. Set the other secrets as you collect them in sections 3-5 (each prompts for the value):
   ```
   pnpm exec wrangler secret put RESEND_API_KEY
   pnpm exec wrangler secret put GOOGLE_CLIENT_ID
   pnpm exec wrangler secret put GOOGLE_CLIENT_SECRET
   pnpm exec wrangler secret put APPLE_TEAM_ID
   pnpm exec wrangler secret put APPLE_KEY_ID
   pnpm exec wrangler secret put APPLE_PRIVATE_KEY
   ```
   Secrets can be set before the first deploy only if the Worker already exists; otherwise deploy once first (step 7), then set them and deploy again.
6. Custom domain: add to `wrangler.jsonc`
   ```jsonc
   "routes": [{ "pattern": "auth.baderech.app", "custom_domain": true }]
   ```
   Because `baderech.app` is already a zone in your Cloudflare account, deploy creates the DNS record and certificate automatically. (Or dashboard: Workers & Pages -> the Worker -> Settings -> Domains & Routes -> Add -> Custom domain.) The hostname must not already have a conflicting CNAME.
7. Deploy:
   ```
   pnpm exec wrangler deploy
   ```
8. Check: `curl https://auth.baderech.app/health` should return a 200 OK (the repo's health route). Then confirm `https://auth.baderech.app/api/auth/ok` responds (Better Auth's built-in check).

## 3. Resend (outgoing email)

Free-tier limits (checked against Resend docs): **100 emails/day, 3,000/month**, 3 verified domains, 10 requests/second per team. Sent and received mail both count; each To/CC/BCC recipient counts separately. Enough for early verification/reset mail; upgrade if you grow.

1. Sign up at resend.com (use a shared owner mailbox, not a personal one).
2. Dashboard -> **Domains** -> **Add Domain**. Enter `baderech.app` (Resend recommends a dedicated subdomain like `updates.baderech.app` for reputation isolation; the root works too and matches `noreply@baderech.app`. If you use a subdomain, change `EMAIL_FROM` to match). Pick the region nearest your users. Leave the Return-Path subdomain at the default `send`.
3. Add the DNS records. Easiest: choose Resend's **Cloudflare sign-in / auto-configure** option (uses Domain Connect; records are added for you and verified within minutes). Otherwise copy each record from the domain's **Records** tab into Cloudflare DNS exactly. Any CNAME must be **DNS only** (grey cloud), not proxied.
4. What the records are, in plain words:
   - **SPF** - a DNS list of servers allowed to send mail for a domain. Receivers check the sending server against it.
   - **DKIM** - a cryptographic signature added to every message; the public key sits in DNS so receivers can prove the mail really came from you and wasn't altered.
   - **DMARC** - tells receivers what to do when SPF/DKIM fail (nothing, quarantine, reject) and where to send reports. Without all three, Gmail/Outlook/Apple will spam-folder or reject your mail.
5. Existing Email Routing records are not a clash: Resend puts its SPF (TXT) and MX records on the **`send.`** subdomain (the Return-Path), and the DKIM key at `resend._domainkey`. Your root MX/SPF for inbound Email Routing stay untouched. Do not merge or edit the root SPF record for Resend.
6. Click **Verify DNS Records**. Usually minutes; can take up to 72 hours. If stuck, use **Restart verification**; check propagation at dns.email.
7. After verification add a DMARC TXT record at `_dmarc.baderech.app`, starting soft: `v=DMARC1; p=none; rua=mailto:<your address>`. Tighten to `quarantine` later. (If DMARC already exists for the Email Routing setup, edit instead of adding a second one - only one is allowed.)
8. Dashboard -> **API Keys** -> **Create API Key**: name `beezyworks-accounts`, permission **Sending access**, domain restricted to `baderech.app`. The key is shown once. `pnpm exec wrangler secret put RESEND_API_KEY`.
9. Send a test sign-up and check the mail lands in inbox (not spam).

## 4. Google (browser redirect flow only)

Only one **Web application** client is needed. No iOS/Android clients, no SHA-1s, because the apps use the browser flow.

1. https://console.cloud.google.com -> create a project (e.g. `BeezyWorks Accounts`) under the owner Google account.
2. Open **Google Auth Platform** (search for it; older name: APIs & Services -> OAuth consent screen). Click **Get started** if prompted.
3. **Branding**: app name (the name users see, e.g. "Baderech"), user support email, app logo (optional, see note below), **application home page**, **privacy policy link**, terms (optional), **Authorized domains**: add `baderech.app`, and developer contact email.
4. **Audience**: choose **External**. Then click **Publish app** to move from *Testing* to *In production*. While in Testing only listed test users can sign in and tokens expire after 7 days, so you must publish.
5. Verification expectations: `openid`, `email` and `profile` are the basic non-sensitive scopes, which do **not** need Google's sensitive-scope security review. However, Google may require **brand verification** before showing your app name/logo (and may flag an unverified-app screen) - especially if you upload a logo or the home page/privacy policy domains aren't verified. Practical approach: verify `baderech.app` ownership in Google Search Console with the same account, keep the home page and privacy policy on `baderech.app`, and if the console shows "Verification required", submit it (usually days). *Unverified:* I could not find a Google page that states this exact rule; behaviour reported by developers is that a logo can trigger brand verification even with only basic scopes.
6. **Data Access** -> **Add or remove scopes**: select `.../auth/userinfo.email`, `.../auth/userinfo.profile`, `openid`. Save. No other scopes.
7. **Clients** -> **Create client** -> Application type **Web application**, name `Auth Worker`.
   - Authorized JavaScript origins: `https://auth.baderech.app`
   - Authorized redirect URIs: `https://auth.baderech.app/api/auth/callback/google` (confirmed against Better Auth docs; path follows the auth base path)
8. Copy the **Client ID** and **Client secret** (the secret is shown at creation - copy it now; you can add a new one later if lost). Then:
   ```
   pnpm exec wrangler secret put GOOGLE_CLIENT_ID
   pnpm exec wrangler secret put GOOGLE_CLIENT_SECRET
   ```
9. Note: clients unused for 6 months are auto-deleted (you get email warnings), and secrets can be rotated by adding a second one.

Adding a new app later needs **nothing** in Google: the redirect always goes through the auth Worker.

## 5. Apple

You need a paid Apple Developer Program team. Sign in at developer.apple.com -> **Certificates, Identifiers & Profiles**.

### 5a. Per app: enable the capability

1. **Identifiers** -> select the app's App ID (the bundle ID, e.g. `app.baderech.mishna`) -> enable **Sign in with Apple** -> Save.
2. Pick **one App ID as the primary** (e.g. Mishna). On each other app's App ID, open the Sign in with Apple **Edit** and choose **Enable as a primary App ID** for the primary, and **Group with an existing primary App ID** for the rest. Grouped apps share one user identity and consent, so a user signs in once across the family and gets the same Apple user id / private relay address.
3. In each Expo app's `app.json`: `"ios": { "usesAppleSignIn": true }` (the expo-apple-authentication config plugin adds the entitlement). With EAS, run a fresh build with `eas build` so the provisioning profile regenerates with the capability (EAS can sync capabilities with the App ID).
4. Add each bundle ID to `APPLE_APP_BUNDLE_IDS` (comma-separated). Native sign-in tokens have the bundle ID as their audience, so the Worker needs every one.

### 5b. Services ID (web / Android redirect flow)

1. **Identifiers** -> **+** -> **Services IDs** -> Continue. Description "Baderech Accounts", identifier e.g. `app.baderech.auth` (must differ from every App ID). Register.
2. Open it, tick **Sign in with Apple**, click **Configure**.
3. **Primary App ID**: the one from 5a.
4. **Domains and Subdomains**: `auth.baderech.app`.
5. **Return URLs**: `https://auth.baderech.app/api/auth/callback/apple` (confirmed in Better Auth's Apple docs). HTTPS only, no localhost.
6. Next -> Done -> Continue -> Save.
7. Domain verification: older Apple flow asked you to download `apple-developer-domain-association.txt` and host it at `https://auth.baderech.app/.well-known/apple-developer-domain-association.txt` before clicking **Verify**. *Unverified whether Apple still requires this for new Services IDs* (I could not load Apple's current page). If the portal shows a Download button, the Worker must serve that file at that path (ask the code agent to add a route/static asset) and then you click Verify.
8. Set `APPLE_SERVICES_ID` (var) to this identifier.

The Better Auth Apple provider also needs `https://appleid.apple.com` in trusted origins; the code handles that, not you. Apple posts the callback as `form_post` cross-site, so the Worker's cookie/CSRF handling must allow it (code side). Apple sends the user's name and email **only on first authorization**, so if a test sign-in gets lost, revoke the app under appleid.apple.com -> Sign-In and Security -> Sign in with Apple to retest.

### 5c. Sign in with Apple key

1. **Keys** -> **+** -> name `Baderech Accounts`, tick **Sign in with Apple** -> **Configure** -> choose the primary App ID -> Save -> Continue -> Register.
2. **Download** the `.p8` - **one time only**. Store it in your password manager. Note the **Key ID** (10 chars, shown on the page and in the filename).
3. **Team ID**: top-right of the developer site or Membership details (10 chars).
4. Store:
   ```
   pnpm exec wrangler secret put APPLE_TEAM_ID
   pnpm exec wrangler secret put APPLE_KEY_ID
   pnpm exec wrangler secret put APPLE_PRIVATE_KEY < AuthKey_XXXXXXXXXX.p8
   ```
   Redirecting the file with `<` preserves the multi-line PEM (`-----BEGIN PRIVATE KEY-----` ... `-----END PRIVATE KEY-----`). Alternatively paste the whole thing at the prompt. Avoid pasting with escaped `\n` unless the code expects it. Then delete any loose copy of the `.p8`.

### 5d. Sign in with Apple for Email Communication (private relay)

Users who choose "Hide My Email" get an `@privaterelay.appleid.com` address. Apple only forwards mail from **registered senders** that pass authentication; otherwise verification/reset emails to those users are silently dropped.

1. Developer account -> **Certificates, Identifiers & Profiles** -> **Services** (sidebar) -> **Sign in with Apple for Email Communication** -> **Configure**.
2. **+** next to **Email Sources**. Under **Domains and Subdomains** enter `baderech.app` (add `send.baderech.app` too, since the SMTP envelope/Return-Path domain is `send.`). Under **Individual Email Addresses** you can add `noreply@baderech.app`.
3. Next -> Register. The table shows whether each source passed the **SPF** check. Apple requires SPF and/or DKIM to authenticate (it recommends both); with Resend verified in section 3 this should pass. If it shows failed, re-check the `send.` SPF record and re-run the check after DNS propagates.
4. Do this after Resend is verified, otherwise the SPF check will fail.

### 5e. Server-to-server notifications (optional, future)

Apple can POST events (email-disabled, consent-revoked, account-delete) to an endpoint you register in the Services ID/App ID Sign in with Apple configuration. Not required now; later add a Worker route to handle them (delete or flag the user on `account-delete`/`consent-revoked`) and register the URL. Not covered in the Worker today.

## 6. Adding a new app later

1. Append the app's URL scheme and web origin to `TRUSTED_ORIGINS` (e.g. `mishna://,https://mishna.baderech.app,siddur://,https://siddur.baderech.app`).
2. Append its iOS bundle ID to `APPLE_APP_BUNDLE_IDS`.
3. Apple: enable Sign in with Apple on the new App ID and **group it with the primary App ID** (5a). Set `ios.usesAppleSignIn: true` in the app and rebuild.
4. Edit `wrangler.jsonc` vars and `pnpm exec wrangler deploy`.
5. Nothing to do in Google or Resend (and Apple Services ID/key stay as is).

## 7. App Store / Play notes

- **Apple guideline 4.8 (Login Services):** if you offer Google (a third-party login), you must also offer an equivalent privacy-preserving option; Sign in with Apple satisfies this. Keep the Apple button at least as prominent as Google.
- **Guideline 5.1.1(v):** apps that let users create an account must let them **delete the account inside the app** (not just deactivate). Ensure each app calls the auth service's delete-user endpoint and, for Apple users, ideally revokes the Apple token (Better Auth / the Worker should handle it - check). Also needed on the web build.
- **Privacy policy:** update every app's policy (and the in-app legal copy, e.g. Mishna's `settings/data/legal.ts`) to say: accounts are stored on Cloudflare (D1), sign-in via Google/Apple/email, email sent through Resend, what's collected (email, name, provider ids, sessions/IP and user agent), retention and deletion. Update App Store **App Privacy** labels (Contact Info: email/name; Identifiers: user ID) and link the policy URL.
- **Google Play Data safety form:** declare collection of email, name and user IDs for account management, data encrypted in transit, and that users can request deletion; Play also requires a **web link for account deletion** and an in-app path when accounts can be created.
- Google brand verification (section 4) and the privacy policy URL must be on `baderech.app`.

## Things I could not confirm

- Exact Google rule on when brand verification is required for basic-scope apps (no official statement found; see 4.5).
- Whether Apple still requires hosting `apple-developer-domain-association.txt` for new Services IDs (Apple's page did not load; 5b.7).
- Exact current menu labels on Apple's portal for grouping App IDs and Email Communication (taken from third-party guides and memory; Apple's docs confirm the registration requirement and SPF/DKIM authentication).
- Resend "Sending access" key wording and the existence of domain scoping in the create-key dialog (docs confirm permission + optional domain restriction exist).
- Resend's current auto-configure is described as Domain Connect "Sign in to Cloudflare"; the exact button label may vary.
- The repo's `/health` route and D1 binding names - verify against the code the other agent writes.
