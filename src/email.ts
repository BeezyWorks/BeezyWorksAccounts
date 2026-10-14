import { DEFAULT_EMAIL_FROM, type Env } from './env'

export interface Mail {
  to: string
  subject: string
  text: string
  html: string
  /** The action link, kept separately so it can be logged / captured in dev. */
  link: string
}

/**
 * Emails "sent" while RESEND_API_KEY is unset (local dev and tests). In-memory
 * only, capped, and never populated in production where the key is set.
 */
export const devOutbox: Mail[] = []

const esc = (s: string) =>
  s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')

function compose(kind: 'verify' | 'reset', to: string, name: string | undefined, link: string): Mail {
  const hello = name ? `Hello ${name},` : 'Hello,'
  const copy =
    kind === 'verify'
      ? {
          subject: 'Verify your email address',
          intro: 'Please confirm your email address to finish creating your account.',
          action: 'Verify email',
          outro: "If you didn't create an account, you can ignore this email.",
        }
      : {
          subject: 'Reset your password',
          intro: 'We received a request to reset your password.',
          action: 'Reset password',
          outro: "If you didn't ask for this, you can ignore this email; your password won't change.",
        }
  const text = `${hello}\n\n${copy.intro}\n\n${copy.action}: ${link}\n\n${copy.outro}\n`
  const html =
    `<div style="font-family:-apple-system,Segoe UI,Roboto,sans-serif;max-width:480px;margin:0 auto;padding:16px;color:#222">` +
    `<p>${esc(hello)}</p><p>${esc(copy.intro)}</p>` +
    `<p><a href="${esc(link)}" style="display:inline-block;padding:10px 18px;background:#1f4e8c;color:#fff;border-radius:6px;text-decoration:none">${esc(copy.action)}</a></p>` +
    `<p style="font-size:13px;color:#555">Or paste this link into your browser:<br>${esc(link)}</p>` +
    `<p style="font-size:13px;color:#555">${esc(copy.outro)}</p></div>`
  return { to, subject: copy.subject, text, html, link }
}

export const verificationMail = (to: string, name: string | undefined, link: string) =>
  compose('verify', to, name, link)
export const resetMail = (to: string, name: string | undefined, link: string) =>
  compose('reset', to, name, link)

/** Send via Resend, or log (and record in `devOutbox`) when no API key is configured. */
export async function sendMail(env: Env, mail: Mail): Promise<void> {
  if (!env.RESEND_API_KEY) {
    console.log(`[email:dev] to=${mail.to} subject=${JSON.stringify(mail.subject)} link=${mail.link}`)
    devOutbox.push(mail)
    if (devOutbox.length > 50) devOutbox.shift()
    return
  }
  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { authorization: `Bearer ${env.RESEND_API_KEY}`, 'content-type': 'application/json' },
    body: JSON.stringify({
      from: env.EMAIL_FROM || DEFAULT_EMAIL_FROM,
      to: [mail.to],
      subject: mail.subject,
      text: mail.text,
      html: mail.html,
    }),
  })
  if (!res.ok) {
    // Never include the link/token in logs when a real send fails.
    console.error(`[email] Resend rejected message (${res.status}): ${(await res.text()).slice(0, 300)}`)
    throw new Error('Failed to send email')
  }
}
