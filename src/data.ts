import { createAuth } from './auth'
import type { Env } from './env'

export const DATA_BASE_PATH = '/api/data'
export const MAX_BODY_BYTES = 256 * 1024
const NAMESPACE_RE = /^[a-z][a-z0-9._-]{0,63}$/

interface Row {
  data: string
  revision: number
  updated_at: number
}

const record = (namespace: string, row: Row | null) => ({
  namespace,
  revision: row?.revision ?? 0,
  updatedAt: row?.updated_at ?? null,
  data: row ? JSON.parse(row.data) : null,
})

const fail = (status: number, error: string, extra?: Record<string, unknown>) =>
  Response.json({ error, ...extra }, { status })

async function current(env: Env, userId: string, namespace: string): Promise<Row | null> {
  return env.DB.prepare('SELECT data, revision, updated_at FROM app_data WHERE user_id = ? AND namespace = ?')
    .bind(userId, namespace)
    .first<Row>()
}

/**
 * Write with the revision check done inside one SQL statement, so concurrent writers can
 * never both win. Returns the new row, or null when `baseRevision` no longer matches.
 */
async function write(
  env: Env,
  userId: string,
  namespace: string,
  json: string,
  baseRevision: number | undefined,
): Promise<Row | null> {
  const now = Date.now()
  let stmt: D1PreparedStatement
  if (baseRevision === undefined) {
    stmt = env.DB.prepare(
      `INSERT INTO app_data (user_id, namespace, data, revision, updated_at) VALUES (?1, ?2, ?3, 1, ?4)
       ON CONFLICT (user_id, namespace) DO UPDATE
         SET data = excluded.data, revision = app_data.revision + 1, updated_at = excluded.updated_at
       RETURNING data, revision, updated_at`,
    ).bind(userId, namespace, json, now)
  } else if (baseRevision === 0) {
    stmt = env.DB.prepare(
      `INSERT INTO app_data (user_id, namespace, data, revision, updated_at) VALUES (?1, ?2, ?3, 1, ?4)
       ON CONFLICT (user_id, namespace) DO NOTHING
       RETURNING data, revision, updated_at`,
    ).bind(userId, namespace, json, now)
  } else {
    stmt = env.DB.prepare(
      `UPDATE app_data SET data = ?3, revision = revision + 1, updated_at = ?4
       WHERE user_id = ?1 AND namespace = ?2 AND revision = ?5
       RETURNING data, revision, updated_at`,
    ).bind(userId, namespace, json, now, baseRevision)
  }
  return stmt.first<Row>()
}

/** Remove everything a user stored (also done by the FK cascade; D1 enforcement is not relied on). */
export async function deleteUserData(env: Env, userId: string) {
  await env.DB.prepare('DELETE FROM app_data WHERE user_id = ?').bind(userId).run()
}

export async function handleData(request: Request, env: Env): Promise<Response> {
  if (!['GET', 'PUT'].includes(request.method)) {
    return new Response(JSON.stringify({ error: 'method not allowed' }), {
      status: 405,
      headers: { 'content-type': 'application/json', allow: 'GET, PUT, OPTIONS' },
    })
  }

  const auth = await createAuth(env)
  const session = await auth.api.getSession({ headers: request.headers })
  if (!session?.user) return fail(401, 'unauthorized')
  const userId = session.user.id

  let namespace = new URL(request.url).pathname.slice(DATA_BASE_PATH.length + 1)
  try {
    namespace = decodeURIComponent(namespace)
  } catch {
    // leave undecoded; it fails the pattern below
  }
  if (!NAMESPACE_RE.test(namespace)) return fail(400, 'invalid namespace')

  const noStore = { 'cache-control': 'no-store' }

  if (request.method === 'GET') {
    return Response.json(record(namespace, await current(env, userId, namespace)), { headers: noStore })
  }

  const declared = Number(request.headers.get('content-length'))
  if (declared > MAX_BODY_BYTES) return fail(413, 'payload too large')
  const raw = new Uint8Array(await request.arrayBuffer())
  if (raw.byteLength > MAX_BODY_BYTES) return fail(413, 'payload too large')

  let body: unknown
  try {
    body = JSON.parse(new TextDecoder().decode(raw))
  } catch {
    return fail(400, 'invalid JSON')
  }
  if (!body || typeof body !== 'object' || Array.isArray(body) || !('data' in body)) {
    return fail(400, 'body must be an object with a "data" field')
  }
  const { data, baseRevision } = body as { data: unknown; baseRevision?: unknown }
  if (baseRevision !== undefined && (!Number.isInteger(baseRevision) || (baseRevision as number) < 0)) {
    return fail(400, 'baseRevision must be a non-negative integer')
  }

  const row = await write(env, userId, namespace, JSON.stringify(data), baseRevision as number | undefined)
  if (!row) {
    return Response.json(record(namespace, await current(env, userId, namespace)), { status: 409, headers: noStore })
  }
  return Response.json(record(namespace, row), { headers: noStore })
}
