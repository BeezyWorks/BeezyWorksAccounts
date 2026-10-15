import { describe, expect, it } from 'vitest'
import worker from '../src/index'
import { baseEnv, call, ORIGIN, PASSWORD, verifiedSession } from './helpers'

const put = (ns: string, body: unknown, token: string) => call('PUT', `/api/data/${ns}`, body, { token })
const get = (ns: string, token: string) => call('GET', `/api/data/${ns}`, undefined, { token })

describe('app data', () => {
  it('requires a session', async () => {
    expect((await call('GET', '/api/data/siddur')).status).toBe(401)
    expect((await call('PUT', '/api/data/siddur', { data: 1 })).data).toEqual({ error: 'unauthorized' })
    expect((await call('GET', '/api/data/siddur', undefined, { token: 'bogus' })).status).toBe(401)
  })

  it('rejects bad namespaces and other methods', async () => {
    const { token } = await verifiedSession()
    for (const ns of ['Siddur', '1abc', '-x', 'a'.repeat(65), 'a%20b', 'a/b', '']) {
      expect((await get(ns, token)).status).toBe(400)
    }
    expect((await get('a'.repeat(64), token)).status).toBe(200)
    expect((await get('shared.events_v-2', token)).status).toBe(200)
    expect((await call('DELETE', '/api/data/siddur', undefined, { token })).status).toBe(405)
    expect((await call('POST', '/api/data/siddur', {}, { token })).status).toBe(405)
  })

  it('returns an empty record when nothing is stored', async () => {
    const { token } = await verifiedSession()
    const r = await get('siddur', token)
    expect(r.status).toBe(200)
    expect(r.data).toEqual({ namespace: 'siddur', revision: 0, updatedAt: null, data: null })
  })

  it('PUT then GET, with incrementing revisions', async () => {
    const { token } = await verifiedSession()
    const before = Date.now()
    const a = await put('siddur', { data: { a: [1, 2], b: null } }, token)
    expect(a.status).toBe(200)
    expect(a.data).toMatchObject({ namespace: 'siddur', revision: 1, data: { a: [1, 2], b: null } })
    expect(a.data.updatedAt).toBeGreaterThanOrEqual(before)

    expect((await get('siddur', token)).data).toEqual(a.data)

    const b = await put('siddur', { data: 'second' }, token)
    expect(b.data).toMatchObject({ revision: 2, data: 'second' })
    expect((await put('siddur', { data: null }, token)).data).toMatchObject({ revision: 3, data: null })
  })

  it('accepts a matching baseRevision and returns 409 with the current record for a stale one', async () => {
    const { token } = await verifiedSession()
    expect((await put('siddur', { data: 'x', baseRevision: 0 }, token)).data.revision).toBe(1)
    expect((await put('siddur', { data: 'y', baseRevision: 1 }, token)).data.revision).toBe(2)

    const stale = await put('siddur', { data: 'z', baseRevision: 1 }, token)
    expect(stale.status).toBe(409)
    expect(stale.data).toMatchObject({ namespace: 'siddur', revision: 2, data: 'y' })
    const again = await put('siddur', { data: 'z', baseRevision: 0 }, token)
    expect(again.status).toBe(409)
    expect((await get('siddur', token)).data).toMatchObject({ revision: 2, data: 'y' })

    // baseRevision on a namespace with no row only matches 0
    const fresh = await put('mishna', { data: 1, baseRevision: 3 }, token)
    expect(fresh.status).toBe(409)
    expect(fresh.data).toEqual({ namespace: 'mishna', revision: 0, updatedAt: null, data: null })
  })

  it('lets only one of two writers with the same baseRevision win', async () => {
    const { token } = await verifiedSession()
    await put('siddur', { data: 0 }, token)
    const rs = await Promise.all([1, 2, 3].map((n) => put('siddur', { data: n, baseRevision: 1 }, token)))
    expect(rs.map((r) => r.status).sort()).toEqual([200, 409, 409])
  })

  it('overwrites when baseRevision is omitted', async () => {
    const { token } = await verifiedSession()
    await put('siddur', { data: 'a' }, token)
    await put('siddur', { data: 'b' }, token)
    const r = await put('siddur', { data: 'c' }, token)
    expect(r.status).toBe(200)
    expect(r.data).toMatchObject({ revision: 3, data: 'c' })
  })

  it('validates bodies', async () => {
    const { token } = await verifiedSession()
    expect((await put('siddur', {}, token)).status).toBe(400)
    expect((await put('siddur', [1], token)).status).toBe(400)
    expect((await put('siddur', { data: 1, baseRevision: -1 }, token)).status).toBe(400)
    expect((await put('siddur', { data: 1, baseRevision: 'x' }, token)).status).toBe(400)
    expect((await put('siddur', { data: 1, baseRevision: 1.5 }, token)).status).toBe(400)
    const bad = await worker.fetch(
      new Request(`${ORIGIN}/api/data/siddur`, {
        method: 'PUT',
        headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
        body: '{nope',
      }),
      baseEnv,
    )
    expect(bad.status).toBe(400)
    expect((await get('siddur', token)).data.revision).toBe(0)
  })

  it('rejects bodies over 256 KB', async () => {
    const { token } = await verifiedSession()
    const big = await put('siddur', { data: 'x'.repeat(256 * 1024) }, token)
    expect(big.status).toBe(413)
    const ok = await put('siddur', { data: 'x'.repeat(200 * 1024) }, token)
    expect(ok.status).toBe(200)
  })

  it('isolates users and namespaces', async () => {
    const a = await verifiedSession()
    const b = await verifiedSession()
    await put('siddur', { data: 'a-siddur' }, a.token)
    await put('mishna', { data: 'a-mishna' }, a.token)
    expect((await get('siddur', a.token)).data.data).toBe('a-siddur')
    expect((await get('mishna', a.token)).data.data).toBe('a-mishna')
    expect((await get('siddur', b.token)).data).toMatchObject({ revision: 0, data: null })
    await put('siddur', { data: 'b-siddur' }, b.token)
    expect((await get('siddur', a.token)).data).toMatchObject({ revision: 1, data: 'a-siddur' })
  })

  it('removes a deleted account\'s rows', async () => {
    const a = await verifiedSession()
    const b = await verifiedSession()
    await put('siddur', { data: 1 }, a.token)
    await put('mishna', { data: 2 }, a.token)
    await put('siddur', { data: 3 }, b.token)
    const count = (id: string) =>
      baseEnv.DB.prepare('SELECT count(*) AS n FROM app_data WHERE user_id = ?').bind(id).first<{ n: number }>()
    expect((await count(a.user.id))!.n).toBe(2)

    const del = await call('POST', '/api/auth/delete-user', { password: PASSWORD }, { token: a.token })
    expect(del.status).toBe(200)
    expect((await count(a.user.id))!.n).toBe(0)
    expect((await count(b.user.id))!.n).toBe(1)
  })
})

describe('CORS', () => {
  const preflight = (origin: string, path: string) =>
    worker.fetch(
      new Request(`${ORIGIN}${path}`, {
        method: 'OPTIONS',
        headers: { origin, 'access-control-request-method': 'PUT', 'access-control-request-headers': 'authorization' },
      }),
      baseEnv,
    )

  it('answers preflights from a trusted origin', async () => {
    for (const path of ['/api/data/siddur', '/api/auth/sign-in/email']) {
      const res = await preflight('https://mishna.test', path)
      expect(res.status).toBe(204)
      expect(res.headers.get('access-control-allow-origin')).toBe('https://mishna.test')
      expect(res.headers.get('access-control-allow-methods')).toBe('GET, POST, PUT, DELETE, OPTIONS')
      expect(res.headers.get('access-control-allow-headers')).toBe('content-type, authorization')
      expect(res.headers.get('access-control-allow-credentials')).toBe('true')
      expect(res.headers.get('access-control-expose-headers')).toContain('set-auth-token')
      expect(res.headers.get('vary')).toContain('Origin')
    }
  })

  it('gives untrusted or non-http origins no CORS headers', async () => {
    for (const origin of ['https://evil.test', 'mishnaapp://']) {
      const res = await preflight(origin, '/api/data/siddur')
      expect(res.headers.get('access-control-allow-origin')).toBeNull()
      expect(res.headers.get('access-control-allow-credentials')).toBeNull()
      expect(res.headers.get('vary')).toContain('Origin')
    }
  })

  it('adds CORS headers to real responses, once', async () => {
    const { token } = await verifiedSession()
    const res = await worker.fetch(
      new Request(`${ORIGIN}/api/data/siddur`, { headers: { origin: 'https://mishna.test', authorization: `Bearer ${token}` } }),
      baseEnv,
    )
    expect(res.status).toBe(200)
    expect(res.headers.get('access-control-allow-origin')).toBe('https://mishna.test')

    const si = await worker.fetch(
      new Request(`${ORIGIN}/api/auth/get-session`, { headers: { origin: 'https://mishna.test', authorization: `Bearer ${token}` } }),
      baseEnv,
    )
    expect(si.headers.get('access-control-allow-origin')).toBe('https://mishna.test')
    expect(si.headers.get('access-control-expose-headers')).toContain('set-auth-token')
  })
})
