/**
 * Login route: baseline 200/401 behavior + R5 auth-event auditing.
 *
 * R5 assertions: login success/failure/logout emit an audit event with the
 * source IP; the FAILURE event must NOT contain the password or bcrypt hash.
 *
 * Run: npx vitest run --no-file-parallelism src/app/api/auth/login/route.test.ts
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'
import { NextRequest } from 'next/server'

vi.stubEnv('AUTH_SECRET', 'c'.repeat(64))

const mockUserFindUnique = vi.fn()
vi.mock('@/lib/prisma', () => ({
  default: { user: { findUnique: (a: unknown) => mockUserFindUnique(a) } },
}))

const mockVerifyPassword = vi.fn()
vi.mock('@/lib/auth', async (orig) => {
  const actual = await orig<typeof import('@/lib/auth')>()
  return {
    ...actual,
    verifyPassword: (p: string, h: string) => mockVerifyPassword(p, h),
    createToken: async () => 'signed.jwt.token',
  }
})

const mockWriteAudit = vi.fn().mockResolvedValue(undefined)
vi.mock('@/lib/audit', () => ({
  writeAudit: (a: unknown) => mockWriteAudit(a),
  writeActAsAudit: vi.fn(),
}))

import { POST } from './route'

function req(body: unknown, headers: Record<string, string> = {}): NextRequest {
  return new NextRequest('http://localhost:3000/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-forwarded-for': '203.0.113.9', ...headers },
    body: JSON.stringify(body),
  })
}

beforeEach(() => {
  vi.clearAllMocks()
})

describe('POST /api/auth/login', () => {
  test('missing fields -> 400', async () => {
    const res = await POST(req({ email: '' }))
    expect(res.status).toBe(400)
  })

  test('unknown user -> 401 and a failure audit with the attempted email + IP', async () => {
    mockUserFindUnique.mockResolvedValue(null)
    const res = await POST(req({ email: 'nobody@example.com', password: 'guess' }))
    expect(res.status).toBe(401)
    const call = mockWriteAudit.mock.calls.find(c => c[0].action === 'auth.login.failure')
    expect(call).toBeDefined()
    expect(call[0].after.email).toBe('nobody@example.com')
    expect(call[0].after.ip).toBe('203.0.113.9')
  })

  test('failure audit NEVER contains the password or hash', async () => {
    mockUserFindUnique.mockResolvedValue({ id: 'u1', password: '$2b$10$HASHHASHHASH', role: 'user' })
    mockVerifyPassword.mockResolvedValue(false)
    await POST(req({ email: 'u@example.com', password: 'sup3rsecret' }))
    const call = mockWriteAudit.mock.calls.find(c => c[0].action === 'auth.login.failure')
    const serialized = JSON.stringify(call[0])
    expect(serialized).not.toContain('sup3rsecret')
    expect(serialized).not.toContain('$2b$10$HASHHASHHASH')
  })

  test('valid login -> 200 and a success audit', async () => {
    mockUserFindUnique.mockResolvedValue({
      id: 'u1', name: 'U', email: 'u@example.com', password: '$2b$10$x', role: 'user',
    })
    mockVerifyPassword.mockResolvedValue(true)
    const res = await POST(req({ email: 'u@example.com', password: 'right' }))
    expect(res.status).toBe(200)
    const call = mockWriteAudit.mock.calls.find(c => c[0].action === 'auth.login.success')
    expect(call).toBeDefined()
    expect(call[0].actorId).toBe('u1')
  })
})
