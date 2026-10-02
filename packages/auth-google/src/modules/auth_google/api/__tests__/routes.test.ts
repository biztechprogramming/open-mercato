const mockAuthService = {
  findUserByEmailAndTenant: jest.fn(),
  findUsersByEmail: jest.fn(),
  getUserRoles: jest.fn(async () => ['admin']),
  updateLastLoginAt: jest.fn(async () => undefined),
  createSession: jest.fn(async () => ({ session: { id: 'session-1' }, token: 'refresh-token-1' })),
}

jest.mock('@open-mercato/shared/lib/di/container', () => ({
  createRequestContainer: jest.fn(async () => ({ resolve: () => mockAuthService })),
}))

jest.mock('@open-mercato/core/modules/auth/events', () => ({
  emitAuthEvent: jest.fn(async () => undefined),
}))

import { GET as startGET } from '../get/start/route'
import { GET as callbackGET } from '../get/callback/route'
import { GOOGLE_AUTH_STATE_COOKIE } from '../../lib/state'

const clientId = 'client-123.apps.googleusercontent.com'
const tenantId = '7d3f1b2e-4a5c-4d6e-8f90-123456789abc'
const savedEnv = { ...process.env }

function makeIdToken(claims: Record<string, unknown>): string {
  const encode = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url')
  return `${encode({ alg: 'RS256' })}.${encode(claims)}.signature`
}

function readSetCookie(res: Response, name: string): string | null {
  const header = res.headers.getSetCookie().find((value) => value.startsWith(`${name}=`))
  return header ? decodeURIComponent(header.split(';')[0].slice(name.length + 1)) : null
}

async function startFlow(query: string = `tenant=${tenantId}&redirect=/backend/customers`) {
  const res = await startGET(new Request(`http://localhost:3000/api/auth_google/start?${query}`))
  const location = new URL(res.headers.get('location') ?? '')
  return {
    res,
    state: location.searchParams.get('state') ?? '',
    nonce: location.searchParams.get('nonce') ?? '',
    cookie: readSetCookie(res, GOOGLE_AUTH_STATE_COOKIE) ?? '',
    location,
  }
}

function callbackRequest(query: string, cookie: string | null) {
  return new Request(`http://localhost:3000/api/auth_google/callback?${query}`, {
    headers: cookie ? { cookie: `${GOOGLE_AUTH_STATE_COOKIE}=${encodeURIComponent(cookie)}` } : {},
  })
}

function mockGoogleTokenEndpoint(claims: Record<string, unknown>) {
  global.fetch = jest.fn(async () => new Response(JSON.stringify({ id_token: makeIdToken(claims) }), { status: 200 })) as typeof fetch
}

beforeEach(() => {
  process.env = {
    ...savedEnv,
    NODE_ENV: 'test',
    APP_URL: 'http://localhost:3000',
    JWT_SECRET: 'test-secret-for-auth-google-routes-0123456789abcdef',
    GOOGLE_AUTH_CLIENT_ID: clientId,
    GOOGLE_AUTH_CLIENT_SECRET: 'client-secret',
    GOOGLE_AUTH_ALLOWED_DOMAINS: 'ecoinspector.com',
  }
  jest.clearAllMocks()
})

afterAll(() => {
  process.env = savedEnv
})

describe('GET /api/auth_google/start', () => {
  it('redirects to Google with PKCE and sets the state cookie', async () => {
    const { res, location, cookie, state } = await startFlow()
    expect(res.status).toBe(307)
    expect(location.origin).toBe('https://accounts.google.com')
    expect(location.searchParams.get('redirect_uri')).toBe('http://localhost:3000/api/auth_google/callback')
    expect(location.searchParams.get('code_challenge_method')).toBe('S256')
    expect(state).not.toBe('')
    expect(cookie).not.toBe('')
  })

  it('sends the user back to login when Google sign-in is not configured', async () => {
    delete process.env.GOOGLE_AUTH_CLIENT_ID
    const res = await startGET(new Request('http://localhost:3000/api/auth_google/start'))
    expect(res.headers.get('location')).toContain('/login?googleError=not_configured')
  })
})

describe('GET /api/auth_google/callback', () => {
  it('signs in the matching user and redirects to the requested page', async () => {
    const { state, nonce, cookie } = await startFlow()
    mockGoogleTokenEndpoint({
      iss: 'https://accounts.google.com',
      aud: clientId,
      sub: 'google-sub',
      exp: Math.floor(Date.now() / 1000) + 600,
      nonce,
      email: 'owner@ecoinspector.com',
      email_verified: true,
    })
    mockAuthService.findUserByEmailAndTenant.mockResolvedValue({
      id: 'user-1',
      email: 'owner@ecoinspector.com',
      tenantId,
      organizationId: 'org-1',
      isConfirmed: true,
    })

    const res = await callbackGET(callbackRequest(`code=auth-code&state=${state}`, cookie))

    expect(res.status).toBe(307)
    expect(res.headers.get('location')).toBe('http://localhost:3000/backend/customers')
    expect(mockAuthService.findUserByEmailAndTenant).toHaveBeenCalledWith('owner@ecoinspector.com', tenantId)
    expect(readSetCookie(res, 'auth_token')).toMatch(/^[\w-]+\.[\w-]+\.[\w-]+$/)
    expect(readSetCookie(res, 'session_token')).toBe('refresh-token-1')
    expect(readSetCookie(res, GOOGLE_AUTH_STATE_COOKIE)).toBe('')
  })

  it('rejects a callback without the state cookie', async () => {
    const { state } = await startFlow()
    const res = await callbackGET(callbackRequest(`code=auth-code&state=${state}`, null))
    expect(res.headers.get('location')).toContain('/login?googleError=invalid_state')
    expect(mockAuthService.createSession).not.toHaveBeenCalled()
  })

  it('rejects an email outside the allowed domains', async () => {
    const { state, nonce, cookie } = await startFlow()
    mockGoogleTokenEndpoint({
      iss: 'https://accounts.google.com',
      aud: clientId,
      sub: 'google-sub',
      exp: Math.floor(Date.now() / 1000) + 600,
      nonce,
      email: 'someone@gmail.com',
      email_verified: true,
    })
    const res = await callbackGET(callbackRequest(`code=auth-code&state=${state}`, cookie))
    expect(res.headers.get('location')).toContain('googleError=domain_not_allowed')
    expect(mockAuthService.createSession).not.toHaveBeenCalled()
  })

  it('reports a cancelled Google consent as access_denied', async () => {
    const { state, cookie } = await startFlow()
    const res = await callbackGET(callbackRequest(`error=access_denied&state=${state}`, cookie))
    expect(res.headers.get('location')).toContain('googleError=access_denied')
  })
})
