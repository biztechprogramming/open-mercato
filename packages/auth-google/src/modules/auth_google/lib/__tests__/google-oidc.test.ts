import { buildGoogleAuthorizeUrl, exchangeGoogleCode, GoogleAuthError, validateGoogleIdToken } from '../google-oidc'

const clientId = 'client-123.apps.googleusercontent.com'
const nowSeconds = 1_800_000_000

function makeIdToken(claims: Record<string, unknown>): string {
  const encode = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url')
  return `${encode({ alg: 'RS256' })}.${encode(claims)}.signature`
}

const validClaims = {
  iss: 'https://accounts.google.com',
  aud: clientId,
  sub: 'google-sub-1',
  exp: nowSeconds + 600,
  nonce: 'nonce-1',
  email: 'Owner@AcmeCorp.com',
  email_verified: true,
  hd: 'acmecorp.com',
}

function expectCode(fn: () => unknown, code: string) {
  try {
    fn()
  } catch (error) {
    expect(error).toBeInstanceOf(GoogleAuthError)
    expect((error as GoogleAuthError).code).toBe(code)
    return
  }
  throw new Error('expected GoogleAuthError')
}

describe('buildGoogleAuthorizeUrl', () => {
  it('requests an OIDC code flow with PKCE, state and nonce', () => {
    const url = new URL(buildGoogleAuthorizeUrl({
      clientId,
      redirectUri: 'https://app.example.com/api/auth_google/callback',
      state: 'state-1',
      nonce: 'nonce-1',
      codeChallenge: 'challenge-1',
      loginHint: 'owner@example.com',
    }))
    expect(url.origin + url.pathname).toBe('https://accounts.google.com/o/oauth2/v2/auth')
    expect(url.searchParams.get('response_type')).toBe('code')
    expect(url.searchParams.get('scope')).toBe('openid email profile')
    expect(url.searchParams.get('code_challenge_method')).toBe('S256')
    expect(url.searchParams.get('code_challenge')).toBe('challenge-1')
    expect(url.searchParams.get('state')).toBe('state-1')
    expect(url.searchParams.get('nonce')).toBe('nonce-1')
    expect(url.searchParams.get('login_hint')).toBe('owner@example.com')
  })
})

describe('validateGoogleIdToken', () => {
  const expected = { clientId, nonce: 'nonce-1', nowSeconds }

  it('returns the normalized identity for a valid token', () => {
    expect(validateGoogleIdToken(makeIdToken(validClaims), expected)).toEqual({
      subject: 'google-sub-1',
      email: 'owner@acmecorp.com',
      hostedDomain: 'acmecorp.com',
      name: null,
    })
  })

  it('rejects a foreign issuer', () => {
    expectCode(() => validateGoogleIdToken(makeIdToken({ ...validClaims, iss: 'https://evil.example' }), expected), 'invalid_token')
  })

  it('rejects a token minted for another client', () => {
    expectCode(() => validateGoogleIdToken(makeIdToken({ ...validClaims, aud: 'other-client' }), expected), 'invalid_token')
  })

  it('rejects an expired token', () => {
    expectCode(() => validateGoogleIdToken(makeIdToken({ ...validClaims, exp: nowSeconds - 3600 }), expected), 'invalid_token')
  })

  it('rejects a nonce mismatch', () => {
    expectCode(() => validateGoogleIdToken(makeIdToken({ ...validClaims, nonce: 'replayed' }), expected), 'invalid_token')
  })

  it('rejects an unverified email', () => {
    expectCode(() => validateGoogleIdToken(makeIdToken({ ...validClaims, email_verified: false }), expected), 'email_unverified')
  })

  it('rejects a malformed token', () => {
    expectCode(() => validateGoogleIdToken('not-a-jwt', expected), 'invalid_token')
  })
})

describe('exchangeGoogleCode', () => {
  const input = {
    clientId,
    clientSecret: 'secret',
    redirectUri: 'https://app.example.com/api/auth_google/callback',
    code: 'auth-code',
    codeVerifier: 'verifier',
  }

  it('posts the code and PKCE verifier and returns the id_token', async () => {
    const fetchImpl = jest.fn(async () => new Response(JSON.stringify({ id_token: 'id-token-1' }), { status: 200 }))
    await expect(exchangeGoogleCode(input, fetchImpl)).resolves.toBe('id-token-1')
    const [, init] = fetchImpl.mock.calls[0] as unknown as [string, RequestInit]
    const body = new URLSearchParams(String(init.body))
    expect(body.get('grant_type')).toBe('authorization_code')
    expect(body.get('code_verifier')).toBe('verifier')
    expect(body.get('code')).toBe('auth-code')
  })

  it('maps a non-2xx response to exchange_failed', async () => {
    const fetchImpl = jest.fn(async () => new Response('{"error":"invalid_grant"}', { status: 400 }))
    await expect(exchangeGoogleCode(input, fetchImpl)).rejects.toMatchObject({ code: 'exchange_failed' })
  })

  it('maps a network failure to exchange_failed', async () => {
    const fetchImpl = jest.fn(async () => { throw new Error('offline') })
    await expect(exchangeGoogleCode(input, fetchImpl)).rejects.toMatchObject({ code: 'exchange_failed' })
  })
})
