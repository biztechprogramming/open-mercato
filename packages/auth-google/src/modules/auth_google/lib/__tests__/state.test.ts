import { createCodeChallenge, createGoogleAuthState, openGoogleAuthState, sealGoogleAuthState } from '../state'

const originalSecret = process.env.JWT_SECRET

beforeAll(() => {
  process.env.JWT_SECRET = 'test-secret-for-auth-google-state-cookie-0123456789'
})

afterAll(() => {
  process.env.JWT_SECRET = originalSecret
})

describe('google auth state cookie', () => {
  const tenantId = '7d3f1b2e-4a5c-4d6e-8f90-123456789abc'

  it('round-trips the sealed state when the returned state matches', () => {
    const state = createGoogleAuthState({ tenantId, redirect: '/backend' })
    const opened = openGoogleAuthState(sealGoogleAuthState(state), state.state)
    expect(opened).toEqual(state)
  })

  it('rejects a mismatched returned state', () => {
    const state = createGoogleAuthState({ tenantId: null, redirect: '/backend' })
    expect(openGoogleAuthState(sealGoogleAuthState(state), 'forged-state')).toBeNull()
  })

  it('rejects a tampered cookie', () => {
    const state = createGoogleAuthState({ tenantId: null, redirect: '/backend' })
    const sealed = sealGoogleAuthState(state)
    const [header, , signature] = sealed.split('.')
    const forgedBody = Buffer.from(JSON.stringify({ ...state, redirect: '/evil' })).toString('base64url')
    expect(openGoogleAuthState(`${header}.${forgedBody}.${signature}`, state.state)).toBeNull()
  })

  it('rejects a missing cookie or state', () => {
    expect(openGoogleAuthState(null, 'x')).toBeNull()
    expect(openGoogleAuthState('a.b.c', null)).toBeNull()
  })

  it('derives an RFC 7636 S256 code challenge', () => {
    expect(createCodeChallenge('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk')).toBe('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM')
  })
})
