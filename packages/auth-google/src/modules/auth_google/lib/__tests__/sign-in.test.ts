import { resolveGoogleUser } from '../sign-in'
import type { GoogleIdentity } from '../google-oidc'

const identity: GoogleIdentity = { subject: 'sub', email: 'owner@example.org', hostedDomain: null, name: null }
const tenantId = '7d3f1b2e-4a5c-4d6e-8f90-123456789abc'

function makeAuth(overrides: { byTenant?: unknown; byEmail?: unknown[] }) {
  return {
    findUserByEmailAndTenant: jest.fn(async () => overrides.byTenant ?? null),
    findUsersByEmail: jest.fn(async () => overrides.byEmail ?? []),
  } as never
}

describe('resolveGoogleUser', () => {
  it('looks the user up inside the requested tenant', async () => {
    const user = { id: 'u1', isConfirmed: true }
    const auth = makeAuth({ byTenant: user })
    await expect(resolveGoogleUser(auth, identity, tenantId)).resolves.toBe(user)
  })

  it('accepts a single match across tenants when no tenant is requested', async () => {
    const user = { id: 'u1', isConfirmed: true }
    await expect(resolveGoogleUser(makeAuth({ byEmail: [user] }), identity, null)).resolves.toBe(user)
  })

  it('refuses an email registered in several tenants without a tenant hint', async () => {
    const auth = makeAuth({ byEmail: [{ id: 'u1' }, { id: 'u2' }] })
    await expect(resolveGoogleUser(auth, identity, null)).rejects.toMatchObject({ code: 'account_not_found' })
  })

  it('refuses unknown and deactivated accounts', async () => {
    await expect(resolveGoogleUser(makeAuth({}), identity, null)).rejects.toMatchObject({ code: 'account_not_found' })
    const auth = makeAuth({ byTenant: { id: 'u1', isConfirmed: false } })
    await expect(resolveGoogleUser(auth, identity, tenantId)).rejects.toMatchObject({ code: 'account_not_found' })
  })
})
