import type { AuthService } from '@open-mercato/core/modules/auth/services/authService'
import { signJwt } from '@open-mercato/shared/lib/auth/jwt'
import { GoogleAuthError, type GoogleIdentity } from './google-oidc'

export const GOOGLE_SESSION_MAX_AGE_SECONDS = 60 * 60 * 8

type AuthUser = NonNullable<Awaited<ReturnType<AuthService['findUserByEmailAndTenant']>>>

export type GoogleSignInResult = {
  user: AuthUser
  tenantId: string | null
  organizationId: string | null
  token: string
  sessionToken: string
}

export async function resolveGoogleUser(
  auth: Pick<AuthService, 'findUserByEmailAndTenant' | 'findUsersByEmail'>,
  identity: GoogleIdentity,
  tenantId: string | null,
): Promise<AuthUser> {
  let user: AuthUser | null = null
  if (tenantId) {
    user = await auth.findUserByEmailAndTenant(identity.email, tenantId)
  } else {
    const users = await auth.findUsersByEmail(identity.email)
    user = users.length === 1 ? users[0] : null
  }
  if (!user || user.isConfirmed === false) {
    throw new GoogleAuthError('account_not_found', '[internal] No single active account matches the Google email')
  }
  return user
}

export async function issueGoogleSession(
  auth: Pick<AuthService, 'getUserRoles' | 'updateLastLoginAt' | 'createSession'>,
  user: AuthUser,
  requestedTenantId: string | null,
): Promise<GoogleSignInResult> {
  const tenantId = requestedTenantId ?? (user.tenantId ? String(user.tenantId) : null)
  const organizationId = user.organizationId ? String(user.organizationId) : null
  const roles = await auth.getUserRoles(user, tenantId)
  await auth.updateLastLoginAt(user)
  const expiresAt = new Date(Date.now() + GOOGLE_SESSION_MAX_AGE_SECONDS * 1000)
  const { session, token: sessionToken } = await auth.createSession(user, expiresAt)
  const token = signJwt({
    sub: String(user.id),
    sid: String(session.id),
    tenantId,
    orgId: organizationId,
    email: user.email,
    roles,
  })
  return { user, tenantId, organizationId, token, sessionToken }
}
