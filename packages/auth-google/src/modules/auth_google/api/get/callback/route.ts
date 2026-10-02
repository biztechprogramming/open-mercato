import type { OpenApiRouteDoc } from '@open-mercato/shared/lib/openapi'
import { createRequestContainer } from '@open-mercato/shared/lib/di/container'
import { createLogger } from '@open-mercato/shared/lib/logger'
import type { AuthService } from '@open-mercato/core/modules/auth/services/authService'
import { buildSafeRedirectResponse } from '@open-mercato/core/modules/auth/lib/requestRedirect'
import { emitAuthEvent } from '@open-mercato/core/modules/auth/events'
import { isEmailDomainAllowed, readGoogleAuthConfig, resolveRedirectUri } from '../../../lib/config'
import { exchangeGoogleCode, GoogleAuthError, type GoogleIdentity, validateGoogleIdToken } from '../../../lib/google-oidc'
import { buildLoginErrorRedirect, clearStateCookie, resolveAppBase } from '../../../lib/redirects'
import { GOOGLE_SESSION_MAX_AGE_SECONDS, issueGoogleSession, resolveGoogleUser } from '../../../lib/sign-in'
import { GOOGLE_AUTH_STATE_COOKIE, openGoogleAuthState } from '../../../lib/state'

export const metadata = {
  path: '/auth_google/callback',
  GET: { requireAuth: false },
}

const logger = createLogger('auth_google').child({ component: 'callback' })

function readCookie(req: Request, name: string): string | null {
  const header = req.headers.get('cookie')
  if (!header) return null
  for (const part of header.split(';')) {
    const [rawName, ...rest] = part.trim().split('=')
    if (rawName !== name) continue
    try {
      return decodeURIComponent(rest.join('='))
    } catch {
      return null
    }
  }
  return null
}

export async function GET(req: Request) {
  const url = new URL(req.url)
  const state = openGoogleAuthState(readCookie(req, GOOGLE_AUTH_STATE_COOKIE), url.searchParams.get('state'))
  if (!state) return buildLoginErrorRedirect(req, 'invalid_state')
  if (url.searchParams.get('error')) return buildLoginErrorRedirect(req, 'access_denied', state.tenantId)
  const code = url.searchParams.get('code')
  if (!code) return buildLoginErrorRedirect(req, 'invalid_state', state.tenantId)

  const config = readGoogleAuthConfig()
  if (!config) return buildLoginErrorRedirect(req, 'not_configured', state.tenantId)

  let identity: GoogleIdentity | null = null
  try {
    const idToken = await exchangeGoogleCode({
      clientId: config.clientId,
      clientSecret: config.clientSecret,
      redirectUri: resolveRedirectUri(config, resolveAppBase(req)),
      code,
      codeVerifier: state.codeVerifier,
    })
    identity = validateGoogleIdToken(idToken, { clientId: config.clientId, nonce: state.nonce })
    if (!isEmailDomainAllowed(identity.email, config.allowedDomains)) {
      throw new GoogleAuthError('domain_not_allowed', '[internal] Google email domain is not allowed')
    }

    const container = await createRequestContainer()
    const auth = container.resolve<AuthService>('authService')
    const user = await resolveGoogleUser(auth, identity, state.tenantId)
    const session = await issueGoogleSession(auth, user, state.tenantId)
    void emitAuthEvent('auth.login.success', {
      id: String(user.id),
      email: user.email,
      tenantId: session.tenantId,
      organizationId: session.organizationId,
    }).catch(() => undefined)

    const res = buildSafeRedirectResponse(req, state.redirect)
    clearStateCookie(res)
    const cookieOptions = {
      httpOnly: true,
      path: '/',
      sameSite: 'lax' as const,
      secure: process.env.NODE_ENV === 'production',
      maxAge: GOOGLE_SESSION_MAX_AGE_SECONDS,
    }
    res.cookies.set('auth_token', session.token, cookieOptions)
    res.cookies.set('session_token', session.sessionToken, cookieOptions)
    return res
  } catch (error) {
    if (error instanceof GoogleAuthError) {
      if (identity) {
        void emitAuthEvent('auth.login.failed', { email: identity.email, reason: `google_${error.code}` }).catch(() => undefined)
      }
      logger.warn('Google sign-in rejected', { code: error.code })
      return buildLoginErrorRedirect(req, error.code, state.tenantId)
    }
    logger.error('Google sign-in failed unexpectedly', { err: error })
    return buildLoginErrorRedirect(req, 'exchange_failed', state.tenantId)
  }
}

export const openApi: OpenApiRouteDoc = {
  tag: 'Authentication & Accounts',
  summary: 'Google sign-in callback',
  methods: {
    GET: {
      summary: 'Complete Google OpenID Connect sign-in',
      description:
        'Validates the state cookie, exchanges the authorization code (PKCE) for an ID token, and signs in the existing user whose email matches the verified Google email. On failure redirects to /login with a `googleError` code.',
      responses: [
        { status: 307, description: 'Redirect into the app on success, or to /login?googleError=<code> on failure', mediaType: 'text/html' },
      ],
    },
  },
}
