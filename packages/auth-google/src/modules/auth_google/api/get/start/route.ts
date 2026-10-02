import { NextResponse } from 'next/server'
import { z } from 'zod'
import type { OpenApiRouteDoc } from '@open-mercato/shared/lib/openapi'
import { sanitizeRedirectPath } from '@open-mercato/core/modules/auth/lib/safeRedirect'
import { readGoogleAuthConfig, resolveRedirectUri } from '../../../lib/config'
import { buildGoogleAuthorizeUrl } from '../../../lib/google-oidc'
import { buildLoginErrorRedirect, GOOGLE_AUTH_COOKIE_PATH, resolveAppBase } from '../../../lib/redirects'
import {
  createCodeChallenge,
  createGoogleAuthState,
  GOOGLE_AUTH_STATE_COOKIE,
  GOOGLE_AUTH_STATE_TTL_SECONDS,
  sealGoogleAuthState,
} from '../../../lib/state'

export const metadata = {
  path: '/auth_google/start',
  GET: { requireAuth: false },
}

const tenantIdSchema = z.string().uuid()
const loginHintSchema = z.string().email()

export async function GET(req: Request) {
  const url = new URL(req.url)
  const tenantParsed = tenantIdSchema.safeParse(url.searchParams.get('tenant')?.trim())
  const tenantId = tenantParsed.success ? tenantParsed.data : null
  const config = readGoogleAuthConfig()
  if (!config) return buildLoginErrorRedirect(req, 'not_configured', tenantId)

  const appBase = resolveAppBase(req)
  const redirect = sanitizeRedirectPath(url.searchParams.get('redirect'), appBase, '/backend')
  const loginHint = loginHintSchema.safeParse(url.searchParams.get('email')?.trim())
  const state = createGoogleAuthState({ tenantId, redirect })
  const authorizeUrl = buildGoogleAuthorizeUrl({
    clientId: config.clientId,
    redirectUri: resolveRedirectUri(config, appBase),
    state: state.state,
    nonce: state.nonce,
    codeChallenge: createCodeChallenge(state.codeVerifier),
    loginHint: loginHint.success ? loginHint.data : null,
  })

  const res = NextResponse.redirect(authorizeUrl, 307)
  res.cookies.set(GOOGLE_AUTH_STATE_COOKIE, sealGoogleAuthState(state), {
    httpOnly: true,
    path: GOOGLE_AUTH_COOKIE_PATH,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    maxAge: GOOGLE_AUTH_STATE_TTL_SECONDS,
  })
  return res
}

export const openApi: OpenApiRouteDoc = {
  tag: 'Authentication & Accounts',
  summary: 'Start Google sign-in',
  methods: {
    GET: {
      summary: 'Redirect to Google for OpenID Connect sign-in',
      description:
        'Stores a signed, short-lived state cookie (state, nonce, PKCE verifier) and redirects the browser to Google. Optional query params: `tenant` (tenant UUID), `redirect` (same-origin path after sign-in), `email` (login hint).',
      responses: [
        { status: 307, description: 'Redirect to Google, or back to /login when Google sign-in is not configured', mediaType: 'text/html' },
      ],
    },
  },
}
