import { buildSafeRedirectResponse, resolveTrustedRedirectBase } from '@open-mercato/core/modules/auth/lib/requestRedirect'
import type { GoogleAuthErrorCode } from './google-oidc'
import { GOOGLE_AUTH_STATE_COOKIE } from './state'

export const GOOGLE_AUTH_ERROR_PARAM = 'googleError'
export const GOOGLE_AUTH_COOKIE_PATH = '/api/auth_google'

export function resolveAppBase(req: Request): string {
  return resolveTrustedRedirectBase(req) ?? new URL(req.url).origin
}

export function buildLoginErrorRedirect(req: Request, code: GoogleAuthErrorCode, tenantId: string | null = null) {
  const params = new URLSearchParams({ [GOOGLE_AUTH_ERROR_PARAM]: code })
  if (tenantId) params.set('tenant', tenantId)
  const res = buildSafeRedirectResponse(req, `/login?${params.toString()}`)
  clearStateCookie(res)
  return res
}

export function clearStateCookie(res: { cookies: { set: (name: string, value: string, options: Record<string, unknown>) => unknown } }) {
  res.cookies.set(GOOGLE_AUTH_STATE_COOKIE, '', {
    httpOnly: true,
    path: GOOGLE_AUTH_COOKIE_PATH,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    maxAge: 0,
  })
}
