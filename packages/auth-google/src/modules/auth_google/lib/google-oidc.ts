import { z } from 'zod'
import { readJsonSafe } from '@open-mercato/shared/lib/http/readJsonSafe'

export const GOOGLE_AUTHORIZE_URL = 'https://accounts.google.com/o/oauth2/v2/auth'
export const GOOGLE_TOKEN_URL = 'https://oauth2.googleapis.com/token'
const GOOGLE_ISSUERS = new Set(['https://accounts.google.com', 'accounts.google.com'])
const CLOCK_SKEW_SECONDS = 60

export class GoogleAuthError extends Error {
  constructor(readonly code: GoogleAuthErrorCode, message: string) {
    super(message)
    this.name = 'GoogleAuthError'
  }
}

export type GoogleAuthErrorCode =
  | 'not_configured'
  | 'invalid_state'
  | 'access_denied'
  | 'exchange_failed'
  | 'invalid_token'
  | 'email_unverified'
  | 'domain_not_allowed'
  | 'account_not_found'

export type BuildAuthorizeUrlInput = {
  clientId: string
  redirectUri: string
  state: string
  nonce: string
  codeChallenge: string
  loginHint?: string | null
}

export function buildGoogleAuthorizeUrl(input: BuildAuthorizeUrlInput): string {
  const url = new URL(GOOGLE_AUTHORIZE_URL)
  url.searchParams.set('client_id', input.clientId)
  url.searchParams.set('redirect_uri', input.redirectUri)
  url.searchParams.set('response_type', 'code')
  url.searchParams.set('scope', 'openid email profile')
  url.searchParams.set('state', input.state)
  url.searchParams.set('nonce', input.nonce)
  url.searchParams.set('code_challenge', input.codeChallenge)
  url.searchParams.set('code_challenge_method', 'S256')
  url.searchParams.set('prompt', 'select_account')
  if (input.loginHint) url.searchParams.set('login_hint', input.loginHint)
  return url.toString()
}

const tokenResponseSchema = z.object({
  id_token: z.string().min(1),
})

const idTokenClaimsSchema = z.object({
  iss: z.string(),
  aud: z.union([z.string(), z.array(z.string())]),
  sub: z.string().min(1),
  exp: z.number(),
  nonce: z.string().optional(),
  email: z.string().email().optional(),
  email_verified: z.union([z.boolean(), z.string()]).optional(),
  hd: z.string().optional(),
  name: z.string().optional(),
})

export type GoogleIdentity = {
  subject: string
  email: string
  hostedDomain: string | null
  name: string | null
}

export type ExchangeCodeInput = {
  clientId: string
  clientSecret: string
  redirectUri: string
  code: string
  codeVerifier: string
}

type FetchLike = (input: string, init: RequestInit) => Promise<Response>

export async function exchangeGoogleCode(input: ExchangeCodeInput, fetchImpl: FetchLike = fetch): Promise<string> {
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code: input.code,
    client_id: input.clientId,
    client_secret: input.clientSecret,
    redirect_uri: input.redirectUri,
    code_verifier: input.codeVerifier,
  })
  let response: Response
  try {
    response = await fetchImpl(GOOGLE_TOKEN_URL, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' },
      body: body.toString(),
    })
  } catch {
    throw new GoogleAuthError('exchange_failed', '[internal] Google token endpoint unreachable')
  }
    if (!response.ok) {
    throw new GoogleAuthError('exchange_failed', `[internal] Google token endpoint returned ${response.status}`)
  }
  const parsed = tokenResponseSchema.safeParse(await readJsonSafe<unknown>(response, null))
  if (!parsed.success) {
    throw new GoogleAuthError('exchange_failed', '[internal] Google token response missing id_token')
  }
  return parsed.data.id_token
}

function decodeJwtClaims(idToken: string): unknown {
  const parts = idToken.split('.')
  if (parts.length !== 3) return null
  try {
    return JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'))
  } catch {
    return null
  }
}

export function validateGoogleIdToken(
  idToken: string,
  expected: { clientId: string; nonce: string; nowSeconds?: number },
): GoogleIdentity {
  const parsed = idTokenClaimsSchema.safeParse(decodeJwtClaims(idToken))
  if (!parsed.success) throw new GoogleAuthError('invalid_token', '[internal] Malformed Google ID token')
  const claims = parsed.data
  const now = expected.nowSeconds ?? Math.floor(Date.now() / 1000)
  const audiences = Array.isArray(claims.aud) ? claims.aud : [claims.aud]
  if (!GOOGLE_ISSUERS.has(claims.iss)) throw new GoogleAuthError('invalid_token', '[internal] Unexpected ID token issuer')
  if (!audiences.includes(expected.clientId)) throw new GoogleAuthError('invalid_token', '[internal] ID token audience mismatch')
  if (claims.exp + CLOCK_SKEW_SECONDS < now) throw new GoogleAuthError('invalid_token', '[internal] ID token expired')
  if (claims.nonce !== expected.nonce) throw new GoogleAuthError('invalid_token', '[internal] ID token nonce mismatch')
  if (!claims.email) throw new GoogleAuthError('invalid_token', '[internal] ID token has no email claim')
  const verified = claims.email_verified === true || claims.email_verified === 'true'
  if (!verified) throw new GoogleAuthError('email_unverified', '[internal] Google email is not verified')
  return {
    subject: claims.sub,
    email: claims.email.toLowerCase(),
    hostedDomain: claims.hd?.toLowerCase() ?? null,
    name: claims.name ?? null,
  }
}
