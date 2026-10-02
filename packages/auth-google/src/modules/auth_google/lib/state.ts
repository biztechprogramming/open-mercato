import crypto from 'node:crypto'
import { z } from 'zod'
import { signAudienceJwt, verifyAudienceJwt } from '@open-mercato/shared/lib/auth/jwt'

export const GOOGLE_AUTH_STATE_COOKIE = 'om_google_auth_state'
export const GOOGLE_AUTH_STATE_TTL_SECONDS = 10 * 60
const STATE_AUDIENCE = 'auth_google.state'

const statePayloadSchema = z.object({
  state: z.string().min(1),
  nonce: z.string().min(1),
  codeVerifier: z.string().min(43).max(128),
  tenantId: z.string().uuid().nullable(),
  redirect: z.string(),
})

export type GoogleAuthState = z.infer<typeof statePayloadSchema>

function randomToken(bytes: number = 32): string {
  return crypto.randomBytes(bytes).toString('base64url')
}

export function createCodeChallenge(codeVerifier: string): string {
  return crypto.createHash('sha256').update(codeVerifier).digest('base64url')
}

export function createGoogleAuthState(input: { tenantId: string | null; redirect: string }): GoogleAuthState {
  return {
    state: randomToken(),
    nonce: randomToken(),
    codeVerifier: randomToken(48),
    tenantId: input.tenantId,
    redirect: input.redirect,
  }
}

export function sealGoogleAuthState(state: GoogleAuthState): string {
  return signAudienceJwt(STATE_AUDIENCE, state, GOOGLE_AUTH_STATE_TTL_SECONDS)
}

export function openGoogleAuthState(cookieValue: string | null | undefined, returnedState: string | null): GoogleAuthState | null {
  if (!cookieValue || !returnedState) return null
  const payload = verifyAudienceJwt(STATE_AUDIENCE, cookieValue)
  if (!payload) return null
  const parsed = statePayloadSchema.safeParse(payload)
  if (!parsed.success) return null
  const expected = Buffer.from(parsed.data.state)
  const provided = Buffer.from(returnedState)
  if (expected.length !== provided.length || !crypto.timingSafeEqual(expected, provided)) return null
  return parsed.data
}
