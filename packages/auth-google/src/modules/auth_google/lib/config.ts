export type GoogleAuthConfig = {
  clientId: string
  clientSecret: string
  allowedDomains: string[]
  redirectUri: string | null
}

export const GOOGLE_AUTH_CALLBACK_PATH = '/api/auth_google/callback'

function readTrimmed(env: NodeJS.ProcessEnv, key: string): string {
  const value = env[key]
  return typeof value === 'string' ? value.trim() : ''
}

export function parseAllowedDomains(raw: string): string[] {
  return raw
    .split(',')
    .map((domain) => domain.trim().toLowerCase().replace(/^@/, ''))
    .filter(Boolean)
}

export function readGoogleAuthConfig(env: NodeJS.ProcessEnv = process.env): GoogleAuthConfig | null {
  const clientId = readTrimmed(env, 'GOOGLE_AUTH_CLIENT_ID')
  const clientSecret = readTrimmed(env, 'GOOGLE_AUTH_CLIENT_SECRET')
  if (!clientId || !clientSecret) return null
  return {
    clientId,
    clientSecret,
    allowedDomains: parseAllowedDomains(readTrimmed(env, 'GOOGLE_AUTH_ALLOWED_DOMAINS')),
    redirectUri: readTrimmed(env, 'GOOGLE_AUTH_REDIRECT_URI') || null,
  }
}

export function resolveRedirectUri(config: GoogleAuthConfig, appBaseUrl: string): string {
  if (config.redirectUri) return config.redirectUri
  return new URL(GOOGLE_AUTH_CALLBACK_PATH, appBaseUrl).toString()
}

export function isEmailDomainAllowed(email: string, allowedDomains: string[]): boolean {
  if (!allowedDomains.length) return true
  const domain = email.split('@').pop()?.toLowerCase() ?? ''
  return allowedDomains.includes(domain)
}
