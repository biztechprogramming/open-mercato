import { isEmailDomainAllowed, parseAllowedDomains, readGoogleAuthConfig, resolveRedirectUri } from '../config'

describe('google auth config', () => {
  it('is disabled when the client id or secret is missing', () => {
    expect(readGoogleAuthConfig({ GOOGLE_AUTH_CLIENT_ID: 'id' } as NodeJS.ProcessEnv)).toBeNull()
    expect(readGoogleAuthConfig({ GOOGLE_AUTH_CLIENT_SECRET: 'secret' } as NodeJS.ProcessEnv)).toBeNull()
  })

  it('reads credentials, domains and redirect override', () => {
    const config = readGoogleAuthConfig({
      GOOGLE_AUTH_CLIENT_ID: ' id ',
      GOOGLE_AUTH_CLIENT_SECRET: 'secret',
      GOOGLE_AUTH_ALLOWED_DOMAINS: 'AcmeCorp.com, @example.org',
      GOOGLE_AUTH_REDIRECT_URI: 'https://app.example.com/custom',
    } as NodeJS.ProcessEnv)
    expect(config).toEqual({
      clientId: 'id',
      clientSecret: 'secret',
      allowedDomains: ['acmecorp.com', 'example.org'],
      redirectUri: 'https://app.example.com/custom',
    })
  })

  it('derives the callback URL from the app base when not overridden', () => {
    const config = { clientId: 'id', clientSecret: 'secret', allowedDomains: [], redirectUri: null }
    expect(resolveRedirectUri(config, 'https://app.example.com')).toBe('https://app.example.com/api/auth_google/callback')
  })

  it('allows any domain when no allowlist is set, otherwise only listed domains', () => {
    expect(isEmailDomainAllowed('a@anything.com', [])).toBe(true)
    const allowed = parseAllowedDomains('acmecorp.com,example.org')
    expect(isEmailDomainAllowed('a@Example.org', allowed)).toBe(true)
    expect(isEmailDomainAllowed('a@gmail.com', allowed)).toBe(false)
  })
})
