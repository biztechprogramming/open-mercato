# `@open-mercato/auth-google` — Agent Guidelines

"Continue with Google" for staff users. OpenID Connect authorization-code flow with PKCE, state and nonce. Opt-in via `OM_ENABLE_AUTH_GOOGLE=true`.

- **Package**: `@open-mercato/auth-google` ⇒ **module id**: `auth_google`
- Signs in **existing** users only — the verified Google email must match exactly one active user (scoped to `?tenant=` when given). No just-in-time provisioning.
- Issues the same `auth_token` / `session_token` cookies as `POST /api/auth/login` via `AuthService.createSession` + `signJwt`.

## Key Files (`src/modules/auth_google/`)

| File | Purpose |
|------|---------|
| `api/get/start/route.ts` | `GET /api/auth_google/start` — seals state cookie, redirects to Google |
| `api/get/callback/route.ts` | `GET /api/auth_google/callback` — verifies state, exchanges code, signs the user in |
| `lib/config.ts` | Env config (`GOOGLE_AUTH_CLIENT_ID`, `GOOGLE_AUTH_CLIENT_SECRET`, `GOOGLE_AUTH_ALLOWED_DOMAINS`, `GOOGLE_AUTH_REDIRECT_URI`) |
| `lib/state.ts` | Audience-scoped signed state cookie (`auth_google.state`), PKCE challenge |
| `lib/google-oidc.ts` | Authorize URL, token exchange, ID-token claim validation, `GoogleAuthError` codes |
| `lib/sign-in.ts` | User resolution + session issuance |
| `widgets/injection/login-button/` | Button injected into `auth.login:form`; maps `?googleError=<code>` to `auth_google.errors.<code>` |

## Rules

- The ID token is taken from Google's token endpoint over TLS (OIDC Core §3.1.3.7), so its claims are validated (`iss`, `aud`, `exp`, `nonce`, `email_verified`) without JWKS signature checks. Never accept an ID token from the browser.
- Keep error responses generic — the callback only ever redirects to `/login?googleError=<code>`.
- Validate: `yarn workspace @open-mercato/auth-google test` and `typecheck`.
