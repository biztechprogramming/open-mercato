# Sign in with Google (`auth_google`)

## TLDR

New opt-in provider package `@open-mercato/auth-google` (module `auth_google`) that adds a "Continue with Google" button to the staff login page. Existing users sign in with their Google account; no accounts are created automatically.

## Overview

Staff today can only sign in with email and password. This module adds Google as a second way to sign in, through OpenID Connect. It touches no core code: it uses the existing `auth.login:form` injection spot and the public `AuthService` session API.

## Architecture

- `GET /api/auth_google/start?tenant=&redirect=&email=` creates `{state, nonce, codeVerifier, tenantId, redirect}`, seals it into an httpOnly cookie (`om_google_auth_state`, path `/api/auth_google`, 10 min) signed with the `auth_google.state` JWT audience, and 307s to Google (`scope=openid email profile`, `code_challenge_method=S256`, `prompt=select_account`).
- `GET /api/auth_google/callback` checks the cookie against the returned `state`, exchanges the code with the PKCE verifier, and validates the ID token (`iss`, `aud`, `exp`, `nonce`, `email_verified`). It then applies the optional domain allowlist and resolves the user the same way password login does: by tenant when `tenant` was given, otherwise only when the email belongs to exactly one user. It refuses deactivated users. On success it issues the `auth_token` and `session_token` cookies (8 h), emits `auth.login.success`, and redirects to the sanitized `redirect`. On failure it emits `auth.login.failed` (reason `google_<code>`, once the email is known) and redirects to `/login?googleError=<code>`.
- A login widget renders the button and turns `googleError` into a translated message through the `setError` login-form context.

## Configuration

| Env | Required | Meaning |
|-----|----------|---------|
| `OM_ENABLE_AUTH_GOOGLE` | yes | Adds `auth_google` to `enabledModules` |
| `GOOGLE_AUTH_CLIENT_ID` / `GOOGLE_AUTH_CLIENT_SECRET` | yes | Google OAuth "Web application" client |
| `GOOGLE_AUTH_ALLOWED_DOMAINS` | no | Comma-separated email domains allowed to sign in |
| `GOOGLE_AUTH_REDIRECT_URI` | no | Override for `<APP_URL>/api/auth_google/callback` |

## Security

- CSRF/login-CSRF: signed state cookie + constant-time state compare; replay: nonce; code interception: PKCE S256.
- Open redirect: `redirect` goes through `sanitizeRedirectPath`; final redirects use `buildSafeRedirectResponse`.
- No account enumeration beyond the existing login: every failure redirects with a generic code.
- Known gap: the after-interceptors of `auth/login` (e.g. an MFA challenge) do not run for Google sign-in.

## Migration & Backward Compatibility

Additive only: new package, new routes under `/api/auth_google/*`, new env vars and i18n keys. The module is off by default. No DB schema changes, and no contract surfaces are changed.

## Test Coverage

Unit and route tests in `packages/auth-google/src/modules/auth_google/**/__tests__` cover the authorize URL, token exchange, ID-token validation, the state cookie (round-trip, tamper, mismatch), config and domain allowlist, user resolution (tenant, ambiguous, deactivated), and the start/callback happy path, missing cookie, disallowed domain and cancelled consent. An end-to-end run against real Google needs live credentials, so it is a manual QA step.

## Changelog

- 2026-10-02: Initial implementation.
