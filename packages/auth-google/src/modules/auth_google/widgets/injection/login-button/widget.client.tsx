'use client'

import * as React from 'react'
import type { InjectionWidgetComponentProps } from '@open-mercato/shared/modules/widgets/injection'
import type { LoginFormWidgetContext } from '@open-mercato/core/modules/auth/frontend/login-injection'
import { useT } from '@open-mercato/shared/lib/i18n/context'
import { SocialButton } from '@open-mercato/ui/primitives/social-button'

const ERROR_PARAM = 'googleError'
const START_PATH = '/api/auth_google/start'

export default function GoogleLoginButton({ context }: InjectionWidgetComponentProps<LoginFormWidgetContext>) {
  const t = useT()
  const [pending, setPending] = React.useState(false)
  const { searchParams, setError, tenantId, email } = context
  const errorCode = searchParams.get(ERROR_PARAM)

  React.useEffect(() => {
    if (!errorCode) return
    setError(t(`auth_google.errors.${errorCode}`, t('auth_google.errors.generic', 'Google sign-in failed. Please try again.')))
  }, [errorCode, setError, t])

  const handleClick = React.useCallback(() => {
    setPending(true)
    const params = new URLSearchParams()
    if (tenantId) params.set('tenant', tenantId)
    const redirect = searchParams.get('redirect')
    if (redirect) params.set('redirect', redirect)
    if (email.trim()) params.set('email', email.trim())
    const query = params.toString()
    window.location.assign(query ? `${START_PATH}?${query}` : START_PATH)
  }, [email, searchParams, tenantId])

  return (
    <SocialButton type="button" brand="google" appearance="stroke" className="w-full" onClick={handleClick} disabled={pending}>
      {pending
        ? t('auth_google.login.redirecting', 'Redirecting to Google...')
        : t('auth_google.login.button', 'Continue with Google')}
    </SocialButton>
  )
}
