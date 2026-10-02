import type { InjectionWidgetModule } from '@open-mercato/shared/modules/widgets/injection'
import type { LoginFormWidgetContext } from '@open-mercato/core/modules/auth/frontend/login-injection'
import GoogleLoginButton from './widget.client'

const widget: InjectionWidgetModule<LoginFormWidgetContext> = {
  metadata: {
    id: 'auth_google.injection.login-button',
    title: 'Continue with Google',
    description: 'Adds a "Continue with Google" button to the staff login form.',
    priority: 100,
    enabled: true,
  },
  Widget: GoogleLoginButton,
}

export default widget
