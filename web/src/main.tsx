import { acceptLauncherSignIn } from './lib/launcherSignIn'
import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App'
import { AppDialogProvider } from './AppDialogs'
import './styles.css'

function renderConsole() {
ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <AppDialogProvider>
      <App />
    </AppDialogProvider>
  </React.StrictMode>,
)
}

void acceptLauncherSignIn().then(allowed => { if (allowed) renderConsole() }).catch(() => {
  ReactDOM.createRoot(document.getElementById('root')!).render(<main><p>Unable to complete the Security Console sign-in with your assigned account.</p><a href="https://apps.creccommw.org/">Return to the CREMIS App Launcher</a></main>)
})
