import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App'
import { AppDialogProvider } from './AppDialogs'
import './styles.css'

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <AppDialogProvider>
      <App />
    </AppDialogProvider>
  </React.StrictMode>,
)
