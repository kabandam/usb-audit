import { createClient } from '@supabase/supabase-js'

// Vite normally injects these at build time. The production fallback keeps
// pre-built/manual Netlify deploys connected to the dedicated CRECCOM
// Security Console project. The publishable key is browser-safe by design;
// never place a service-role/secret key here.
const productionUrl = 'https://pgbipustotixwahmotvu.supabase.co'
const productionPublishableKey = 'sb_publishable_QvmzYuPfcZAYsAwdB2vrcQ_IZ5tABcr'

const url = (import.meta.env.VITE_SUPABASE_URL as string | undefined) || productionUrl
const key = (import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY as string | undefined) || productionPublishableKey

export const isBackendConfigured = Boolean(url && key)

export const supabase = isBackendConfigured
  ? createClient(url, key, {
      auth: {
        persistSession: true,
        autoRefreshToken: true,
        detectSessionInUrl: true,
      },
    })
  : null
