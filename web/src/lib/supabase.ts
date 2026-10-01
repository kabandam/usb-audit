import { createClient } from '@supabase/supabase-js'
import { addObservedEgressBytes } from './usageByteCounter'

const productionUrl = 'https://pgbipustotixwahmotvu.supabase.co'
const productionPublishableKey = 'sb_publishable_QvmzYuPfcZAYsAwdB2vrcQ_IZ5tABcr'

const url = (import.meta.env.VITE_SUPABASE_URL as string | undefined) || productionUrl
const key = (import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY as string | undefined) || productionPublishableKey

export const isBackendConfigured = Boolean(url && key)

const measuredFetch: typeof globalThis.fetch = async (input, init) => {
  const response = await globalThis.fetch(input, init)

  // Measure every Supabase HTTP response in one place so Auth, PostgREST,
  // Edge Functions and Storage responses are all included without relying on
  // page-specific bookkeeping. Prefer Content-Length when the edge provides it;
  // otherwise measure a cloned response body without consuming the real response.
  const lengthHeader = Number(response.headers.get('content-length') || '0')
  if (Number.isFinite(lengthHeader) && lengthHeader > 0) {
    addObservedEgressBytes(lengthHeader)
  } else {
    void response.clone().arrayBuffer()
      .then(buffer => addObservedEgressBytes(buffer.byteLength))
      .catch(() => undefined)
  }

  return response
}

export const supabase = isBackendConfigured
  ? createClient(url, key, {
      global: { fetch: measuredFetch },
      auth: {
        persistSession: true,
        autoRefreshToken: true,
        detectSessionInUrl: true,
      },
    })
  : null
