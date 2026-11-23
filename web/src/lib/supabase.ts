import { createClient } from '@supabase/supabase-js'
import { addObservedEgressBytes } from './usageByteCounter'

const productionUrl = 'https://pgbipustotixwahmotvu.supabase.co'
const productionPublishableKey = 'sb_publishable_QvmzYuPfcZAYsAwdB2vrcQ_IZ5tABcr'

const url = (import.meta.env.VITE_SUPABASE_URL as string | undefined) || productionUrl
const key = (import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY as string | undefined) || productionPublishableKey

export const isBackendConfigured = Boolean(url && key)

// Supabase/PostgREST can briefly return PGRST303 ("JWT issued at future")
// for freshly issued sessions when its token issuer and verifier disagree
// about the current time. Keep validation on the server; only retry this
// specific 401 response a bounded number of times. The permanent fix for
// affected PostgREST versions is a Supabase infrastructure upgrade.
const jwtIssuedInFuture = async (response: Response): Promise<boolean> => {
  if (response.status !== 401) return false
  try {
    const body = (await response.clone().json()) as { code?: string; message?: string }
    return body?.code === 'PGRST303' && /JWT issued at future/i.test(body.message || '')
  } catch {
    return false
  }
}

const retryDelaysMs = [1000, 2000, 4000]

const measuredFetch: typeof globalThis.fetch = async (input, init) => {
  const requestUrl = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url
  const isPostgrestRequest = requestUrl.startsWith(url.replace(/\/$/, '') + '/rest/v1/')

  for (let attempt = 0; ; attempt++) {
    // Clone Request inputs so an already-consumed request body is never reused
    // when a PostgREST request is safely retried after a rejected token.
    const response = await globalThis.fetch(input instanceof Request ? input.clone() : input, init)

    // Count all actual HTTP responses, including any rejected request that
    // was retried. Never consume the response body needed by Supabase.
    const lengthHeader = Number(response.headers.get('content-length') || '0')
    if (Number.isFinite(lengthHeader) && lengthHeader > 0) {
      addObservedEgressBytes(lengthHeader)
    } else {
      void response.clone().arrayBuffer()
        .then(buffer => addObservedEgressBytes(buffer.byteLength))
        .catch(() => undefined)
    }

    if (!isPostgrestRequest || attempt >= retryDelaysMs.length || !(await jwtIssuedInFuture(response))) {
      return response
    }
    if (init?.signal?.aborted || (input instanceof Request && input.signal.aborted)) {
      return response
    }
    await new Promise<void>(resolve => setTimeout(resolve, retryDelaysMs[attempt]))
  }
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
