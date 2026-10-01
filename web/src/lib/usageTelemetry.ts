import { supabase } from './supabase'
import { addObservedEgressBytes, peekObservedEgressBytes, restoreObservedEgressBytes, takeObservedEgressBytes } from './usageByteCounter'

const encoder = new TextEncoder()
let flushTimer: number | null = null
let flushing = false

const clientId = () => {
  const key = 'smart-console:usage-client-id'
  let value = sessionStorage.getItem(key)
  if (!value) {
    value = crypto.randomUUID()
    sessionStorage.setItem(key, value)
  }
  return value
}

const byteSize = (value: unknown) => {
  if (value == null) return 0
  try { return encoder.encode(JSON.stringify(value)).byteLength }
  catch { return 0 }
}

// Use this only for non-fetch traffic such as Supabase Realtime websocket payloads.
// Normal Supabase HTTP responses are measured centrally by the custom client fetch.
export const observeSupabaseEgress = (...payloads: unknown[]) => {
  let addedBytes = 0
  for (const payload of payloads) addedBytes += byteSize(payload)
  addObservedEgressBytes(addedBytes)
  scheduleFlush()
}

export const scheduleFlush = () => {
  const bytes = peekObservedEgressBytes()
  if (bytes <= 0) return
  if (bytes >= 128 * 1024) {
    void flushWebEgress()
    return
  }
  if (flushTimer == null) {
    flushTimer = window.setTimeout(() => {
      flushTimer = null
      void flushWebEgress()
    }, 5 * 60_000)
  }
}

export const flushWebEgress = async () => {
  if (!supabase || flushing || peekObservedEgressBytes() <= 0) return
  flushing = true
  const bytes = takeObservedEgressBytes()
  if (flushTimer != null) {
    window.clearTimeout(flushTimer)
    flushTimer = null
  }
  try {
    const { error } = await supabase.rpc('record_client_egress', {
      p_report_id: crypto.randomUUID(),
      p_client_type: 'web',
      p_client_id: clientId(),
      p_bytes: bytes,
    })
    if (error) restoreObservedEgressBytes(bytes)
  } catch {
    restoreObservedEgressBytes(bytes)
  } finally {
    flushing = false
    scheduleFlush()
  }
}
