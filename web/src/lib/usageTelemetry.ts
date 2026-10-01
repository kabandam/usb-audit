import { supabase } from './supabase'

const encoder = new TextEncoder()
let pendingBytes = 0
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

export const observeSupabaseEgress = (...payloads: unknown[]) => {
  pendingBytes += payloads.reduce((total, payload) => total + byteSize(payload), 0)
  if (pendingBytes <= 0) return
  if (pendingBytes >= 128 * 1024) {
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
  if (!supabase || flushing || pendingBytes <= 0) return
  flushing = true
  const bytes = pendingBytes
  pendingBytes = 0
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
    if (error) pendingBytes += bytes
  } catch {
    pendingBytes += bytes
  } finally {
    flushing = false
  }
}
