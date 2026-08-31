import { createClient } from 'npm:@supabase/supabase-js@2.57.4'

const cors = {
  'access-control-allow-origin': 'https://secure.creccommw.org',
  'access-control-allow-headers': 'authorization, x-client-info, apikey, content-type',
  'access-control-allow-methods': 'POST, OPTIONS',
}
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), {
  status, headers: { ...cors, 'content-type': 'application/json; charset=utf-8' },
})
const sha256 = async (value: string) => {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value))
  return Array.from(new Uint8Array(digest)).map(byte => byte.toString(16).padStart(2, '0')).join('')
}
const randomCode = () => {
  const bytes = crypto.getRandomValues(new Uint8Array(12))
  const hex = Array.from(bytes).map(byte => byte.toString(16).padStart(2, '0')).join('').toUpperCase()
  return `CSC-${hex.slice(0, 8)}-${hex.slice(8, 16)}-${hex.slice(16, 24)}`
}

Deno.serve(async (req: Request) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: cors })
  if (req.method !== 'POST') return json({ error: 'Method not allowed' }, 405)

  const url = Deno.env.get('SUPABASE_URL') || ''
  const publishableKey = Deno.env.get('SUPABASE_ANON_KEY') || ''
  const serviceKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY') || ''
  const authorization = req.headers.get('authorization') || ''
  const userClient = createClient(url, publishableKey, { global: { headers: { Authorization: authorization } } })
  const token = authorization.replace(/^Bearer\s+/i, '')
  const { data: { user }, error: userError } = await userClient.auth.getUser(token)
  if (userError || !user || !user.email?.toLowerCase().endsWith('@creccommw.org')) {
    return json({ error: 'A CRECCOM account is required' }, 403)
  }

  const admin = createClient(url, serviceKey, { auth: { persistSession: false, autoRefreshToken: false } })
  const body = await req.json().catch(() => ({})) as { action?: string, label?: string, terminalId?: string }
  if (body.action === 'create_enrollment') {
    const code = randomCode()
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString()
    const { error } = await admin.rpc('create_terminal_enrollment', {
      p_code_hash: await sha256(code), p_code_prefix: code.slice(0, 12), p_label: body.label?.slice(0, 100) || '',
      p_created_by: user.id, p_expires_at: expiresAt,
    })
    if (error) return json({ error: 'Could not create enrollment code' }, 500)
    return json({ code, expiresAt })
  }

  if (body.action === 'revoke_terminal' && body.terminalId) {
    const { error } = await admin.rpc('revoke_terminal', { p_terminal_id: body.terminalId })
    if (error) return json({ error: 'Could not revoke terminal' }, 500)
    return json({ ok: true })
  }

  return json({ error: 'Unsupported action' }, 400)
})
