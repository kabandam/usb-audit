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
const allowedCommands = new Set(['inventory', 'remote_support'])

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
  if (userError || !user || user.email?.toLowerCase() !== 'martinkabanda@creccommw.org') {
    return json({ error: 'This account is not authorized for the security console' }, 403)
  }

  const admin = createClient(url, serviceKey, { auth: { persistSession: false, autoRefreshToken: false } })
  const body = await req.json().catch(() => ({})) as { action?: string, label?: string, terminalId?: string, commandType?: string }
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
    await admin.from('endpoint_audit_log').insert({ actor_user_id: user.id, terminal_id: body.terminalId, action: 'terminal_revoked', details: {} })
    return json({ ok: true })
  }

  if (body.action === 'request_command' && body.terminalId && body.commandType) {
    if (!allowedCommands.has(body.commandType)) return json({ error: 'This endpoint command is not enabled yet' }, 400)
    const { data: terminal, error: terminalError } = await admin.from('terminals').select('terminal_id,enrollment_status').eq('terminal_id', body.terminalId).maybeSingle()
    if (terminalError || !terminal || terminal.enrollment_status === 'revoked') return json({ error: 'Endpoint is unavailable or revoked' }, 404)

    const { data: command, error: commandError } = await admin.from('endpoint_commands').insert({
      terminal_id: body.terminalId,
      command_type: body.commandType,
      requested_by: user.id,
      payload: body.commandType === 'remote_support' ? { mode: 'user_visible_support' } : {},
    }).select('command_id,status,requested_at').single()
    if (commandError) return json({ error: 'Could not queue endpoint command' }, 500)

    await admin.from('endpoint_audit_log').insert({
      actor_user_id: user.id,
      terminal_id: body.terminalId,
      action: `command_requested:${body.commandType}`,
      details: { command_id: command.command_id },
    })
    return json({ ok: true, command })
  }

  return json({ error: 'Unsupported action' }, 400)
})
