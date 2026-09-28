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

type AdminClient = ReturnType<typeof createClient>
type RequestBody = {
  action?: string
  label?: string
  terminalId?: string
  commandType?: string
  mode?: 'audit' | 'enforce'
  softwareKey?: string
  terminalIds?: string[]
  allTerminalIds?: string[]
}

async function queuePolicySync(admin: AdminClient, terminalId: string, requestedBy: string) {
  const { data: policy, error: policyError } = await admin.from('endpoint_policies')
    .select('mode').eq('is_default', true).order('updated_at', { ascending: false }).limit(1).maybeSingle()
  if (policyError) throw policyError

  const { data: rules, error: rulesError } = await admin.from('software_control_rules')
    .select('software_key,software_name,publisher,install_location,executable_paths')
    .eq('terminal_id', terminalId).eq('is_active', true).eq('action', 'block')
  if (rulesError) throw rulesError

  await admin.from('endpoint_commands').update({
    status: 'cancelled',
    completed_at: new Date().toISOString(),
    result: { message: 'Superseded by a newer endpoint policy.' },
  }).eq('terminal_id', terminalId).eq('command_type', 'sync_policy').in('status', ['pending', 'acknowledged'])

  const payload = {
    mode: policy?.mode === 'enforce' ? 'enforce' : 'audit',
    blockedSoftware: (rules ?? []).map(rule => ({
      softwareKey: rule.software_key,
      softwareName: rule.software_name,
      publisher: rule.publisher,
      installLocation: rule.install_location,
      executablePaths: Array.isArray(rule.executable_paths) ? rule.executable_paths : [],
    })),
  }

  const { error } = await admin.from('endpoint_commands').insert({
    terminal_id: terminalId,
    command_type: 'sync_policy',
    requested_by: requestedBy,
    payload,
  })
  if (error) throw error
}

Deno.serve(async (req: Request) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: cors })
  if (req.method !== 'POST') return json({ error: 'Method not allowed' }, 405)

  const url = Deno.env.get('SUPABASE_URL') || ''
  const publishableKey = Deno.env.get('SUPABASE_ANON_KEY') || ''
  const serviceKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY') || ''
  if (!url || !publishableKey || !serviceKey) return json({ error: 'Server configuration unavailable' }, 500)

  const authorization = req.headers.get('authorization') || ''
  const userClient = createClient(url, publishableKey, { global: { headers: { Authorization: authorization } } })
  const token = authorization.replace(/^Bearer\s+/i, '')
  const { data: { user }, error: userError } = await userClient.auth.getUser(token)
  if (userError || !user?.email) return json({ error: 'Authentication required' }, 401)

  const admin = createClient(url, serviceKey, { auth: { persistSession: false, autoRefreshToken: false } })
  const { data: consoleUser, error: accessError } = await admin.from('console_users')
    .select('email,access_role,is_active').eq('email', user.email.toLowerCase()).maybeSingle()
  if (accessError || !consoleUser?.is_active) {
    return json({ error: 'This account is not authorized for the security console' }, 403)
  }

  const body = await req.json().catch(() => ({})) as RequestBody

  if (body.action === 'create_enrollment') {
    if (consoleUser.access_role !== 'admin') return json({ error: 'Administrator access is required' }, 403)
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
    if (consoleUser.access_role !== 'admin') return json({ error: 'Administrator access is required' }, 403)
    const { error } = await admin.rpc('revoke_terminal', { p_terminal_id: body.terminalId })
    if (error) return json({ error: 'Could not revoke terminal' }, 500)
    await admin.from('endpoint_audit_log').insert({ actor_user_id: user.id, terminal_id: body.terminalId, action: 'terminal_revoked', details: {} })
    return json({ ok: true })
  }

  if (body.action === 'set_policy_mode' && body.mode) {
    if (consoleUser.access_role !== 'admin') return json({ error: 'Administrator access is required' }, 403)
    if (!['audit', 'enforce'].includes(body.mode)) return json({ error: 'Invalid policy mode' }, 400)

    const now = new Date().toISOString()
    const { error } = await admin.from('endpoint_policies').update({ mode: body.mode, updated_at: now }).eq('is_default', true)
    if (error) return json({ error: 'Could not update endpoint policy mode' }, 500)

    const { data: terminals, error: terminalsError } = await admin.from('terminals')
      .select('terminal_id').eq('enrollment_status', 'active')
    if (terminalsError) return json({ error: 'Could not load managed endpoints' }, 500)

    try {
      for (const terminal of terminals ?? []) await queuePolicySync(admin, terminal.terminal_id, user.id)
    } catch {
      return json({ error: 'Policy changed, but one or more endpoint sync commands could not be queued' }, 500)
    }

    await admin.from('endpoint_audit_log').insert({
      actor_user_id: user.id,
      action: 'policy_mode_changed',
      details: { mode: body.mode === 'enforce' ? 'control' : 'audit' },
    })
    return json({ ok: true, mode: body.mode })
  }

  if (body.action === 'set_software_block_targets' && body.softwareKey) {
    if (consoleUser.access_role !== 'admin') return json({ error: 'Administrator access is required' }, 403)

    const allTerminalIds = [...new Set((body.allTerminalIds ?? []).filter(Boolean))].slice(0, 250)
    const selectedTerminalIds = [...new Set((body.terminalIds ?? []).filter(Boolean))].slice(0, 250)
    if (allTerminalIds.length === 0) return json({ error: 'No eligible endpoints were supplied' }, 400)
    if (selectedTerminalIds.some(id => !allTerminalIds.includes(id))) return json({ error: 'Invalid endpoint selection' }, 400)

    const { data: installedRows, error: installedError } = await admin.from('installed_software')
      .select('terminal_id,software_key,name,publisher,install_location,executable_paths')
      .eq('software_key', body.softwareKey)
      .in('terminal_id', allTerminalIds)
    if (installedError) return json({ error: 'Could not validate software inventory' }, 500)

    const rowsByTerminal = new Map((installedRows ?? []).map(row => [row.terminal_id, row]))
    for (const terminalId of selectedTerminalIds) {
      const row = rowsByTerminal.get(terminalId)
      if (!row) return json({ error: 'The selected software is not installed on one of the selected endpoints' }, 400)
      const paths = Array.isArray(row.executable_paths) ? row.executable_paths : []
      if (!row.install_location && paths.length === 0) {
        return json({ error: `${row.name} on ${terminalId} needs a fresh inventory before it can be blocked safely` }, 400)
      }
    }

    const now = new Date().toISOString()
    for (const terminalId of allTerminalIds) {
      const row = rowsByTerminal.get(terminalId)
      if (!row) continue
      if (selectedTerminalIds.includes(terminalId)) {
        const { error } = await admin.from('software_control_rules').upsert({
          terminal_id: terminalId,
          software_key: row.software_key,
          software_name: row.name,
          publisher: row.publisher,
          install_location: row.install_location,
          executable_paths: Array.isArray(row.executable_paths) ? row.executable_paths : [],
          action: 'block',
          is_active: true,
          created_by: user.id,
          updated_at: now,
        }, { onConflict: 'terminal_id,software_key' })
        if (error) return json({ error: 'Could not save software block rule' }, 500)
      } else {
        const { error } = await admin.from('software_control_rules').delete()
          .eq('terminal_id', terminalId).eq('software_key', body.softwareKey)
        if (error) return json({ error: 'Could not remove software block rule' }, 500)
      }
    }

    try {
      for (const terminalId of allTerminalIds) await queuePolicySync(admin, terminalId, user.id)
    } catch {
      return json({ error: 'Software rule changed, but one or more endpoint sync commands could not be queued' }, 500)
    }

    await admin.from('endpoint_audit_log').insert({
      actor_user_id: user.id,
      action: 'software_block_targets_changed',
      details: { software_key: body.softwareKey, blocked_terminal_ids: selectedTerminalIds, affected_terminal_ids: allTerminalIds },
    })
    return json({ ok: true, blockedTerminalIds: selectedTerminalIds })
  }

  if (body.action === 'request_command' && body.terminalId && body.commandType) {
    if (consoleUser.access_role !== 'admin') return json({ error: 'Administrator access is required' }, 403)
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
