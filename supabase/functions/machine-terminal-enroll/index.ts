import { createClient } from 'npm:@supabase/supabase-js@2.57.4'

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), {
  status,
  headers: { 'content-type': 'application/json; charset=utf-8' },
})

const sha256 = async (value: string) => {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value))
  return Array.from(new Uint8Array(digest)).map(byte => byte.toString(16).padStart(2, '0')).join('')
}

const hmacHex = async (keyText: string, value: string) => {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(keyText),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  )
  const signature = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(value))
  return Array.from(new Uint8Array(signature)).map(byte => byte.toString(16).padStart(2, '0')).join('')
}

type Body = {
  terminalId?: string
  computerName?: string
  machineSecret?: string
  appVersion?: string
  serialNumber?: string
  manufacturer?: string
  model?: string
}

Deno.serve(async (req: Request) => {
  if (req.method !== 'POST') return json({ error: 'Method not allowed' }, 405)

  const url = Deno.env.get('SUPABASE_URL') || ''
  const serviceKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY') || ''
  if (!url || !serviceKey) return json({ error: 'Server configuration unavailable' }, 500)

  let body: Body
  try { body = await req.json() } catch { return json({ error: 'Invalid JSON body' }, 400) }

  const terminalId = (body.terminalId || '').trim().slice(0, 180)
  const computerName = (body.computerName || '').trim().slice(0, 120)
  const machineSecret = (body.machineSecret || '').trim()
  const appVersion = (body.appVersion || '').trim().slice(0, 60)
  const serialNumber = (body.serialNumber || '').trim().slice(0, 160)
  const manufacturer = (body.manufacturer || '').trim().slice(0, 120)
  const model = (body.model || '').trim().slice(0, 160)

  if (!terminalId || !computerName) return json({ error: 'Machine identity is incomplete' }, 400)
  if (machineSecret.length < 48 || machineSecret.length > 256) {
    return json({ error: 'Machine enrollment secret is invalid' }, 400)
  }

  const secretHash = await sha256(machineSecret)
  const admin = createClient(url, serviceKey, { auth: { persistSession: false, autoRefreshToken: false } })
  const clientIp = (req.headers.get('x-forwarded-for') || '').split(',')[0].trim() || null

  const { data: existing, error: existingError } = await admin
    .from('machine_enrollment_requests')
    .select('request_id,status,machine_secret_hash')
    .eq('terminal_id', terminalId)
    .maybeSingle()

  if (existingError) return json({ error: 'Could not check machine enrollment' }, 500)

  let requestId = existing?.request_id as string | undefined
  let status = existing?.status as string | undefined

  if (existing) {
    if (existing.machine_secret_hash !== secretHash) {
      return json({ error: 'This machine identity is already registered with a different credential' }, 409)
    }

    const { error: updateError } = await admin.from('machine_enrollment_requests').update({
      computer_name: computerName,
      app_version: appVersion || null,
      serial_number: serialNumber || null,
      manufacturer: manufacturer || null,
      model: model || null,
      last_seen_at: new Date().toISOString(),
      last_ip: clientIp,
    }).eq('request_id', existing.request_id)
    if (updateError) return json({ error: 'Could not refresh machine enrollment' }, 500)
  } else {
    const { data: created, error: createError } = await admin.from('machine_enrollment_requests').insert({
      terminal_id: terminalId,
      computer_name: computerName,
      machine_secret_hash: secretHash,
      app_version: appVersion || null,
      serial_number: serialNumber || null,
      manufacturer: manufacturer || null,
      model: model || null,
      status: 'pending',
      last_ip: clientIp,
    }).select('request_id,status').single()

    if (createError || !created) return json({ error: 'Could not register this machine' }, 500)
    requestId = created.request_id
    status = created.status
  }

  if (status === 'denied') {
    return json({ status: 'denied', requestId, error: 'This machine enrollment was denied by CRECCOM IT.' }, 403)
  }

  if (status === 'pending') {
    return json({
      status: 'pending',
      requestId,
      message: 'Machine registered. Waiting for CRECCOM IT approval.',
    }, 202)
  }

  if (!requestId || !['approved', 'completed'].includes(status || '')) {
    return json({ error: 'Machine enrollment state is invalid' }, 409)
  }

  const terminalToken = 'csc_' + await hmacHex(serviceKey, `smart-console-machine|${terminalId}|${machineSecret}`)
  const tokenHash = await sha256(terminalToken)

  const { data: completed, error: completeError } = await admin.rpc('complete_machine_enrollment', {
    p_request_id: requestId,
    p_terminal_id: terminalId,
    p_computer_name: computerName,
    p_app_version: appVersion,
    p_serial_number: serialNumber,
    p_manufacturer: manufacturer,
    p_model: model,
    p_token_hash: tokenHash,
    p_token_prefix: terminalToken.slice(0, 12),
  })

  if (completeError || !completed) return json({ error: 'Could not complete machine enrollment' }, 500)

  return json({
    status: 'enrolled',
    requestId,
    terminalToken,
    ingestUrl: 'https://pgbipustotixwahmotvu.supabase.co/functions/v1/usb-audit-ingest',
    webConsoleUrl: 'https://secure.creccommw.org',
  })
})
