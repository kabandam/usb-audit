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
const CONTROL_AGENT_MIN_VERSION = '1.2.47'
const DEPLOYMENT_AGENT_MIN_VERSION = '1.2.95'
const PACKAGE_VERIFICATION_AGENT_MIN_VERSION = '1.2.98'

const versionAtLeast = (value: string | null | undefined, minimum: string) => {
  const left = (value || '0').split('.').map(part => Number.parseInt(part, 10) || 0)
  const right = minimum.split('.').map(part => Number.parseInt(part, 10) || 0)
  const length = Math.max(left.length, right.length)
  for (let index = 0; index < length; index++) {
    const a = left[index] || 0
    const b = right[index] || 0
    if (a > b) return true
    if (a < b) return false
  }
  return true
}

const isValidHttpsUrl = (value: string) => {
  try {
    const parsed = new URL(value)
    return parsed.protocol === 'https:' && Boolean(parsed.hostname)
  } catch {
    return false
  }
}

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
  groupId?: string
  groupIds?: string[]
  name?: string
  description?: string
  appId?: string
  appIds?: string[]
  version?: string
  publisher?: string
  installerType?: 'msi' | 'exe'
  packageType?: 'msi' | 'exe' | 'zip'
  packageUrl?: string
  packageDownloadUrl?: string
  packageDownloadUrls?: Record<string, string>
  storageProvider?: 'https' | 'onedrive'
  storageDriveId?: string
  storageItemId?: string
  storageWebUrl?: string
  storageFileName?: string
  fileSizeBytes?: number
  installerEntry?: string
  metadataConfidence?: 'detected' | 'confirm' | 'manual'
  sha256?: string
  installArgs?: string
  successCodes?: number[]
  notes?: string
  batchName?: string
  taskId?: string
  requestId?: string
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

async function queueApplicationVerification(admin: AdminClient, appId: string, requestedBy: string, packageDownloadUrl?: string) {
  const { data: app, error: appError } = await admin.from('deployment_apps')
    .select('app_id,name,version,publisher,installer_type,package_type,package_url,storage_provider,storage_drive_id,storage_item_id,storage_web_url,storage_file_name,file_size_bytes,installer_entry,sha256,is_active')
    .eq('app_id', appId).maybeSingle()
  if (appError || !app || !app.is_active) throw new Error('Application package is unavailable for verification')

  const cutoff = new Date(Date.now() - 10 * 60 * 1000).toISOString()
  const { data: terminals, error: terminalError } = await admin.from('terminals')
    .select('terminal_id,computer_name,app_version,last_seen_at,enrollment_status')
    .eq('enrollment_status', 'active')
    .gte('last_seen_at', cutoff)
    .order('last_seen_at', { ascending: false })
    .limit(25)
  if (terminalError) throw new Error('Could not locate an online verification endpoint')

  const terminal = (terminals ?? []).find(item =>
    versionAtLeast(item.app_version, PACKAGE_VERIFICATION_AGENT_MIN_VERSION)
  )
  if (!terminal) {
    await admin.from('deployment_apps').update({
      verification_status: 'pending',
      verification_message: `Waiting for an online Smart Console ${PACKAGE_VERIFICATION_AGENT_MIN_VERSION}+ endpoint to verify this package.`,
      last_verification_requested_at: new Date().toISOString(),
    }).eq('app_id', appId)
    return { queued: false, reason: 'waiting_for_endpoint' }
  }

  const now = new Date().toISOString()
  const payload = {
    deploymentTaskId: crypto.randomUUID(),
    deploymentBatchId: crypto.randomUUID(),
    appId: app.app_id,
    appName: app.name,
    appVersion: app.version,
    publisher: app.publisher,
    installerType: app.installer_type,
    packageType: app.package_type || app.installer_type,
    packageUrl: packageDownloadUrl && isValidHttpsUrl(packageDownloadUrl) ? packageDownloadUrl : app.package_url,
    storageProvider: packageDownloadUrl && isValidHttpsUrl(packageDownloadUrl) ? 'https' : (app.storage_provider || 'https'),
    storageDriveId: app.storage_drive_id,
    storageItemId: app.storage_item_id,
    storageWebUrl: app.storage_web_url,
    storageFileName: app.storage_file_name,
    fileSizeBytes: app.file_size_bytes,
    installerEntry: app.installer_entry,
    sha256: app.sha256,
    installArgs: '',
    successCodes: [0],
    sequence: 0,
    attempt: 1,
  }

  const { data: command, error: commandError } = await admin.from('endpoint_commands').insert({
    terminal_id: terminal.terminal_id,
    command_type: 'verify_application_package',
    requested_by: requestedBy,
    payload,
  }).select('command_id').single()
  if (commandError || !command) throw new Error('Could not queue application package verification')

  await admin.from('deployment_apps').update({
    verification_status: 'queued',
    verification_message: `Verification queued on ${terminal.computer_name || terminal.terminal_id}.`,
    last_verification_requested_at: now,
  }).eq('app_id', appId)

  await admin.from('endpoint_audit_log').insert({
    actor_user_id: requestedBy,
    terminal_id: terminal.terminal_id,
    action: 'application_package_verification_requested',
    details: { app_id: appId, command_id: command.command_id },
  })

  return { queued: true, terminalId: terminal.terminal_id, commandId: command.command_id }
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
    return json({ error: 'This account is not authorized for Smart Console' }, 403)
  }

  const body = await req.json().catch(() => ({})) as RequestBody

  if (body.action === 'approve_machine_enrollment' && body.requestId) {
    if (consoleUser.access_role !== 'admin') return json({ error: 'Administrator access is required' }, 403)

    const now = new Date().toISOString()
    const { data: request, error } = await admin.from('machine_enrollment_requests')
      .update({
        status: 'approved',
        approved_at: now,
        approved_by: user.id,
      })
      .eq('request_id', body.requestId)
      .eq('status', 'pending')
      .select('request_id,terminal_id,computer_name')
      .maybeSingle()

    if (error) return json({ error: 'Could not approve machine enrollment' }, 500)
    if (!request) return json({ error: 'This machine enrollment is no longer pending' }, 409)

    await admin.from('endpoint_audit_log').insert({
      actor_user_id: user.id,
      terminal_id: request.terminal_id,
      action: 'machine_enrollment_approved',
      details: { request_id: request.request_id, computer_name: request.computer_name },
    })

    return json({ ok: true })
  }

  if (body.action === 'deny_machine_enrollment' && body.requestId) {
    if (consoleUser.access_role !== 'admin') return json({ error: 'Administrator access is required' }, 403)

    const now = new Date().toISOString()
    const { data: request, error } = await admin.from('machine_enrollment_requests')
      .update({
        status: 'denied',
        approved_at: now,
        approved_by: user.id,
      })
      .eq('request_id', body.requestId)
      .eq('status', 'pending')
      .select('request_id,terminal_id,computer_name')
      .maybeSingle()

    if (error) return json({ error: 'Could not deny machine enrollment' }, 500)
    if (!request) return json({ error: 'This machine enrollment is no longer pending' }, 409)

    await admin.from('endpoint_audit_log').insert({
      actor_user_id: user.id,
      terminal_id: request.terminal_id,
      action: 'machine_enrollment_denied',
      details: { request_id: request.request_id, computer_name: request.computer_name },
    })

    return json({ ok: true })
  }

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

  if (body.action === 'save_endpoint_group') {
    if (consoleUser.access_role !== 'admin') return json({ error: 'Administrator access is required' }, 403)

    const name = (body.name || '').trim().slice(0, 80)
    const description = (body.description || '').trim().slice(0, 300)
    const terminalIds = [...new Set((body.terminalIds ?? []).filter(Boolean))].slice(0, 250)
    if (!name) return json({ error: 'Group name is required' }, 400)

    if (terminalIds.length > 0) {
      const { data: validTerminals, error } = await admin.from('terminals')
        .select('terminal_id').in('terminal_id', terminalIds).eq('enrollment_status', 'active')
      if (error) return json({ error: 'Could not validate group endpoints' }, 500)
      if ((validTerminals ?? []).length !== terminalIds.length) return json({ error: 'One or more selected endpoints are unavailable or revoked' }, 400)
    }

    let groupId = body.groupId
    if (groupId) {
      const { data, error } = await admin.from('endpoint_groups').update({
        name, description: description || null, updated_at: new Date().toISOString(),
      }).eq('group_id', groupId).select('group_id').maybeSingle()
      if (error || !data) return json({ error: error?.code === '23505' ? 'A group with this name already exists' : 'Could not update endpoint group' }, 500)
    } else {
      const { data, error } = await admin.from('endpoint_groups').insert({
        name, description: description || null, created_by: user.id,
      }).select('group_id').single()
      if (error || !data) return json({ error: error?.code === '23505' ? 'A group with this name already exists' : 'Could not create endpoint group' }, 500)
      groupId = data.group_id
    }

    const { error: deleteError } = await admin.from('endpoint_group_members').delete().eq('group_id', groupId)
    if (deleteError) return json({ error: 'Group saved, but existing membership could not be refreshed' }, 500)

    if (terminalIds.length > 0) {
      const { error: memberError } = await admin.from('endpoint_group_members').insert(
        terminalIds.map(terminalId => ({ group_id: groupId, terminal_id: terminalId }))
      )
      if (memberError) return json({ error: 'Group saved, but selected endpoints could not be added' }, 500)
    }

    await admin.from('endpoint_audit_log').insert({
      actor_user_id: user.id,
      action: 'endpoint_group_saved',
      details: { group_id: groupId, name, terminal_count: terminalIds.length },
    })
    return json({ ok: true, groupId })
  }

  if (body.action === 'save_deployment_app') {
    if (consoleUser.access_role !== 'admin') return json({ error: 'Administrator access is required' }, 403)

    const name = (body.name || '').trim().slice(0, 120)
    const version = (body.version || '').trim().slice(0, 60)
    const publisher = (body.publisher || '').trim().slice(0, 120)
    const installerType = body.installerType
    const packageType = body.packageType || installerType
    const storageProvider = body.storageProvider || 'https'
    const packageUrl = (body.packageUrl || '').trim()
    const storageDriveId = (body.storageDriveId || '').trim().slice(0, 512)
    const storageItemId = (body.storageItemId || '').trim().slice(0, 512)
    const storageWebUrl = (body.storageWebUrl || '').trim().slice(0, 2048)
    const storageFileName = (body.storageFileName || '').trim().slice(0, 260)
    const installerEntry = (body.installerEntry || '').trim().slice(0, 600)
    const fileSizeBytes = Number.isFinite(body.fileSizeBytes) ? Math.max(0, Math.floor(body.fileSizeBytes || 0)) : null
    const metadataConfidence = body.metadataConfidence || 'manual'
    const digest = (body.sha256 || '').trim().toLowerCase()
    const installArgs = (body.installArgs || '').trim().slice(0, 500)
    const installTimeoutMinutes = Number.isFinite(body.installTimeoutMinutes)
      ? Math.max(5, Math.min(60, Math.floor(body.installTimeoutMinutes)))
      : 15
    const notes = (body.notes || '').trim().slice(0, 500)
    const successCodes = [...new Set((body.successCodes ?? [0, 1641, 3010]).filter(code => Number.isInteger(code)))].slice(0, 20)

    if (!name || !version) return json({ error: 'Application name and version are required' }, 400)
    if (!['msi', 'exe'].includes(installerType || '')) return json({ error: 'Installer type must be MSI or EXE' }, 400)
    if (!['msi', 'exe', 'zip'].includes(packageType || '')) return json({ error: 'Package type must be MSI, EXE or ZIP' }, 400)
    if (!['https', 'onedrive'].includes(storageProvider)) return json({ error: 'Unsupported package storage provider' }, 400)
    if (storageProvider === 'https' && !isValidHttpsUrl(packageUrl)) return json({ error: 'Package URL must be a valid HTTPS address' }, 400)
    if (storageProvider === 'onedrive' && (!storageDriveId || !storageItemId)) return json({ error: 'OneDrive package identifiers are required' }, 400)
    if (packageType === 'zip' && !installerEntry) return json({ error: 'ZIP packages need an installer entry' }, 400)
    if (!['detected', 'confirm', 'manual'].includes(metadataConfidence)) return json({ error: 'Invalid package metadata status' }, 400)
    if (digest && !/^[0-9a-f]{64}$/.test(digest)) return json({ error: 'SHA-256 must be a valid 64-character digest when provided' }, 400)
    if (successCodes.length === 0) return json({ error: 'At least one successful installer exit code is required' }, 400)

    const row = {
      name, version, publisher: publisher || null, installer_type: installerType,
      package_type: packageType, package_url: storageProvider === 'https' ? packageUrl : null,
      storage_provider: storageProvider,
      storage_drive_id: storageProvider === 'onedrive' ? storageDriveId : null,
      storage_item_id: storageProvider === 'onedrive' ? storageItemId : null,
      storage_web_url: storageProvider === 'onedrive' ? (storageWebUrl || null) : null,
      storage_file_name: storageFileName || null,
      file_size_bytes: fileSizeBytes,
      installer_entry: packageType === 'zip' ? installerEntry : null,
      metadata_confidence: metadataConfidence,
      sha256: digest || null, install_args: installArgs,
      install_timeout_minutes: installTimeoutMinutes,
      success_codes: successCodes, notes: notes || null, is_active: true,
      updated_at: new Date().toISOString(),
    }

    let appId = body.appId
    if (appId) {
      const { data, error } = await admin.from('deployment_apps').update(row).eq('app_id', appId).select('app_id').maybeSingle()
      if (error || !data) return json({ error: error?.code === '23505' ? 'This application version already exists' : 'Could not update application' }, 500)
    } else {
      const { data: existing } = await admin.from('deployment_apps')
        .select('app_id').eq('name', name).eq('version', version).maybeSingle()

      if (existing?.app_id) {
        const { data, error } = await admin.from('deployment_apps')
          .update(row).eq('app_id', existing.app_id).select('app_id').single()
        if (error || !data) return json({ error: 'Could not refresh existing application catalog entry' }, 500)
        appId = data.app_id
      } else {
        const { data, error } = await admin.from('deployment_apps')
          .insert({ ...row, created_by: user.id }).select('app_id').single()
        if (error || !data) return json({ error: 'Could not add application' }, 500)
        appId = data.app_id
      }
    }

    await admin.from('endpoint_audit_log').insert({
      actor_user_id: user.id,
      action: 'deployment_app_saved',
      details: { app_id: appId, name, version, publisher: publisher || null, installer_type: installerType, package_type: packageType, storage_provider: storageProvider },
    })

    let verification: unknown = null
    try {
      verification = await queueApplicationVerification(admin, appId!, user.id, body.packageDownloadUrl)
    } catch (verificationError) {
      await admin.from('deployment_apps').update({
        verification_status: 'failed',
        verification_message: verificationError instanceof Error ? verificationError.message : 'Could not queue package verification.',
      }).eq('app_id', appId!)
    }
    return json({ ok: true, appId, verification })
  }

  if (body.action === 'verify_deployment_app' && body.appId) {
    if (consoleUser.access_role !== 'admin') return json({ error: 'Administrator access is required' }, 403)
    try {
      const verification = await queueApplicationVerification(admin, body.appId, user.id, body.packageDownloadUrl)
      return json({ ok: true, verification })
    } catch (error) {
      return json({ error: error instanceof Error ? error.message : 'Could not queue application verification' }, 500)
    }
  }

  if (body.action === 'create_app_deployment') {
    if (consoleUser.access_role !== 'admin') return json({ error: 'Administrator access is required' }, 403)

    const appIds = [...new Set((body.appIds ?? []).filter(Boolean))].slice(0, 20)
    const packageDownloadUrls = body.packageDownloadUrls ?? {}
    const explicitTerminalIds = [...new Set((body.terminalIds ?? []).filter(Boolean))].slice(0, 250)
    const groupIds = [...new Set((body.groupIds ?? []).filter(Boolean))].slice(0, 50)
    if (appIds.length === 0) return json({ error: 'Select at least one application' }, 400)

    const resolvedTerminalIds = new Set(explicitTerminalIds)
    if (groupIds.length > 0) {
      const { data: groupMembers, error } = await admin.from('endpoint_group_members')
        .select('terminal_id').in('group_id', groupIds)
      if (error) return json({ error: 'Could not resolve endpoint groups' }, 500)
      for (const member of groupMembers ?? []) resolvedTerminalIds.add(member.terminal_id)
    }

    const terminalIds = [...resolvedTerminalIds].slice(0, 250)
    if (terminalIds.length === 0) return json({ error: 'Select at least one endpoint or endpoint group' }, 400)
    if (appIds.length * terminalIds.length > 1000) return json({ error: 'A deployment batch is limited to 1,000 application/endpoint tasks' }, 400)

    const { data: terminals, error: terminalError } = await admin.from('terminals')
      .select('terminal_id,computer_name,app_version,enrollment_status').in('terminal_id', terminalIds)
    if (terminalError) return json({ error: 'Could not validate deployment endpoints' }, 500)
    if ((terminals ?? []).length !== terminalIds.length) return json({ error: 'One or more selected endpoints no longer exist' }, 400)

    const unavailable = (terminals ?? []).filter(terminal => terminal.enrollment_status !== 'active')
    if (unavailable.length > 0) return json({ error: `Revoked endpoints cannot receive deployments: ${unavailable.map(t => t.computer_name).join(', ')}` }, 409)

    const outdated = (terminals ?? []).filter(terminal => !versionAtLeast(terminal.app_version, DEPLOYMENT_AGENT_MIN_VERSION))
    if (outdated.length > 0) {
      return json({
        error: `App Deployment requires Smart Console Agent ${DEPLOYMENT_AGENT_MIN_VERSION} or newer. Waiting for update on: ${outdated.map(t => t.computer_name || t.terminal_id).join(', ')}`,
      }, 409)
    }

    const { data: apps, error: appError } = await admin.from('deployment_apps')
      .select('app_id,name,version,publisher,installer_type,package_type,package_url,storage_provider,storage_drive_id,storage_item_id,storage_web_url,storage_file_name,file_size_bytes,installer_entry,sha256,install_args,install_timeout_minutes,success_codes,is_active,metadata_confidence,verification_status')
      .in('app_id', appIds)
    if (appError) return json({ error: 'Could not load selected applications' }, 500)
    if ((apps ?? []).length !== appIds.length || (apps ?? []).some(app => !app.is_active)) return json({ error: 'One or more selected applications are unavailable' }, 400)

    const silentMissingApps = (apps ?? []).filter(app =>
      app.installer_type === 'exe' && !(app.install_args || '').trim()
    )
    if (silentMissingApps.length > 0) {
      return json({
        error: `Unattended EXE deployment requires silent install arguments: ${silentMissingApps.map(app => app.name).join(', ')}`,
      }, 409)
    }

    const unverifiedApps = (apps ?? []).filter(app =>
      !/^[0-9A-Fa-f]{64}$/.test(app.sha256 || '') || app.verification_status !== 'verified'
    )
    if (unverifiedApps.length > 0) {
      return json({
        error: `SHA-256 and Microsoft Defender verification must complete before deployment: ${unverifiedApps.map(app => app.name).join(', ')}`,
      }, 409)
    }

    const appsById = new Map((apps ?? []).map(app => [app.app_id, app]))
    const orderedApps = appIds.map(id => appsById.get(id)).filter(Boolean)
    const batchName = (body.batchName || '').trim().slice(0, 120)
      || `App deployment ${new Date().toISOString().slice(0, 16).replace('T', ' ')}`

    const { data: batch, error: batchError } = await admin.from('deployment_batches').insert({
      name: batchName,
      requested_by: user.id,
      app_count: appIds.length,
      terminal_count: terminalIds.length,
      status: 'queued',
    }).select('batch_id').single()
    if (batchError || !batch) return json({ error: 'Could not create deployment batch' }, 500)

    const createdCommandIds: string[] = []
    try {
      for (const terminalId of terminalIds) {
        for (let index = 0; index < orderedApps.length; index++) {
          const app = orderedApps[index]!
          const taskId = crypto.randomUUID()
          const payload = {
            deploymentTaskId: taskId,
            deploymentBatchId: batch.batch_id,
            appId: app.app_id,
            appName: app.name,
            appVersion: app.version,
            publisher: app.publisher,
            installerType: app.installer_type,
            packageType: app.package_type || app.installer_type,
            packageUrl: packageDownloadUrls[app.app_id] && isValidHttpsUrl(packageDownloadUrls[app.app_id]) ? packageDownloadUrls[app.app_id] : app.package_url,
            storageProvider: packageDownloadUrls[app.app_id] && isValidHttpsUrl(packageDownloadUrls[app.app_id]) ? 'https' : (app.storage_provider || 'https'),
            storageDriveId: app.storage_drive_id,
            storageItemId: app.storage_item_id,
            storageWebUrl: app.storage_web_url,
            storageFileName: app.storage_file_name,
            fileSizeBytes: app.file_size_bytes,
            installerEntry: app.installer_entry,
            sha256: app.sha256,
            installArgs: app.install_args || '',
            installTimeoutMinutes: Number(app.install_timeout_minutes || 15),
            successCodes: Array.isArray(app.success_codes) ? app.success_codes : [0, 1641, 3010],
            sequence: index + 1,
            attempt: 1,
          }

          const { data: command, error: commandError } = await admin.from('endpoint_commands').insert({
            terminal_id: terminalId,
            command_type: 'deploy_application',
            requested_by: user.id,
            payload,
          }).select('command_id').single()
          if (commandError || !command) throw commandError || new Error('Could not create endpoint deployment command')
          createdCommandIds.push(command.command_id)

          const { error: taskError } = await admin.from('deployment_tasks').insert({
            task_id: taskId,
            batch_id: batch.batch_id,
            app_id: app.app_id,
            terminal_id: terminalId,
            sequence_no: index + 1,
            command_id: command.command_id,
            status: 'pending',
          })
          if (taskError) throw taskError
        }
      }
    } catch {
      if (createdCommandIds.length > 0) {
        await admin.from('endpoint_commands').update({
          status: 'cancelled', completed_at: new Date().toISOString(),
          result: { message: 'Deployment batch creation did not complete.' },
        }).in('command_id', createdCommandIds)
      }
      await admin.from('deployment_batches').update({ status: 'failed' }).eq('batch_id', batch.batch_id)
      return json({ error: 'Deployment batch could not be fully queued. No remaining tasks will be delivered.' }, 500)
    }

    await admin.from('endpoint_audit_log').insert({
      actor_user_id: user.id,
      action: 'application_deployment_created',
      details: {
        batch_id: batch.batch_id, name: batchName,
        app_ids: appIds, terminal_ids: terminalIds, group_ids: groupIds,
        task_count: appIds.length * terminalIds.length,
      },
    })

    return json({
      ok: true,
      batchId: batch.batch_id,
      taskCount: appIds.length * terminalIds.length,
      terminalCount: terminalIds.length,
      appCount: appIds.length,
    })
  }

  if (body.action === 'retry_deployment_task' && body.taskId) {
    if (consoleUser.access_role !== 'admin') return json({ error: 'Administrator access is required' }, 403)

    const { data: task, error: taskError } = await admin.from('deployment_tasks')
      .select('task_id,batch_id,app_id,terminal_id,command_id,status,attempt_count,last_progress_at')
      .eq('task_id', body.taskId).maybeSingle()
    if (taskError || !task) return json({ error: 'Deployment task was not found' }, 404)

    const lastProgress = task.last_progress_at ? new Date(task.last_progress_at).getTime() : 0
    const stale = Date.now() - lastProgress >= 5 * 60 * 1000
    if (!['failed', 'cancelled'].includes(task.status) && !stale) {
      return json({ error: 'This deployment is still reporting progress. Force retry becomes available after 5 minutes without progress.' }, 409)
    }

    const { data: terminal, error: terminalError } = await admin.from('terminals')
      .select('terminal_id,computer_name,app_version,enrollment_status')
      .eq('terminal_id', task.terminal_id).maybeSingle()
    if (terminalError || !terminal || terminal.enrollment_status !== 'active') {
      return json({ error: 'The target endpoint is unavailable or revoked' }, 409)
    }
    if (!versionAtLeast(terminal.app_version, DEPLOYMENT_AGENT_MIN_VERSION)) {
      return json({ error: `Force retry requires Smart Console Agent ${DEPLOYMENT_AGENT_MIN_VERSION} or newer on ${terminal.computer_name || terminal.terminal_id}` }, 409)
    }

    const { data: app, error: appError } = await admin.from('deployment_apps')
      .select('app_id,name,version,publisher,installer_type,package_type,package_url,storage_provider,storage_drive_id,storage_item_id,storage_web_url,storage_file_name,file_size_bytes,installer_entry,sha256,install_args,install_timeout_minutes,success_codes,is_active')
      .eq('app_id', task.app_id).maybeSingle()
    if (appError || !app || !app.is_active) return json({ error: 'The deployment application is unavailable' }, 409)
    if (!/^[0-9A-Fa-f]{64}$/.test(app.sha256 || '')) return json({ error: 'The package SHA-256 must be verified before retrying deployment' }, 409)

    if (task.command_id) {
      await admin.from('endpoint_commands').update({
        status: 'cancelled',
        completed_at: new Date().toISOString(),
        result: { message: 'Superseded by a forced deployment retry.' },
      }).eq('command_id', task.command_id).in('status', ['pending', 'acknowledged'])
    }

    const nextAttempt = Math.max(1, Number(task.attempt_count || 1) + 1)
    const payload = {
      deploymentTaskId: task.task_id,
      deploymentBatchId: task.batch_id,
      appId: app.app_id,
      appName: app.name,
      appVersion: app.version,
      publisher: app.publisher,
      installerType: app.installer_type,
      packageType: app.package_type || app.installer_type,
      packageUrl: body.packageDownloadUrl && isValidHttpsUrl(body.packageDownloadUrl) ? body.packageDownloadUrl : app.package_url,
      storageProvider: body.packageDownloadUrl && isValidHttpsUrl(body.packageDownloadUrl) ? 'https' : (app.storage_provider || 'https'),
      storageDriveId: app.storage_drive_id,
      storageItemId: app.storage_item_id,
      storageWebUrl: app.storage_web_url,
      storageFileName: app.storage_file_name,
      fileSizeBytes: app.file_size_bytes,
      installerEntry: app.installer_entry,
      sha256: app.sha256,
      installArgs: app.install_args || '',
      installTimeoutMinutes: Number(app.install_timeout_minutes || 15),
      successCodes: Array.isArray(app.success_codes) ? app.success_codes : [0, 1641, 3010],
      sequence: 1,
      attempt: nextAttempt,
    }

    const { data: command, error: commandError } = await admin.from('endpoint_commands').insert({
      terminal_id: task.terminal_id,
      command_type: 'deploy_application',
      requested_by: user.id,
      payload,
    }).select('command_id').single()
    if (commandError || !command) return json({ error: 'Could not queue forced deployment retry' }, 500)

    const retryAt = new Date().toISOString()
    const { error: updateError } = await admin.from('deployment_tasks').update({
      command_id: command.command_id,
      status: 'pending',
      message: null,
      completed_at: null,
      progress_percent: 0,
      progress_stage: 'retry_queued',
      progress_message: `Forced retry queued by IT — attempt ${nextAttempt}`,
      attempt_count: nextAttempt,
      last_progress_at: retryAt,
      started_at: null,
      defender_scan_status: null,
    }).eq('task_id', task.task_id)
    if (updateError) return json({ error: 'Retry command was created but the deployment task could not be reset' }, 500)

    await admin.from('deployment_batches').update({ status: 'in_progress' }).eq('batch_id', task.batch_id)
    await admin.from('endpoint_audit_log').insert({
      actor_user_id: user.id,
      terminal_id: task.terminal_id,
      action: 'application_deployment_force_retry',
      details: { task_id: task.task_id, batch_id: task.batch_id, app_id: task.app_id, attempt: nextAttempt },
    })

    return json({ ok: true, commandId: command.command_id, attempt: nextAttempt })
  }

  if (body.action === 'set_policy_mode' && body.mode) {
    if (consoleUser.access_role !== 'admin') return json({ error: 'Administrator access is required' }, 403)
    if (!['audit', 'enforce'].includes(body.mode)) return json({ error: 'Invalid policy mode' }, 400)

    const { data: terminals, error: terminalsError } = await admin.from('terminals')
      .select('terminal_id,computer_name,app_version').eq('enrollment_status', 'active')
    if (terminalsError) return json({ error: 'Could not load managed endpoints' }, 500)

    if (body.mode === 'enforce') {
      const outdated = (terminals ?? []).filter(terminal => !versionAtLeast(terminal.app_version, CONTROL_AGENT_MIN_VERSION))
      if (outdated.length > 0) {
        return json({
          error: `Control mode requires Smart Console Agent ${CONTROL_AGENT_MIN_VERSION} or newer. Waiting for update on: ${outdated.map(item => item.computer_name || item.terminal_id).join(', ')}`,
        }, 409)
      }
    }

    const now = new Date().toISOString()
    const { error } = await admin.from('endpoint_policies').update({ mode: body.mode, updated_at: now }).eq('is_default', true)
    if (error) return json({ error: 'Could not update endpoint policy mode' }, 500)

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
