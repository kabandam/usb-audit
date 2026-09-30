import { createClient } from 'npm:@supabase/supabase-js@2.57.4'

type ConnectedDevice = {
  deviceKey?: string
  driveLetter?: string
  deviceName?: string
  deviceSerial?: string | null
  volumeLabel?: string | null
  fileSystem?: string | null
  totalSizeBytes?: number
  availableFreeSpaceBytes?: number
  connectedAt?: string
}

type InstalledSoftware = {
  name?: string
  version?: string | null
  publisher?: string | null
  installLocation?: string | null
  executablePaths?: string[]
}

type NetworkSnapshot = {
  networkName?: string | null
  connectionType?: string | null
  adapterName?: string | null
  localIp?: string | null
  macAddress?: string | null
  gatewayIp?: string | null
  dnsServers?: string[]
  linkSpeedMbps?: number | null
  observedAt?: string
}

type EndpointLocationSnapshot = {
  enabled?: boolean
  status?: string
  latitude?: number | null
  longitude?: number | null
  accuracyMeters?: number | null
  source?: string | null
  capturedAt?: string | null
}

type EndpointSnapshot = {
  osName?: string | null
  osVersion?: string | null
  manufacturer?: string | null
  model?: string | null
  serialNumber?: string | null
  totalMemoryBytes?: number | null
  processorName?: string | null
  defenderStatus?: string | null
  firewallEnabled?: boolean | null
  capturedAt?: string
  installedSoftware?: InstalledSoftware[]
}

type AuditEvent = Record<string, unknown> & {
  eventId?: string
  timestamp?: string
  kind?: string
}

type CommandResult = {
  commandId?: string
  status?: 'completed' | 'failed'
  message?: string | null
  appId?: string | null
  packageSha256?: string | null
  defenderScanStatus?: string | null
}

type DeploymentProgress = {
  commandId?: string
  deploymentTaskId?: string
  progressPercent?: number
  stage?: string
  message?: string | null
  attempt?: number
  defenderScanStatus?: string | null
  updatedAt?: string
}

type AgentUpdateSnapshot = {
  lastCheckedAt?: string | null
  currentVersion?: string | null
  latestVersion?: string | null
  state?: string | null
  message?: string | null
}

type Payload = {
  terminal?: {
    terminalId?: string
    computerName?: string
    windowsUser?: string
    appVersion?: string
    timestamp?: string
    connectedDevices?: ConnectedDevice[]
    endpoint?: EndpointSnapshot
    network?: NetworkSnapshot
    location?: EndpointLocationSnapshot
    managedUpdate?: AgentUpdateSnapshot
  }
  events?: AuditEvent[]
  commandResults?: CommandResult[]
  deploymentProgress?: DeploymentProgress[]
}

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), {
  status,
  headers: { 'content-type': 'application/json; charset=utf-8' },
})

const sha256 = async (value: string) => {
  const data = new TextEncoder().encode(value)
  const digest = await crypto.subtle.digest('SHA-256', data)
  return Array.from(new Uint8Array(digest)).map(byte => byte.toString(16).padStart(2, '0')).join('')
}

const randomToken = () => {
  const bytes = crypto.getRandomValues(new Uint8Array(32))
  return `csc_${Array.from(bytes).map(byte => byte.toString(16).padStart(2, '0')).join('')}`
}

const softwareKey = async (software: InstalledSoftware) =>
  sha256(`${software.name ?? ''}|${software.version ?? ''}|${software.publisher ?? ''}`)

async function refreshDeploymentBatch(admin: ReturnType<typeof createClient>, batchId: string) {
  const { data: tasks, error } = await admin.from('deployment_tasks')
    .select('status').eq('batch_id', batchId)
  if (error || !tasks || tasks.length === 0) return

  const statuses = tasks.map(task => task.status)
  const finished = statuses.every(status => ['completed', 'failed', 'cancelled'].includes(status))
  let nextStatus = statuses.some(status => ['acknowledged', 'completed', 'failed'].includes(status)) ? 'in_progress' : 'queued'

  if (finished) {
    const completed = statuses.filter(status => status === 'completed').length
    const failed = statuses.filter(status => status === 'failed').length
    if (completed === statuses.length) nextStatus = 'completed'
    else if (failed === statuses.length) nextStatus = 'failed'
    else nextStatus = 'partial'
  }

  await admin.from('deployment_batches').update({ status: nextStatus }).eq('batch_id', batchId)
}

Deno.serve(async (req: Request) => {
  if (req.method !== 'POST') return json({ error: 'Method not allowed' }, 405)

  const authorization = req.headers.get('authorization') ?? ''
  const token = authorization.startsWith('Bearer ') ? authorization.slice(7).trim() : ''
  const terminalHeader = req.headers.get('x-usbaudit-terminal')?.trim() ?? ''
  if (!token || !terminalHeader) return json({ error: 'Terminal authentication required' }, 401)

  let payload: Payload
  try { payload = await req.json() } catch { return json({ error: 'Invalid JSON body' }, 400) }

  const terminal = payload.terminal
  if (!terminal?.terminalId || terminal.terminalId !== terminalHeader) {
    return json({ error: 'Terminal identity mismatch' }, 401)
  }

  const url = Deno.env.get('SUPABASE_URL')
  const serviceKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')
  if (!url || !serviceKey) return json({ error: 'Server configuration unavailable' }, 500)

  const admin = createClient(url, serviceKey, { auth: { persistSession: false, autoRefreshToken: false } })
  const tokenHash = await sha256(token)

  const { data: tokenId, error: tokenError } = await admin.rpc('verify_terminal_token', {
    p_terminal_id: terminalHeader, p_token_hash: tokenHash,
  })
  if (tokenError) return json({ error: 'Could not verify terminal' }, 500)

  let issuedToken: string | undefined
  if (!tokenId) {
    issuedToken = randomToken()
    const issuedHash = await sha256(issuedToken)
    const { data: claimed, error: claimError } = await admin.rpc('claim_terminal_enrollment', {
      p_code_hash: tokenHash,
      p_token_hash: issuedHash,
      p_token_prefix: issuedToken.slice(0, 12),
      p_terminal_id: terminalHeader,
      p_computer_name: terminal.computerName || terminalHeader,
      p_windows_user: terminal.windowsUser || '',
      p_app_version: terminal.appVersion || '',
    })
    if (claimError) return json({ error: 'Could not complete terminal enrollment' }, 500)
    if (!claimed) return json({ error: 'Invalid, expired, or revoked terminal credential' }, 401)
  }

  const now = new Date().toISOString()
  const endpoint = terminal.endpoint
  const { error: terminalError } = await admin.from('terminals').upsert({
    terminal_id: terminalHeader,
    computer_name: terminal.computerName || terminalHeader,
    windows_user: terminal.windowsUser || null,
    app_version: terminal.appVersion || null,
    last_seen_at: now,
    last_ip: (req.headers.get('x-forwarded-for') || '').split(',')[0].trim() || null,
    last_error: null,
    os_name: endpoint?.osName ?? null,
    os_version: endpoint?.osVersion ?? null,
    manufacturer: endpoint?.manufacturer ?? null,
    model: endpoint?.model ?? null,
    serial_number: endpoint?.serialNumber ?? null,
    total_memory_bytes: endpoint?.totalMemoryBytes ?? null,
    processor_name: endpoint?.processorName ?? null,
    defender_status: endpoint?.defenderStatus ?? null,
    firewall_enabled: endpoint?.firewallEnabled ?? null,
    inventory_at: endpoint?.capturedAt ?? null,
    updated_at: now,
  }, { onConflict: 'terminal_id' })
  if (terminalError) return json({ error: 'Could not update terminal heartbeat' }, 500)


  // Older agents omit this field; keep their previous status row intact until upgraded.
  const update = terminal.managedUpdate
  if (update && typeof update.state === 'string') {
    const timestamp = update.lastCheckedAt ? new Date(update.lastCheckedAt) : null
    const safeTime = timestamp && Number.isFinite(timestamp.getTime()) &&
      Math.abs(Date.now() - timestamp.getTime()) < 30 * 86400000 ? timestamp.toISOString() : null
    const { error: updateError } = await admin.from('endpoint_agent_update_status').upsert({
      terminal_id: terminalHeader,
      current_version: String(update.currentVersion || terminal.appVersion || '').slice(0, 40) || null,
      latest_version: update.latestVersion ? String(update.latestVersion).slice(0, 40) : null,
      state: String(update.state).slice(0, 80),
      message: update.message ? String(update.message).slice(0, 700) : null,
      last_checked_at: safeTime,
      reported_at: now,
    }, { onConflict: 'terminal_id' })
    if (updateError) console.error('Update status reporting failed:', updateError.message)
    // Update visibility is best effort; audit uploads must continue if status telemetry fails.
  }

  // Agent network inventory is attached to the already authenticated terminal heartbeat.
  // Public IP comes from the server ingress, not from an untrusted client field.
  const network = terminal.network
  if (network) {
    const publicIp = (req.headers.get('x-forwarded-for') || '').split(',')[0].trim() || null
    const { data: previous, error: previousError } = await admin.from('endpoint_network_status')
      .select('*').eq('terminal_id', terminalHeader).maybeSingle()
    if (previousError) return json({ error: 'Could not read endpoint network state' }, 500)

    const localIp = network.localIp || null
    const mac = network.macAddress || null
    const networkName = network.networkName || null
    const connectionType = network.connectionType || null
    const gatewayIp = network.gatewayIp || null
    const changed = !previous ||
      previous.network_name !== networkName ||
      previous.connection_type !== connectionType ||
      previous.mac_address !== mac ||
      previous.local_ip !== localIp ||
      previous.public_ip !== publicIp

    // Only query a public-IP provider when the address changes. The resulting city and
    // coordinates are APPROXIMATE IP geolocation, never precise Windows/GPS location.
    let geo = {
      service_provider: previous?.public_ip === publicIp ? previous?.service_provider ?? null : null,
      geo_city: previous?.public_ip === publicIp ? previous?.geo_city ?? null : null,
      geo_region: previous?.public_ip === publicIp ? previous?.geo_region ?? null : null,
      geo_country: previous?.public_ip === publicIp ? previous?.geo_country ?? null : null,
      geo_latitude: previous?.public_ip === publicIp ? previous?.geo_latitude ?? null : null,
      geo_longitude: previous?.public_ip === publicIp ? previous?.geo_longitude ?? null : null,
      geo_accuracy: previous?.public_ip === publicIp ? previous?.geo_accuracy ?? 'not_available' : 'not_available',
    }
    if (publicIp && previous?.public_ip !== publicIp) {
      try {
        // Public IP is disclosed to this lookup provider; no device identifiers are sent.
        const lookup = await fetch(`https://ipwho.is/${encodeURIComponent(publicIp)}`, {
          signal: AbortSignal.timeout(2500),
          headers: { accept: 'application/json' },
        })
        if (lookup.ok) {
          const found = await lookup.json()
          if (found?.success === true) {
            const lat = Number(found.latitude)
            const lon = Number(found.longitude)
            geo = {
              service_provider: typeof found.connection?.isp === 'string' ? found.connection.isp.slice(0, 150) : null,
              geo_city: typeof found.city === 'string' ? found.city.slice(0, 150) : null,
              geo_region: typeof found.region === 'string' ? found.region.slice(0, 150) : null,
              geo_country: typeof found.country === 'string' ? found.country.slice(0, 150) : null,
              geo_latitude: Number.isFinite(lat) && Math.abs(lat) <= 90 ? lat : null,
              geo_longitude: Number.isFinite(lon) && Math.abs(lon) <= 180 ? lon : null,
              geo_accuracy: 'approximate_ip',
            }
          }
        }
      } catch { /* External lookup is best-effort and must not prevent audit synchronization. */ }
    }
    const speed = Number(network.linkSpeedMbps)
    const row = {
      terminal_id: terminalHeader, network_name: networkName,
      connection_type: connectionType, adapter_name: network.adapterName || null,
      local_ip: localIp, mac_address: mac, gateway_ip: gatewayIp,
      dns_servers: Array.isArray(network.dnsServers) ? network.dnsServers.slice(0, 6) : [],
      link_speed_mbps: network.linkSpeedMbps != null && Number.isFinite(speed) && speed >= 0 ? speed : null,
      public_ip: publicIp, ...geo, observed_at: now,
      changed_at: changed ? now : previous?.changed_at || now,
    }
    const { error: networkError } = await admin.from('endpoint_network_status')
      .upsert(row, { onConflict: 'terminal_id' })
    if (networkError) return json({ error: 'Could not save endpoint network status' }, 500)

    // Record a new history entry only when the network identity/address changes.
    if (changed) {
      const { error: historyError } = await admin.from('endpoint_network_history').insert({
        terminal_id: terminalHeader, network_name: networkName,
        connection_type: connectionType, adapter_name: network.adapterName || null,
        local_ip: localIp, mac_address: mac, gateway_ip: gatewayIp,
        link_speed_mbps: row.link_speed_mbps, public_ip: publicIp,
        service_provider: geo.service_provider, geo_city: geo.geo_city,
        geo_region: geo.geo_region, geo_country: geo.geo_country,
        change_reason: !previous ? 'first_observed' :
          previous.public_ip !== publicIp ? 'public_ip_changed' : 'network_changed',
        observed_at: now,
      })
      if (historyError) console.error('Network history insert failed', historyError.message)
    }
  }

  // The foreground Smart Console UI obtains Windows location permission. The agent
  // only forwards permitted samples; disabled/denied clears previously stored coords.
  const location = terminal.location
  if (location && typeof location.enabled === 'boolean') {
    const enabled = location.enabled === true
    const { data: previousLocation, error: previousLocationError } = await admin
      .from('endpoint_location_status').select('*').eq('terminal_id', terminalHeader).maybeSingle()
    if (previousLocationError) return json({ error: 'Could not read endpoint location state' }, 500)
    const lat = Number(location.latitude)
    const lon = Number(location.longitude)
    const accuracy = Number(location.accuracyMeters)
    const captured = location.capturedAt ? new Date(location.capturedAt) : null
    const capturedTime = captured?.getTime() ?? NaN
    const valid = enabled && location.status === 'reporting' &&
      location.source === 'windows_geolocator' &&
      location.latitude != null && location.longitude != null && location.accuracyMeters != null &&
      Number.isFinite(lat) && Math.abs(lat) <= 90 && Number.isFinite(lon) && Math.abs(lon) <= 180 &&
      Number.isFinite(accuracy) && accuracy >= 0 && accuracy <= 100000 &&
      Number.isFinite(capturedTime) && capturedTime <= Date.now() + 300000 &&
      capturedTime > Date.now() - 1200000 &&
      (!previousLocation?.captured_at || capturedTime > new Date(previousLocation.captured_at).getTime())
    const priorFresh = previousLocation?.captured_at &&
      new Date(previousLocation.captured_at).getTime() >= Date.now() - 7 * 86400000
    const coordinates = enabled && priorFresh ? {
      latitude: previousLocation.latitude, longitude: previousLocation.longitude,
      accuracy_meters: previousLocation.accuracy_meters, source: previousLocation.source,
      captured_at: previousLocation.captured_at,
    } : { latitude: null, longitude: null, accuracy_meters: null, source: null, captured_at: null }
    if (valid) {
      coordinates.latitude = lat
      coordinates.longitude = lon
      coordinates.accuracy_meters = accuracy
      coordinates.source = 'windows_geolocator'
      coordinates.captured_at = captured!.toISOString()
    }
    const { error: locationError } = await admin.from('endpoint_location_status').upsert({
      terminal_id: terminalHeader,
      sharing_enabled: enabled,
      status: enabled ? (valid ? 'reporting' : String(location.status || 'awaiting_position').slice(0, 40))
        : String(location.status || 'disabled').slice(0, 40),
      ...coordinates, received_at: now,
    }, { onConflict: 'terminal_id' })
    if (locationError) return json({ error: 'Could not store approved location status' }, 500)
  }

  if (endpoint && Array.isArray(endpoint.installedSoftware)) {
    const software = endpoint.installedSoftware.slice(0, 1000).filter(item => item.name)
    const rows = []
    for (const item of software) {
      rows.push({ terminal_id: terminalHeader, software_key: await softwareKey(item), name: item.name,
        version: item.version ?? null, publisher: item.publisher ?? null,
        install_location: item.installLocation ?? null,
        executable_paths: Array.isArray(item.executablePaths) ? item.executablePaths.slice(0, 50) : [],
        last_seen_at: now })
    }
    if (rows.length > 0) {
      const { error: softwareError } = await admin.from('installed_software').upsert(rows, { onConflict: 'terminal_id,software_key' })
      if (softwareError) return json({ error: 'Could not store installed software inventory' }, 500)
    }
  }

  const connectedDevices = Array.isArray(terminal.connectedDevices) ? terminal.connectedDevices.slice(0, 100) : []
  const { error: deleteDeviceError } = await admin.from('terminal_devices').delete().eq('terminal_id', terminalHeader)
  if (deleteDeviceError) return json({ error: 'Could not refresh terminal devices' }, 500)

  if (connectedDevices.length > 0) {
    const rows = connectedDevices.filter(device => device.deviceKey).map(device => ({
      terminal_id: terminalHeader,
      device_key: device.deviceKey,
      drive_letter: device.driveLetter || null,
      device_name: device.deviceName || null,
      device_serial: device.deviceSerial || null,
      volume_label: device.volumeLabel || null,
      file_system: device.fileSystem || null,
      total_size_bytes: device.totalSizeBytes ?? null,
      available_free_space_bytes: device.availableFreeSpaceBytes ?? null,
      connected_at: device.connectedAt || now,
      updated_at: now,
    }))
    if (rows.length > 0) {
      const { error: deviceError } = await admin.from('terminal_devices').insert(rows)
      if (deviceError) return json({ error: 'Could not store terminal devices' }, 500)
    }
  }

  const events = Array.isArray(payload.events) ? payload.events.slice(0, 500) : []
  if (events.length > 0) {
    const rows = events.filter(event => event.eventId && event.timestamp && event.kind).map(event => ({
      event_id: event.eventId,
      terminal_id: terminalHeader,
      timestamp: event.timestamp,
      kind: event.kind,
      direction: event.direction ?? null,
      windows_user: event.windowsUser ?? null,
      computer_name: event.computerName ?? terminal.computerName ?? null,
      device_name: event.deviceName ?? null,
      device_serial: event.deviceSerial ?? null,
      drive_letter: event.driveLetter ?? null,
      volume_label: event.volumeLabel ?? null,
      file_name: event.fileName ?? null,
      file_path: event.filePath ?? null,
      source_path: event.sourcePath ?? null,
      destination_path: event.destinationPath ?? null,
      file_size_bytes: event.fileSizeBytes ?? null,
      sha256: event.sha256 ?? null,
      archive_copy_created: Boolean(event.archiveCopyCreated),
      evidence: event.evidence ?? null,
      notes: event.notes ?? null,
      previous_record_hash: event.previousRecordHash ?? null,
      record_hash: event.recordHash ?? null,
    }))
    if (rows.length > 0) {
      const { error: eventError } = await admin.from('audit_events').upsert(rows, { onConflict: 'event_id', ignoreDuplicates: true })
      if (eventError) return json({ error: 'Could not store audit events' }, 500)
    }
  }

  const deploymentProgress = Array.isArray(payload.deploymentProgress) ? payload.deploymentProgress.slice(0, 50) : []
  for (const progress of deploymentProgress) {
    if (!progress.commandId || !progress.deploymentTaskId) continue

    const percent = Math.max(0, Math.min(100, Math.round(Number(progress.progressPercent ?? 0))))
    const stage = (progress.stage || 'working').slice(0, 80)
    const message = (progress.message || '').slice(0, 1000)
    const attempt = Math.max(1, Math.min(20, Math.round(Number(progress.attempt ?? 1))))
    const progressAt = progress.updatedAt || now
    const defenderStatus = progress.defenderScanStatus ? progress.defenderScanStatus.slice(0, 40) : null

    const { data: updatedTask, error: progressError } = await admin.from('deployment_tasks').update({
      status: stage === 'completed' ? 'completed' : stage === 'failed' ? 'failed' : 'acknowledged',
      progress_percent: percent,
      progress_stage: stage,
      progress_message: message || null,
      attempt_count: attempt,
      last_progress_at: progressAt,
      defender_scan_status: defenderStatus,
    })
      .eq('task_id', progress.deploymentTaskId)
      .eq('command_id', progress.commandId)
      .eq('terminal_id', terminalHeader)
      .select('batch_id,app_id')
      .maybeSingle()

    if (progressError) return json({ error: 'Could not record application deployment progress' }, 500)

    if (updatedTask) {
      if (defenderStatus === 'clean' && ['defender_clean', 'ready_to_install', 'install_requested', 'installing', 'finalizing', 'completed'].includes(stage)) {
        await admin.from('deployment_apps').update({
          last_defender_verified_at: progressAt,
          last_defender_verified_terminal_id: terminalHeader,
        }).eq('app_id', updatedTask.app_id)
      }
      await refreshDeploymentBatch(admin, updatedTask.batch_id)
    }
  }

  const commandResults = Array.isArray(payload.commandResults) ? payload.commandResults.slice(0, 50) : []
  for (const result of commandResults) {
    if (!result.commandId || !['completed', 'failed'].includes(result.status || '')) continue
    const resultMessage = (result.message || '').slice(0, 500)
    const { data: completedCommand, error } = await admin.from('endpoint_commands').update({
      status: result.status,
      completed_at: now,
      result: {
        message: resultMessage,
        appId: result.appId || null,
        packageSha256: result.packageSha256 || null,
        defenderScanStatus: result.defenderScanStatus || null,
      },
    })
      .eq('command_id', result.commandId)
      .eq('terminal_id', terminalHeader)
      .select('command_type')
      .maybeSingle()
    if (error) return json({ error: 'Could not record endpoint command result' }, 500)

    if (completedCommand?.command_type === 'verify_application_package' && result.appId) {
      if (
        result.status === 'completed' &&
        /^[0-9A-Fa-f]{64}$/.test(result.packageSha256 || '') &&
        result.defenderScanStatus === 'clean'
      ) {
        const { error: verificationError } = await admin.from('deployment_apps').update({
          sha256: String(result.packageSha256).toLowerCase(),
          last_defender_verified_at: now,
          last_defender_verified_terminal_id: terminalHeader,
          verification_status: 'verified',
          verification_message: resultMessage || 'Package SHA-256 and Microsoft Defender verification completed.',
        }).eq('app_id', result.appId)
        if (verificationError) return json({ error: 'Could not mark application package verified' }, 500)
      } else {
        const { error: verificationError } = await admin.from('deployment_apps').update({
          verification_status: 'failed',
          verification_message: resultMessage || 'Application package verification failed.',
        }).eq('app_id', result.appId)
        if (verificationError) return json({ error: 'Could not record application verification failure' }, 500)
      }
    }

    const { data: deploymentTask, error: taskLookupError } = await admin.from('deployment_tasks')
      .select('task_id,batch_id').eq('command_id', result.commandId).maybeSingle()
    if (taskLookupError) return json({ error: 'Could not resolve deployment task result' }, 500)
    if (deploymentTask) {
      const finalMessage = (result.message || '').slice(0, 1000)
      const taskPatch = result.status === 'completed'
        ? {
            status: 'completed',
            message: finalMessage,
            completed_at: now,
            progress_percent: 100,
            progress_stage: 'completed',
            progress_message: finalMessage,
            last_progress_at: now,
          }
        : {
            status: 'failed',
            message: finalMessage,
            completed_at: now,
            progress_stage: 'failed',
            progress_message: finalMessage,
            last_progress_at: now,
          }
      const { error: taskUpdateError } = await admin.from('deployment_tasks').update(taskPatch)
        .eq('task_id', deploymentTask.task_id)
      if (taskUpdateError) return json({ error: 'Could not record deployment task result' }, 500)
      await refreshDeploymentBatch(admin, deploymentTask.batch_id)
    }
  }

  const { data: pendingCommands, error: commandError } = await admin.from('endpoint_commands')
    .select('command_id,command_type,payload')
    .eq('terminal_id', terminalHeader)
    .eq('status', 'pending')
    .in('command_type', ['inventory', 'remote_support', 'sync_policy', 'deploy_application', 'verify_application_package', 'set_connection_password', 'request_location'])
    .order('requested_at', { ascending: true })
    .limit(20)
  if (commandError) return json({ error: 'Could not retrieve endpoint commands' }, 500)

  const commandIds = (pendingCommands ?? []).map(command => command.command_id)
  if (commandIds.length > 0) {
    const { error: acknowledgeError } = await admin.from('endpoint_commands').update({
      status: 'acknowledged', acknowledged_at: now,
    }).in('command_id', commandIds).eq('terminal_id', terminalHeader)
    if (acknowledgeError) return json({ error: 'Could not acknowledge endpoint commands' }, 500)

    const { data: acknowledgedTasks, error: deploymentAckError } = await admin.from('deployment_tasks')
      .update({
        status: 'acknowledged',
        progress_percent: 2,
        progress_stage: 'received',
        progress_message: 'Deployment received by the endpoint.',
        last_progress_at: now,
        started_at: now,
      })
      .in('command_id', commandIds)
      .eq('terminal_id', terminalHeader)
      .eq('status', 'pending')
      .select('batch_id')
    if (deploymentAckError) return json({ error: 'Could not acknowledge deployment tasks' }, 500)
    for (const batchId of [...new Set((acknowledgedTasks ?? []).map(item => item.batch_id))]) {
      await refreshDeploymentBatch(admin, batchId)
    }
  }

  const commands = (pendingCommands ?? []).map(command => ({
    commandId: command.command_id,
    commandType: command.command_type,
    payload: command.payload ?? {},
  }))

  return json({ ok: true, accepted: events.length, terminalId: terminalHeader, receivedAt: now, issuedToken, commands })
})
