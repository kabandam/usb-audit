import { createClient } from 'npm:@supabase/supabase-js@2'

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

type AuditEvent = Record<string, unknown> & {
  eventId?: string
  timestamp?: string
  kind?: string
}

type Payload = {
  terminal?: {
    terminalId?: string
    computerName?: string
    windowsUser?: string
    appVersion?: string
    timestamp?: string
    connectedDevices?: ConnectedDevice[]
  }
  events?: AuditEvent[]
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

Deno.serve(async (req: Request) => {
  if (req.method !== 'POST') return json({ error: 'Method not allowed' }, 405)

  const authorization = req.headers.get('authorization') ?? ''
  const token = authorization.startsWith('Bearer ') ? authorization.slice(7).trim() : ''
  const terminalHeader = req.headers.get('x-usbaudit-terminal')?.trim() ?? ''
  if (!token || !terminalHeader) return json({ error: 'Terminal authentication required' }, 401)

  let payload: Payload
  try {
    payload = await req.json()
  } catch {
    return json({ error: 'Invalid JSON body' }, 400)
  }

  const terminal = payload.terminal
  if (!terminal?.terminalId || terminal.terminalId !== terminalHeader) {
    return json({ error: 'Terminal identity mismatch' }, 401)
  }

  const url = Deno.env.get('SUPABASE_URL')
  const serviceKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')
  if (!url || !serviceKey) return json({ error: 'Server configuration unavailable' }, 500)

  const admin = createClient(url, serviceKey, { auth: { persistSession: false, autoRefreshToken: false } })
  const tokenHash = await sha256(token)

  const { data: tokenRow, error: tokenError } = await admin
    .from('terminal_tokens')
    .select('terminal_id')
    .eq('terminal_id', terminalHeader)
    .eq('token_hash', tokenHash)
    .is('revoked_at', null)
    .maybeSingle()

  if (tokenError) return json({ error: 'Could not verify terminal' }, 500)
  if (!tokenRow) return json({ error: 'Invalid or revoked terminal token' }, 401)

  const now = new Date().toISOString()
  const { error: terminalError } = await admin.from('terminals').upsert({
    terminal_id: terminalHeader,
    computer_name: terminal.computerName || terminalHeader,
    windows_user: terminal.windowsUser || null,
    app_version: terminal.appVersion || null,
    last_seen_at: terminal.timestamp || now,
    updated_at: now,
  }, { onConflict: 'terminal_id' })

  if (terminalError) return json({ error: 'Could not update terminal heartbeat' }, 500)

  const connectedDevices = Array.isArray(terminal.connectedDevices) ? terminal.connectedDevices.slice(0, 100) : []
  const { error: deleteDeviceError } = await admin.from('terminal_devices').delete().eq('terminal_id', terminalHeader)
  if (deleteDeviceError) return json({ error: 'Could not refresh terminal devices' }, 500)

  if (connectedDevices.length > 0) {
    const rows = connectedDevices
      .filter(device => device.deviceKey)
      .map(device => ({
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
    const rows = events
      .filter(event => event.eventId && event.timestamp && event.kind)
      .map(event => ({
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

  return json({ ok: true, accepted: events.length, terminalId: terminalHeader, receivedAt: now })
})
