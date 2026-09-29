import { useEffect, useMemo, useState } from 'react'
import { supabase } from './lib/supabase'
import './deployment-manager.css'

type Terminal = {
  terminal_id: string
  computer_name: string
  windows_user: string | null
  app_version: string | null
  enrollment_status: 'active' | 'revoked'
  last_seen_at: string
}

type DeploymentApp = {
  app_id: string
  name: string
  version: string
  publisher: string | null
  installer_type: 'msi' | 'exe'
  package_type: 'msi' | 'exe' | 'zip'
  package_url: string | null
  storage_provider: 'https' | 'onedrive'
  storage_drive_id: string | null
  storage_item_id: string | null
  storage_web_url: string | null
  storage_file_name: string | null
  file_size_bytes: number | null
  installer_entry: string | null
  metadata_confidence: 'detected' | 'confirm' | 'manual'
  sha256: string | null
  install_args: string
  install_timeout_minutes: number
  success_codes: number[]
  notes: string | null
  is_active: boolean
  created_at: string
  last_defender_verified_at: string | null
  last_defender_verified_terminal_id: string | null
  verification_status: 'pending' | 'queued' | 'verifying' | 'verified' | 'failed'
  verification_message: string | null
  last_verification_requested_at: string | null
}

type EndpointGroup = {
  group_id: string
  name: string
  description: string | null
  created_at: string
}

type GroupMember = {
  group_id: string
  terminal_id: string
}

type DeploymentBatch = {
  batch_id: string
  name: string
  requested_at: string
  app_count: number
  terminal_count: number
  status: 'queued' | 'in_progress' | 'completed' | 'partial' | 'failed' | 'cancelled'
}

type DeploymentTask = {
  task_id: string
  batch_id: string
  app_id: string
  terminal_id: string
  sequence_no: number
  command_id: string | null
  status: 'pending' | 'acknowledged' | 'completed' | 'failed' | 'cancelled'
  message: string | null
  requested_at: string
  completed_at: string | null
  progress_percent: number
  progress_stage: string
  progress_message: string | null
  attempt_count: number
  last_progress_at: string
  started_at: string | null
  defender_scan_status: string | null
}

type Tab = 'deploy' | 'applications' | 'groups' | 'history'

const isOnline = (lastSeen: string) => Date.now() - new Date(lastSeen).getTime() < 45_000
const dateTime = (value?: string | null) => value ? new Date(value).toLocaleString() : '—'
const shortHash = (value?: string | null) => value ? `${value.slice(0, 10)}…${value.slice(-6)}` : 'Not verified'
const packageHost = (value?: string | null) => {
  if (!value) return 'Data Centre OneDrive'
  try { return new URL(value).hostname }
  catch { return value }
}

const DATA_CENTRE_DRIVE_ID = 'b!l4Wat0zMtkGXeibrIQS1DJ9lhL-UKuhPvT-7il85MzyA3mCd8GVwTZ1O0u25u4_s'
const DATA_CENTRE_FOLDER_ID = '01AIJXTSLSPMBUPZP2OFDKZ7FJXJSCOA6U'
const DATA_CENTRE_FOLDER_URL = 'https://creccom-my.sharepoint.com/personal/datacentre_creccommw_org/Documents/Smart%20Console%20App%20Packages'
const GRAPH_CHUNK_SIZE = 10 * 320 * 1024
const SMART_CONSOLE_GRAPH_TOKEN = 'smart-console:graph-provider-token'
const SMART_CONSOLE_GRAPH_TOKEN_EXPIRES = 'smart-console:graph-provider-token-expires'
const RETURN_TO_APPLICATIONS = 'smart-console:return-applications'

const bytesLabel = (value?: number | null) => {
  if (!value) return '—'
  const units = ['B', 'KB', 'MB', 'GB']
  let size = value
  let unit = 0
  while (size >= 1024 && unit < units.length - 1) { size /= 1024; unit++ }
  return `${size >= 100 ? Math.round(size) : size.toFixed(1)} ${units[unit]}`
}

const inferNameVersion = (filename: string) => {
  const stem = filename.replace(/\.(msi|exe|zip)$/i, '')
  const normalized = stem.replace(/[_.-]+/g, ' ').replace(/\s+/g, ' ').trim()
  const match = normalized.match(/(?:^|\s)v?(\d+(?:\.\d+){1,3})(?:\s|$)/i)
  const version = match?.[1] || ''
  const rawName = match ? normalized.slice(0, match.index).trim() : normalized
  const name = (rawName || normalized || 'Application')
    .replace(/\b(setup|installer|install|x64|x86|win64|windows)\b/gi, ' ')
    .replace(/\s+/g, ' ')
    .trim()
  return { name: name || 'Application', version }
}

const listZipInstallerEntries = async (file: File) => {
  const tailLength = Math.min(file.size, 65_557)
  const tailStart = file.size - tailLength
  const tail = new Uint8Array(await file.slice(tailStart).arrayBuffer())
  let eocd = -1
  for (let i = tail.length - 22; i >= 0; i--) {
    if (tail[i] === 0x50 && tail[i + 1] === 0x4b && tail[i + 2] === 0x05 && tail[i + 3] === 0x06) {
      eocd = i
      break
    }
  }
  if (eocd < 0) return []

  const view = new DataView(tail.buffer, tail.byteOffset, tail.byteLength)
  const centralSize = view.getUint32(eocd + 12, true)
  const centralOffset = view.getUint32(eocd + 16, true)
  const central = new Uint8Array(await file.slice(centralOffset, centralOffset + centralSize).arrayBuffer())
  const centralView = new DataView(central.buffer, central.byteOffset, central.byteLength)
  const decoder = new TextDecoder('utf-8')
  const entries: string[] = []
  let offset = 0

  while (offset + 46 <= central.length && centralView.getUint32(offset, true) === 0x02014b50) {
    const nameLength = centralView.getUint16(offset + 28, true)
    const extraLength = centralView.getUint16(offset + 30, true)
    const commentLength = centralView.getUint16(offset + 32, true)
    const nameStart = offset + 46
    const name = decoder.decode(central.slice(nameStart, nameStart + nameLength))
    if (/\.(msi|exe)$/i.test(name) && !name.endsWith('/')) entries.push(name)
    offset = nameStart + nameLength + extraLength + commentLength
  }
  return entries
}

const pickZipInstaller = (entries: string[]) => {
  if (entries.length === 0) return null
  if (entries.length === 1) return entries[0]
  const preferred = entries.filter(entry => /(^|\/)(setup|install|installer)[^/]*\.(msi|exe)$/i.test(entry))
  return preferred.length === 1 ? preferred[0] : entries[0]
}

const sha256File = async (file: File) => {
  const digest = await crypto.subtle.digest('SHA-256', await file.arrayBuffer())
  return Array.from(new Uint8Array(digest)).map(byte => byte.toString(16).padStart(2, '0')).join('')
}

const uploadToDataCentre = async (
  file: File,
  accessToken: string,
  onProgress: (value: number) => void,
) => {
  const safeName = file.name.replace(/[\\/:*?"<>|]/g, '_')
  const encodedName = encodeURIComponent(safeName)

  if (file.size <= 4 * 1024 * 1024) {
    const response = await fetch(
      `https://graph.microsoft.com/v1.0/drives/${DATA_CENTRE_DRIVE_ID}/items/${DATA_CENTRE_FOLDER_ID}:/${encodedName}:/content`,
      {
        method: 'PUT',
        headers: { authorization: `Bearer ${accessToken}`, 'content-type': 'application/octet-stream' },
        body: file,
      },
    )
    if (response.status === 401 || response.status === 403) throw new Error('Microsoft 365 storage authorization expired or is missing the required file permission.')
    if (!response.ok) throw new Error(`Microsoft 365 upload failed (HTTP ${response.status}).`)
    onProgress(100)
    const item = await response.json()
    const linkResponse = await fetch(
      `https://graph.microsoft.com/v1.0/drives/${DATA_CENTRE_DRIVE_ID}/items/${item.id}/createLink`,
      {
        method: 'POST',
        headers: { authorization: `Bearer ${accessToken}`, 'content-type': 'application/json' },
        body: JSON.stringify({ type: 'view', scope: 'organization' }),
      },
    )
    if (linkResponse.status === 401 || linkResponse.status === 403) throw new Error('Microsoft 365 storage authorization expired or is missing the required file permission.')
    if (!linkResponse.ok) throw new Error(`Package uploaded, but the CRECCOM-only access link could not be created (HTTP ${linkResponse.status}).`)
    const permission = await linkResponse.json()
    return { ...item, sharingUrl: permission.link?.webUrl || item.webUrl }
  }

  const sessionResponse = await fetch(
    `https://graph.microsoft.com/v1.0/drives/${DATA_CENTRE_DRIVE_ID}/items/${DATA_CENTRE_FOLDER_ID}:/${encodedName}:/createUploadSession`,
    {
      method: 'POST',
      headers: { authorization: `Bearer ${accessToken}`, 'content-type': 'application/json' },
      body: JSON.stringify({ item: { '@microsoft.graph.conflictBehavior': 'rename', name: safeName } }),
    },
  )
  if (sessionResponse.status === 401 || sessionResponse.status === 403) throw new Error('Microsoft 365 storage authorization expired or is missing the required file permission.')
  if (!sessionResponse.ok) throw new Error(`Could not create Microsoft 365 upload session (HTTP ${sessionResponse.status}).`)
  const uploadSession = await sessionResponse.json()
  const uploadUrl = uploadSession.uploadUrl as string
  if (!uploadUrl) throw new Error('Microsoft 365 returned no upload session URL.')

  let finalItem: any = null
  for (let start = 0; start < file.size; start += GRAPH_CHUNK_SIZE) {
    const endExclusive = Math.min(start + GRAPH_CHUNK_SIZE, file.size)
    const chunk = file.slice(start, endExclusive)
    const response = await fetch(uploadUrl, {
      method: 'PUT',
      headers: {
        'content-length': String(chunk.size),
        'content-range': `bytes ${start}-${endExclusive - 1}/${file.size}`,
      },
      body: chunk,
    })
    if (![200, 201, 202].includes(response.status)) {
      throw new Error(`Microsoft 365 upload failed at ${Math.round((start / file.size) * 100)}% (HTTP ${response.status}).`)
    }
    const payload = await response.json()
    if (response.status !== 202) finalItem = payload
    onProgress(Math.round((endExclusive / file.size) * 100))
  }
  if (!finalItem?.id) throw new Error('Microsoft 365 upload completed without a file identifier.')

  const linkResponse = await fetch(
    `https://graph.microsoft.com/v1.0/drives/${DATA_CENTRE_DRIVE_ID}/items/${finalItem.id}/createLink`,
    {
      method: 'POST',
      headers: { authorization: `Bearer ${accessToken}`, 'content-type': 'application/json' },
      body: JSON.stringify({ type: 'view', scope: 'organization' }),
    },
  )
  if (!linkResponse.ok) throw new Error(`Package uploaded, but the CRECCOM-only access link could not be created (HTTP ${linkResponse.status}).`)
  const permission = await linkResponse.json()
  return { ...finalItem, sharingUrl: permission.link?.webUrl || finalItem.webUrl }
}

export function DeploymentManager() {
  const [tab, setTab] = useState<Tab>('deploy')
  const [terminals, setTerminals] = useState<Terminal[]>([])
  const [apps, setApps] = useState<DeploymentApp[]>([])
  const [groups, setGroups] = useState<EndpointGroup[]>([])
  const [members, setMembers] = useState<GroupMember[]>([])
  const [batches, setBatches] = useState<DeploymentBatch[]>([])
  const [tasks, setTasks] = useState<DeploymentTask[]>([])
  const [selectedApps, setSelectedApps] = useState<Set<string>>(new Set())
  const [selectedTerminals, setSelectedTerminals] = useState<Set<string>>(new Set())
  const [selectedGroups, setSelectedGroups] = useState<Set<string>>(new Set())
  const [batchName, setBatchName] = useState('')
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [busy, setBusy] = useState('')
  const [autoVerificationAttempted, setAutoVerificationAttempted] = useState<Set<string>>(new Set())
  const [storageState, setStorageState] = useState<'checking' | 'ready' | 'connect' | 'error'>('checking')
  const [storageMessage, setStorageMessage] = useState('Checking Data Centre OneDrive access…')

  const [editingAppId, setEditingAppId] = useState<string | null>(null)
  const [appName, setAppName] = useState('')
  const [appVersion, setAppVersion] = useState('')
  const [appPublisher, setAppPublisher] = useState('')
  const [installerType, setInstallerType] = useState<'msi' | 'exe'>('msi')
  const [packageType, setPackageType] = useState<'msi' | 'exe' | 'zip'>('msi')
  const [packageUrl, setPackageUrl] = useState('')
  const [storageProvider, setStorageProvider] = useState<'https' | 'onedrive'>('onedrive')
  const [storageDriveId, setStorageDriveId] = useState('')
  const [storageItemId, setStorageItemId] = useState('')
  const [storageWebUrl, setStorageWebUrl] = useState('')
  const [storageFileName, setStorageFileName] = useState('')
  const [fileSizeBytes, setFileSizeBytes] = useState<number | null>(null)
  const [installerEntry, setInstallerEntry] = useState('')
  const [metadataConfidence, setMetadataConfidence] = useState<'detected' | 'confirm' | 'manual'>('manual')
  const [packageFile, setPackageFile] = useState<File | null>(null)
  const [uploadProgress, setUploadProgress] = useState(0)
  const [dragActive, setDragActive] = useState(false)
  const [sha256, setSha256] = useState('')
  const [installArgs, setInstallArgs] = useState('')
  const [installTimeoutMinutes, setInstallTimeoutMinutes] = useState(15)
  const [successCodes, setSuccessCodes] = useState('0,1641,3010')
  const [appNotes, setAppNotes] = useState('')

  const [editingGroupId, setEditingGroupId] = useState<string | null>(null)
  const [groupName, setGroupName] = useState('')
  const [groupDescription, setGroupDescription] = useState('')
  const [groupTerminals, setGroupTerminals] = useState<Set<string>>(new Set())

  const load = async () => {
    if (!supabase) return
    const results = await Promise.all([
      supabase.from('terminals').select('terminal_id,computer_name,windows_user,app_version,enrollment_status,last_seen_at').order('computer_name'),
      supabase.from('deployment_apps').select('*').eq('is_active', true).order('name').order('version'),
      supabase.from('endpoint_groups').select('*').order('name'),
      supabase.from('endpoint_group_members').select('*'),
      supabase.from('deployment_batches').select('*').order('requested_at', { ascending: false }).limit(60),
      supabase.from('deployment_tasks').select('*').order('requested_at', { ascending: false }).limit(2500),
    ])
    const firstError = results.find(result => result.error)?.error
    setError(firstError?.message || '')
    setTerminals((results[0].data ?? []) as Terminal[])
    setApps((results[1].data ?? []) as DeploymentApp[])
    setGroups((results[2].data ?? []) as EndpointGroup[])
    setMembers((results[3].data ?? []) as GroupMember[])
    setBatches((results[4].data ?? []) as DeploymentBatch[])
    setTasks((results[5].data ?? []) as DeploymentTask[])
  }

  useEffect(() => {
    load()
    const timer = window.setInterval(load, 5_000)
    if (!supabase) return () => window.clearInterval(timer)

    const channel = supabase
      .channel('smart-console-deployment-progress')
      .on('postgres_changes', { event: '*', schema: 'public', table: 'deployment_tasks' }, () => load())
      .subscribe()

    return () => {
      window.clearInterval(timer)
      supabase?.removeChannel(channel)
    }
  }, [])

  const getMicrosoftStorageToken = async () => {
    if (!supabase) return ''
    const { data: { session } } = await supabase.auth.getSession()
    const live = session?.provider_token || ''
    if (live) {
      sessionStorage.setItem(SMART_CONSOLE_GRAPH_TOKEN, live)
      return live
    }

    const cached = sessionStorage.getItem(SMART_CONSOLE_GRAPH_TOKEN) || ''
    const expiresAt = Number(sessionStorage.getItem(SMART_CONSOLE_GRAPH_TOKEN_EXPIRES) || '0')
    if (!cached || (expiresAt > 0 && expiresAt <= Date.now() + 60_000)) {
      sessionStorage.removeItem(SMART_CONSOLE_GRAPH_TOKEN)
      sessionStorage.removeItem(SMART_CONSOLE_GRAPH_TOKEN_EXPIRES)
      return ''
    }
    return cached
  }

  const getOneDriveDownloadUrl = async (driveId: string, itemId: string, token?: string) => {
    const accessToken = token || await getMicrosoftStorageToken()
    if (!accessToken) throw new Error('Connect Microsoft 365 storage before continuing.')

    const response = await fetch(
      `https://graph.microsoft.com/v1.0/drives/${encodeURIComponent(driveId)}/items/${encodeURIComponent(itemId)}`,
      { headers: { authorization: `Bearer ${accessToken}` } },
    )
    if (response.status === 401 || response.status === 403) {
      sessionStorage.removeItem(SMART_CONSOLE_GRAPH_TOKEN)
      sessionStorage.removeItem(SMART_CONSOLE_GRAPH_TOKEN_EXPIRES)
      setStorageState('connect')
      throw new Error('Microsoft 365 storage authorization expired. Reconnect Microsoft 365 and try again.')
    }
    if (!response.ok) throw new Error(`Could not prepare OneDrive package download (HTTP ${response.status}).`)

    const item = await response.json()
    const downloadUrl = item['@microsoft.graph.downloadUrl']
    if (!downloadUrl || typeof downloadUrl !== 'string') throw new Error('Microsoft 365 did not return a temporary package download URL.')
    return downloadUrl as string
  }

  const checkMicrosoftStorage = async () => {
    setStorageState('checking')
    setStorageMessage('Checking Data Centre OneDrive access…')
    try {
      const token = await getMicrosoftStorageToken()
      if (!token) {
        setStorageState('connect')
        setStorageMessage('Connect Microsoft 365 storage once before uploading application packages.')
        return false
      }

      const response = await fetch(
        `https://graph.microsoft.com/v1.0/drives/${DATA_CENTRE_DRIVE_ID}/items/${DATA_CENTRE_FOLDER_ID}?$select=id,name,webUrl`,
        { headers: { authorization: `Bearer ${token}` } },
      )

      if (response.status === 401 || response.status === 403) {
        sessionStorage.removeItem(SMART_CONSOLE_GRAPH_TOKEN)
        sessionStorage.removeItem(SMART_CONSOLE_GRAPH_TOKEN_EXPIRES)
        setStorageState('connect')
        setStorageMessage('Microsoft 365 needs to reconnect so Smart Console can write to the Data Centre package folder.')
        return false
      }
      if (!response.ok) {
        setStorageState('error')
        setStorageMessage(`Data Centre OneDrive could not be verified (HTTP ${response.status}).`)
        return false
      }

      setStorageState('ready')
      setStorageMessage('Data Centre OneDrive connected')
      return true
    } catch (err) {
      setStorageState('error')
      setStorageMessage(err instanceof Error ? err.message : 'Could not verify Data Centre OneDrive.')
      return false
    }
  }

  const connectMicrosoftStorage = async () => {
    if (!supabase) return
    setError('')
    setNotice('')
    sessionStorage.setItem(RETURN_TO_APPLICATIONS, '1')
    const { error: oauthError } = await supabase.auth.signInWithOAuth({
      provider: 'azure',
      options: {
        scopes: 'openid profile email offline_access User.Read Files.ReadWrite.All',
        redirectTo: window.location.origin,
        queryParams: { prompt: 'consent' },
      },
    })
    if (oauthError) {
      setError(oauthError.message)
      sessionStorage.removeItem(RETURN_TO_APPLICATIONS)
    }
  }


  useEffect(() => {
    checkMicrosoftStorage()
  }, [])

  const terminalMap = useMemo(() => new Map(terminals.map(item => [item.terminal_id, item])), [terminals])
  const appMap = useMemo(() => new Map(apps.map(item => [item.app_id, item])), [apps])

  const resolvedTargets = useMemo(() => {
    const ids = new Set(selectedTerminals)
    for (const member of members) {
      if (selectedGroups.has(member.group_id)) ids.add(member.terminal_id)
    }
    return [...ids].filter(id => terminalMap.get(id)?.enrollment_status === 'active')
  }, [selectedTerminals, selectedGroups, members, terminalMap])

  const invokeAdmin = async (body: Record<string, unknown>) => {
    if (!supabase) return { data: null, error: 'Supabase is unavailable' }
    const { data, error: invokeError } = await supabase.functions.invoke('terminal-admin', { body })
    return { data, error: data?.error || invokeError?.message || '' }
  }

  const retryDeploymentTask = async (task: DeploymentTask) => {
    setBusy(`retry:${task.task_id}`); setError(''); setNotice('')
    let packageDownloadUrl = ''
    try {
      const app = appMap.get(task.app_id)
      if (app?.storage_provider === 'onedrive' && app.storage_drive_id && app.storage_item_id) {
        packageDownloadUrl = await getOneDriveDownloadUrl(app.storage_drive_id, app.storage_item_id)
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not refresh the OneDrive package URL.')
      setBusy('')
      return
    }
    const { data, error: invokeError } = await invokeAdmin({
      action: 'retry_deployment_task',
      taskId: task.task_id,
      packageDownloadUrl,
    })
    if (invokeError) setError(invokeError)
    else {
      setNotice(`Force retry queued for ${terminalMap.get(task.terminal_id)?.computer_name || task.terminal_id} — attempt ${data.attempt}.`)
      await load()
    }
    setBusy('')
  }

  const verifyExistingApp = async (app: DeploymentApp) => {
    setBusy(`verify:${app.app_id}`); setError(''); setNotice('')
    let packageDownloadUrl = ''
    try {
      if (app.storage_provider === 'onedrive' && app.storage_drive_id && app.storage_item_id) {
        packageDownloadUrl = await getOneDriveDownloadUrl(app.storage_drive_id, app.storage_item_id)
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not prepare the OneDrive package for verification.')
      setBusy('')
      return
    }
    const { data, error: invokeError } = await invokeAdmin({
      action: 'verify_deployment_app',
      appId: app.app_id,
      packageDownloadUrl,
    })
    if (invokeError) {
      setError(invokeError)
    } else if (data?.verification?.queued === false) {
      setNotice('Package verification is waiting for an online Smart Console 1.2.98+ endpoint.')
    } else {
      setNotice('SHA-256 and Microsoft Defender verification has been queued on an online endpoint.')
    }
    await load()
    setBusy('')
  }

  // Auto-verify pending OneDrive catalog entries when Microsoft 365 storage is connected.
  useEffect(() => {
    if (storageState !== 'ready' || busy) return

    const candidate = apps.find(app =>
      app.verification_status !== 'verified' &&
      app.storage_provider === 'onedrive' &&
      Boolean(app.storage_drive_id) &&
      Boolean(app.storage_item_id) &&
      !autoVerificationAttempted.has(app.app_id)
    )
    if (!candidate) return

    setAutoVerificationAttempted(previous => {
      const next = new Set(previous)
      next.add(candidate.app_id)
      return next
    })
    verifyExistingApp(candidate)
  }, [storageState, apps])

  const queueDeployment = async () => {
    if (selectedApps.size === 0 || resolvedTargets.length === 0) return
    const selectedAppNames = [...selectedApps].map(id => appMap.get(id)?.name).filter(Boolean).join(', ')
    if (!window.confirm(`Deploy ${selectedApps.size} application(s) to ${resolvedTargets.length} managed PC(s)?\n\n${selectedAppNames}`)) return

    setBusy('deploy'); setError(''); setNotice('')
    const packageDownloadUrls: Record<string, string> = {}
    try {
      const token = await getMicrosoftStorageToken()
      for (const appId of selectedApps) {
        const app = appMap.get(appId)
        if (app?.storage_provider === 'onedrive' && app.storage_drive_id && app.storage_item_id) {
          if (!token) throw new Error('Connect Microsoft 365 storage before deploying OneDrive packages.')
          packageDownloadUrls[appId] = await getOneDriveDownloadUrl(app.storage_drive_id, app.storage_item_id, token)
        }
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not prepare OneDrive packages for deployment.')
      setBusy('')
      return
    }

    const { data, error: invokeError } = await invokeAdmin({
      action: 'create_app_deployment',
      batchName: batchName.trim(),
      appIds: [...selectedApps],
      terminalIds: [...selectedTerminals],
      groupIds: [...selectedGroups],
      packageDownloadUrls,
    })
    if (invokeError) {
      setError(invokeError)
    } else {
      setNotice(`Deployment queued: ${data.taskCount} task(s) across ${data.terminalCount} PC(s).`)
      setSelectedApps(new Set())
      setSelectedTerminals(new Set())
      setSelectedGroups(new Set())
      setBatchName('')
      setTab('history')
      await load()
    }
    setBusy('')
  }

  const preparePackage = async (file: File) => {
    const extension = file.name.split('.').pop()?.toLowerCase()
    if (!extension || !['msi', 'exe', 'zip'].includes(extension)) {
      setError('Smart Console accepts MSI, EXE or ZIP application packages.')
      return
    }

    setBusy('package'); setError(''); setNotice(''); setUploadProgress(0)
    try {
      const nextPackageType = extension as 'msi' | 'exe' | 'zip'
      let nextInstallerType: 'msi' | 'exe' = nextPackageType === 'msi' ? 'msi' : 'exe'
      let nextInstallerEntry = ''
      let metadataSourceName = file.name

      if (nextPackageType === 'zip') {
        const entries = await listZipInstallerEntries(file)
        const selectedEntry = pickZipInstaller(entries)
        if (!selectedEntry) throw new Error('No MSI or EXE installer was found inside this ZIP package.')
        nextInstallerEntry = selectedEntry
        nextInstallerType = selectedEntry.toLowerCase().endsWith('.msi') ? 'msi' : 'exe'
        metadataSourceName = selectedEntry.split('/').pop() || file.name
      }

      const inferred = inferNameVersion(metadataSourceName)
      const digest = await sha256File(file)

      const providerToken = await getMicrosoftStorageToken()
      if (!providerToken) {
        setStorageState('connect')
        throw new Error('Connect Microsoft 365 storage before uploading this package.')
      }

      const item = await uploadToDataCentre(file, providerToken, setUploadProgress)

      setPackageFile(file)
      setPackageType(nextPackageType)
      setInstallerType(nextInstallerType)
      setInstallerEntry(nextInstallerEntry)
      setSha256(digest)
      setFileSizeBytes(file.size)
      setStorageProvider('onedrive')
      setStorageDriveId(item.parentReference?.driveId || DATA_CENTRE_DRIVE_ID)
      setStorageItemId(item.id || '')
      setStorageWebUrl(item.sharingUrl || item.webUrl || DATA_CENTRE_FOLDER_URL)
      setStorageFileName(item.name || file.name)
      setPackageUrl('')
      if (!editingAppId || !appName) setAppName(inferred.name)
      if (!editingAppId || !appVersion) setAppVersion(inferred.version)
      const catalogName = inferred.name || 'Application'
      const catalogVersion = inferred.version || 'Unspecified'
      const catalogDriveId = item.parentReference?.driveId || DATA_CENTRE_DRIVE_ID
      const catalogWebUrl = item.sharingUrl || item.webUrl || DATA_CENTRE_FOLDER_URL
      const catalogFileName = item.name || file.name

      setAppName(catalogName)
      setAppVersion(catalogVersion)
      setMetadataConfidence('confirm')

      const { data: catalogData, error: catalogError } = await invokeAdmin({
        action: 'save_deployment_app',
        name: catalogName,
        version: catalogVersion,
        publisher: '',
        installerType: nextInstallerType,
        packageType: nextPackageType,
        packageUrl: '',
        storageProvider: 'onedrive',
        storageDriveId: catalogDriveId,
        storageItemId: item.id || '',
        storageWebUrl: catalogWebUrl,
        storageFileName: catalogFileName,
        fileSizeBytes: file.size,
        installerEntry: nextPackageType === 'zip' ? nextInstallerEntry : '',
        metadataConfidence: 'confirm',
        sha256: digest,
        installArgs: '',
        installTimeoutMinutes: 15,
        successCodes: [0, 1641, 3010],
        notes: 'Automatically cataloged when uploaded to Data Centre OneDrive.',
      })

      if (catalogError) throw new Error(`Package uploaded, but automatic cataloging failed: ${catalogError}`)

      setEditingAppId(catalogData?.appId || null)
      if (catalogData?.appId && item.id) {
        try {
          const packageDownloadUrl = await getOneDriveDownloadUrl(catalogDriveId, item.id, providerToken)
          await invokeAdmin({
            action: 'verify_deployment_app',
            appId: catalogData.appId,
            packageDownloadUrl,
          })
        } catch {
          // The catalog entry remains ready for manual verification from the Applications list.
        }
      }
      setNotice('Package uploaded and cataloged. SHA-256 and Microsoft Defender verification has been queued.')
      await load()
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Could not prepare the application package.'
      if (message.includes('Microsoft 365 storage authorization')) {
        sessionStorage.removeItem(SMART_CONSOLE_GRAPH_TOKEN)
        sessionStorage.removeItem(SMART_CONSOLE_GRAPH_TOKEN_EXPIRES)
        setStorageState('connect')
        setStorageMessage('Reconnect Microsoft 365 storage, then retry the upload.')
      }
      setError(message)
      setPackageFile(null)
      setStorageItemId('')
    } finally {
      setBusy('')
    }
  }

  const resetAppForm = () => {
    setEditingAppId(null); setAppName(''); setAppVersion(''); setAppPublisher('')
    setInstallerType('msi'); setPackageType('msi'); setPackageUrl(''); setSha256(''); setInstallArgs(''); setInstallTimeoutMinutes(15)
    setStorageProvider('onedrive'); setStorageDriveId(''); setStorageItemId(''); setStorageWebUrl('')
    setStorageFileName(''); setFileSizeBytes(null); setInstallerEntry(''); setMetadataConfidence('manual')
    setPackageFile(null); setUploadProgress(0); setSuccessCodes('0,1641,3010'); setAppNotes('')
  }

  const saveApp = async () => {
    const parsedCodes = successCodes.split(',').map(value => Number.parseInt(value.trim(), 10)).filter(Number.isInteger)
    setBusy('app'); setError(''); setNotice('')
    const { error: invokeError } = await invokeAdmin({
      action: 'save_deployment_app',
      appId: editingAppId || undefined,
      name: appName,
      version: appVersion,
      publisher: appPublisher,
      installerType,
      packageType,
      packageUrl,
      storageProvider,
      storageDriveId,
      storageItemId,
      storageWebUrl,
      storageFileName,
      fileSizeBytes,
      installerEntry,
      metadataConfidence,
      sha256,
      installArgs,
      installTimeoutMinutes,
      successCodes: parsedCodes,
      notes: appNotes,
    })
    if (invokeError) setError(invokeError)
    else {
      setNotice(editingAppId ? 'Application updated.' : 'Application added to the deployment catalog.')
      resetAppForm()
      await load()
    }
    setBusy('')
  }

  const editApp = (app: DeploymentApp) => {
    setEditingAppId(app.app_id); setAppName(app.name); setAppVersion(app.version)
    setAppPublisher(app.publisher || ''); setInstallerType(app.installer_type); setPackageType(app.package_type || app.installer_type)
    setPackageUrl(app.package_url || ''); setStorageProvider(app.storage_provider || 'https')
    setStorageDriveId(app.storage_drive_id || ''); setStorageItemId(app.storage_item_id || '')
    setStorageWebUrl(app.storage_web_url || ''); setStorageFileName(app.storage_file_name || '')
    setFileSizeBytes(app.file_size_bytes || null); setInstallerEntry(app.installer_entry || '')
    setMetadataConfidence(app.metadata_confidence || 'manual'); setPackageFile(null); setUploadProgress(0)
    setSha256(app.sha256 || ''); setInstallArgs(app.install_args || ''); setInstallTimeoutMinutes(app.install_timeout_minutes || 15)
    setSuccessCodes((app.success_codes || [0, 1641, 3010]).join(',')); setAppNotes(app.notes || '')
    setTab('applications')
  }

  const resetGroupForm = () => {
    setEditingGroupId(null); setGroupName(''); setGroupDescription(''); setGroupTerminals(new Set())
  }

  const saveGroup = async () => {
    setBusy('group'); setError(''); setNotice('')
    const { error: invokeError } = await invokeAdmin({
      action: 'save_endpoint_group',
      groupId: editingGroupId || undefined,
      name: groupName,
      description: groupDescription,
      terminalIds: [...groupTerminals],
    })
    if (invokeError) setError(invokeError)
    else {
      setNotice(editingGroupId ? 'Endpoint group updated.' : 'Endpoint group created.')
      resetGroupForm()
      await load()
    }
    setBusy('')
  }

  const editGroup = (group: EndpointGroup) => {
    setEditingGroupId(group.group_id); setGroupName(group.name)
    setGroupDescription(group.description || '')
    setGroupTerminals(new Set(members.filter(item => item.group_id === group.group_id).map(item => item.terminal_id)))
    setTab('groups')
  }

  const batchStats = (batchId: string) => {
    const rows = tasks.filter(task => task.batch_id === batchId)
    return {
      total: rows.length,
      completed: rows.filter(task => task.status === 'completed').length,
      failed: rows.filter(task => task.status === 'failed').length,
      active: rows.filter(task => ['pending', 'acknowledged'].includes(task.status)).length,
      progress: rows.length ? Math.round(rows.reduce((sum, task) => sum + Math.max(0, Math.min(100, task.progress_percent || 0)), 0) / rows.length) : 0,
    }
  }

  return <section className="deploymentSection">
    {error && <div className="errorBanner">{error}</div>}
    {notice && <div className="deploymentNotice">{notice}</div>}

    <div className="deploymentTabs">
      <button className={tab === 'deploy' ? 'active' : ''} onClick={() => setTab('deploy')}>Deploy</button>
      <button className={tab === 'applications' ? 'active' : ''} onClick={() => setTab('applications')}>Applications</button>
      <button className={tab === 'groups' ? 'active' : ''} onClick={() => setTab('groups')}>Endpoint Groups</button>
      <button className={tab === 'history' ? 'active' : ''} onClick={() => setTab('history')}>Deployment History</button>
    </div>

    {tab === 'deploy' && <>
      <div className="cards deploymentCards">
        <Metric label="Deployment apps" value={apps.length.toString()} detail="Approved catalog entries" />
        <Metric label="Managed PCs" value={terminals.filter(t => t.enrollment_status === 'active').length.toString()} detail={`${terminals.filter(t => isOnline(t.last_seen_at)).length} currently online`} />
        <Metric label="Endpoint groups" value={groups.length.toString()} detail="Reusable IT targeting" />
        <Metric label="Active deployments" value={batches.filter(b => ['queued', 'in_progress'].includes(b.status)).length.toString()} detail="Queued or installing" />
      </div>

      <div className="deploymentGrid">
        <div className="deploymentPanel">
          <div className="deploymentPanelHead"><div><span>Step 1</span><strong>Select applications</strong></div><em>{selectedApps.size} selected</em></div>
          <div className="deploymentChoiceList">
            {apps.length === 0 ? <p className="deploymentEmpty">Upload an application package first.</p> : apps.map(app => {
              const verified = /^[0-9A-Fa-f]{64}$/.test(app.sha256 || '') && app.verification_status === 'verified'
              const unattendedReady = app.installer_type === 'msi' || Boolean(app.install_args?.trim())
              const ready = verified && unattendedReady
              return <label className={ready ? 'deploymentChoice' : 'deploymentChoice disabledChoice'} key={app.app_id}>
                <input type="checkbox" disabled={!ready} checked={selectedApps.has(app.app_id)} onChange={event => {
                  const next = new Set(selectedApps)
                  if (event.target.checked) next.add(app.app_id); else next.delete(app.app_id)
                  setSelectedApps(next)
                }} />
                <span className="deploymentCheck" />
                <div><strong>{app.name}</strong><small>{app.version} · {!verified ? 'Package needs verification' : !unattendedReady ? 'Silent install arguments required for unattended EXE deployment' : (app.publisher || 'Publisher not specified')}</small></div>
                <b>{!verified ? 'VERIFY' : !unattendedReady ? 'SETUP' : app.installer_type.toUpperCase()}</b>
              </label>
            })}
          </div>
        </div>

        <div className="deploymentPanel">
          <div className="deploymentPanelHead"><div><span>Step 2</span><strong>Choose endpoint groups</strong></div><em>{selectedGroups.size} selected</em></div>
          <div className="groupTargetGrid">
            {groups.length === 0 ? <p className="deploymentEmpty">No saved endpoint groups yet.</p> : groups.map(group => {
              const count = members.filter(item => item.group_id === group.group_id).length
              return <label className={selectedGroups.has(group.group_id) ? 'groupTarget selected' : 'groupTarget'} key={group.group_id}>
                <input type="checkbox" checked={selectedGroups.has(group.group_id)} onChange={event => {
                  const next = new Set(selectedGroups)
                  if (event.target.checked) next.add(group.group_id); else next.delete(group.group_id)
                  setSelectedGroups(next)
                }} />
                <strong>{group.name}</strong><small>{count} PC{count === 1 ? '' : 's'}</small>
              </label>
            })}
          </div>
        </div>

        <div className="deploymentPanel deploymentEndpoints">
          <div className="deploymentPanelHead">
            <div><span>Step 3</span><strong>Add individual PCs</strong></div>
            <button className="textButton" onClick={() => {
              const activeIds = terminals.filter(t => t.enrollment_status === 'active').map(t => t.terminal_id)
              setSelectedTerminals(selectedTerminals.size === activeIds.length ? new Set() : new Set(activeIds))
            }}>{selectedTerminals.size === terminals.filter(t => t.enrollment_status === 'active').length ? 'Clear all' : 'Select all'}</button>
          </div>
          <div className="endpointTargetList">
            {terminals.filter(t => t.enrollment_status === 'active').map(terminal => <label className="endpointTarget" key={terminal.terminal_id}>
              <input type="checkbox" checked={selectedTerminals.has(terminal.terminal_id)} onChange={event => {
                const next = new Set(selectedTerminals)
                if (event.target.checked) next.add(terminal.terminal_id); else next.delete(terminal.terminal_id)
                setSelectedTerminals(next)
              }} />
              <span className="deploymentCheck" />
              <div><strong>{terminal.computer_name}</strong><small>{terminal.windows_user || terminal.terminal_id}</small></div>
              <span className={isOnline(terminal.last_seen_at) ? 'deploymentOnline' : 'deploymentOffline'}>{isOnline(terminal.last_seen_at) ? 'Online' : 'Offline'}</span>
              <code>{terminal.app_version || '—'}</code>
            </label>)}
          </div>
        </div>
      </div>

      <div className="deploymentLaunchBar">
        <div><span>Deployment scope</span><strong>{selectedApps.size} app{selectedApps.size === 1 ? '' : 's'} → {resolvedTargets.length} PC{resolvedTargets.length === 1 ? '' : 's'}</strong><small>Group targets and individually selected PCs are automatically de-duplicated.</small></div>
        <input value={batchName} onChange={event => setBatchName(event.target.value)} placeholder="Deployment name (optional)" maxLength={120} />
        <button className="primary" disabled={busy !== '' || selectedApps.size === 0 || resolvedTargets.length === 0} onClick={queueDeployment}>{busy === 'deploy' ? 'Queuing…' : 'Deploy applications'}</button>
      </div>
    </>}

    {tab === 'applications' && <div className="deploymentTwoCol">
      <div className="deploymentPanel">
        <div className="deploymentPanelHead"><div><span>Catalog</span><strong>{editingAppId ? 'Edit application' : 'Add application'}</strong></div>{editingAppId && <button className="textButton" onClick={resetAppForm}>Cancel edit</button>}</div>
        <div className="deploymentForm">
          {!editingAppId && <div className={`storageConnectionCard ${storageState}`}>
            <div>
              <span className="storageDot" />
              <div><strong>{storageState === 'ready' ? 'Data Centre OneDrive connected' : storageState === 'checking' ? 'Checking Microsoft 365 storage' : 'Microsoft 365 storage connection required'}</strong><small>{storageMessage}</small></div>
            </div>
            {storageState !== 'ready' && storageState !== 'checking' && <button className="secondary compactButton" onClick={connectMicrosoftStorage}>Connect Microsoft 365</button>}
            {storageState === 'ready' && <button className="textButton" onClick={checkMicrosoftStorage}>Recheck</button>}
          </div>}

          {!editingAppId && <div
            className={`packageDropZone ${dragActive ? 'active' : ''} ${storageState !== 'ready' ? 'disabled' : ''}`}
            onDragEnter={event => { event.preventDefault(); if (storageState === 'ready') setDragActive(true) }}
            onDragOver={event => { event.preventDefault(); if (storageState === 'ready') setDragActive(true) }}
            onDragLeave={event => { event.preventDefault(); setDragActive(false) }}
            onDrop={event => {
              event.preventDefault(); setDragActive(false)
              if (storageState !== 'ready') { connectMicrosoftStorage(); return }
              const file = event.dataTransfer.files?.[0]
              if (file) preparePackage(file)
            }}
          >
            <input id="deployment-package-file" type="file" accept=".msi,.exe,.zip" disabled={storageState !== 'ready'} onChange={event => {
              const file = event.target.files?.[0]
              if (file) preparePackage(file)
              event.currentTarget.value = ''
            }} />
            <label htmlFor="deployment-package-file">
              <span className="dropIcon">↑</span>
              <strong>{busy === 'package' ? 'Preparing application package…' : storageState === 'ready' ? 'Drop installer or ZIP here' : 'Connect Microsoft 365 to upload packages'}</strong>
              <small>{storageState === 'ready' ? 'MSI, EXE or ZIP · stored in Data Centre OneDrive' : 'Packages remain private in CRECCOM Microsoft 365'}</small>
              <b>{storageState === 'ready' ? 'Browse files' : 'Connect first'}</b>
            </label>
            {busy === 'package' && <div className="packageUploadProgress"><div style={{ width: `${uploadProgress}%` }} /></div>}
          </div>}

          {(storageItemId || editingAppId) && <div className="packageSummary">
            <div><span>Package</span><strong>{storageFileName || packageFile?.name || 'Existing package'}</strong><small>{packageType.toUpperCase()} · {bytesLabel(fileSizeBytes)} · Data Centre OneDrive</small></div>
            <span className="packageReady">Ready</span>
          </div>}

          <div className="autoDetectedBanner">
            <strong>{metadataConfidence === 'detected' ? 'Detected automatically' : 'Confirm application details'}</strong>
            <span>Smart Console has captured the package type, size, SHA-256 and installer location. Confirm any fields it could not determine reliably.</span>
          </div>

          <label>Application name<input value={appName} onChange={e => { setAppName(e.target.value); setMetadataConfidence('confirm') }} placeholder="e.g. Google Chrome" /></label>
          <div className="deploymentFormRow">
            <label>Version<input value={appVersion} onChange={e => { setAppVersion(e.target.value); setMetadataConfidence('confirm') }} placeholder="e.g. 142.0" /></label>
            <label>Publisher<input value={appPublisher} onChange={e => { setAppPublisher(e.target.value); setMetadataConfidence('confirm') }} placeholder="Confirm publisher if not detected" /></label>
          </div>
          <div className="deploymentFormRow">
            <label>Installer type<select value={installerType} onChange={e => setInstallerType(e.target.value as 'msi' | 'exe')}><option value="msi">MSI</option><option value="exe">EXE</option></select></label>
            <label>Successful exit codes<input value={successCodes} onChange={e => setSuccessCodes(e.target.value)} placeholder="0,1641,3010" /></label>
          </div>
          {packageType === 'zip' && <label>Installer inside ZIP<input value={installerEntry} onChange={e => setInstallerEntry(e.target.value)} placeholder="setup.exe or installer.msi" /></label>}
          <details className="deploymentAdvanced">
            <summary>Advanced installation settings</summary>
            <label>Silent install arguments<input value={installArgs} onChange={e => setInstallArgs(e.target.value)} placeholder={installerType === 'msi' ? 'Additional MSI properties only; /qn is added automatically' : 'Required for EXE, e.g. /quiet /norestart'} /></label>
            {installerType === 'exe' && !installArgs.trim() && <div className="deploymentWarning"><strong>Silent command required</strong><span>Smart Console will not start an EXE deployment until unattended install arguments are supplied. This prevents installers waiting for user input for 45+ minutes.</span></div>}
            <label>Installation timeout (minutes)<input type="number" min={5} max={60} value={installTimeoutMinutes} onChange={e => setInstallTimeoutMinutes(Math.max(5, Math.min(60, Number(e.target.value) || 15)))} /></label>
            <label>SHA-256<input className="mono" value={sha256} readOnly placeholder="Calculated automatically" /></label>
            <label>IT notes<textarea value={appNotes} onChange={e => setAppNotes(e.target.value)} placeholder="Optional deployment notes" rows={3} /></label>
          </details>
          <div className="deploymentSecurityNote"><strong>Verified package</strong><span>The endpoint downloads from Data Centre OneDrive, verifies this exact SHA-256, then starts only the approved MSI/EXE installer.</span></div>
          <button className="primary" disabled={busy !== '' || !appName || !appVersion || !storageItemId || sha256.length !== 64 || (packageType === 'zip' && !installerEntry)} onClick={saveApp}>{busy === 'app' ? 'Saving…' : editingAppId ? 'Update application' : 'Add to catalog'}</button>
        </div>
      </div>

      <div className="deploymentPanel">
        <div className="deploymentPanelHead"><div><span>{apps.length} entries</span><strong>Approved application catalog</strong></div></div>
        <div className="catalogList">{apps.length === 0 ? <p className="deploymentEmpty">No deployment applications yet.</p> : apps.map(app => <div className="catalogRow" key={app.app_id}>
          <div className="catalogIcon">{app.name.slice(0, 1).toUpperCase()}</div>
          <div className="catalogIdentity"><strong>{app.name}</strong><span>{app.version} · {app.publisher || 'Publisher not specified'}</span><small>{packageHost(app.package_url)} · {bytesLabel(app.file_size_bytes)} · {app.install_timeout_minutes || 15} min timeout · SHA-256 {shortHash(app.sha256)}</small></div>
          {app.verification_status === 'verified'
            ? <span className="verifiedBadge">Verified</span>
            : ['queued','verifying'].includes(app.verification_status)
              ? <span className="hashReadyBadge">{app.verification_status === 'queued' ? 'Verification queued' : 'Verifying…'}</span>
              : <span className="verificationBadge">{app.verification_status === 'failed' ? 'Verification failed' : 'Needs verification'}</span>}
          {app.installer_type === 'exe' && !(app.install_args || '').trim() && <span className="verificationBadge">Needs silent command</span>}
          {app.installer_type === 'exe' && (app.install_args || '').trim() && <span className="silentReadyBadge">Unattended ready</span>}
          <span className="installerBadge">{(app.package_type || app.installer_type).toUpperCase()}</span>
          {app.verification_status !== 'verified' && <button className="linkButton" disabled={busy !== '' || ['queued','verifying'].includes(app.verification_status)} onClick={() => verifyExistingApp(app)}>{busy === `verify:${app.app_id}` ? 'Queuing…' : ['queued','verifying'].includes(app.verification_status) ? 'Verifying…' : 'Verify now'}</button>}
          <button className="linkButton" onClick={() => editApp(app)}>Edit</button>
        </div>)}</div>
      </div>
    </div>}

    {tab === 'groups' && <div className="deploymentTwoCol">
      <div className="deploymentPanel">
        <div className="deploymentPanelHead"><div><span>Reusable targeting</span><strong>{editingGroupId ? 'Edit endpoint group' : 'Create endpoint group'}</strong></div>{editingGroupId && <button className="textButton" onClick={resetGroupForm}>Cancel edit</button>}</div>
        <div className="deploymentForm">
          <label>Group name<input value={groupName} onChange={e => setGroupName(e.target.value)} placeholder="e.g. Zomba Office PCs" /></label>
          <label>Description<textarea value={groupDescription} onChange={e => setGroupDescription(e.target.value)} placeholder="Optional description" rows={2} /></label>
          <div className="groupMemberSelector">
            <div className="groupMemberSelectorHead"><strong>Select PCs</strong><span>{groupTerminals.size} selected</span></div>
            {terminals.filter(t => t.enrollment_status === 'active').map(terminal => <label key={terminal.terminal_id}>
              <input type="checkbox" checked={groupTerminals.has(terminal.terminal_id)} onChange={event => {
                const next = new Set(groupTerminals)
                if (event.target.checked) next.add(terminal.terminal_id); else next.delete(terminal.terminal_id)
                setGroupTerminals(next)
              }} />
              <span className="deploymentCheck" /><div><strong>{terminal.computer_name}</strong><small>{terminal.windows_user || 'Managed endpoint'}</small></div>
            </label>)}
          </div>
          <button className="primary" disabled={busy !== '' || !groupName} onClick={saveGroup}>{busy === 'group' ? 'Saving…' : editingGroupId ? 'Update group' : 'Create group'}</button>
        </div>
      </div>

      <div className="deploymentPanel">
        <div className="deploymentPanelHead"><div><span>{groups.length} groups</span><strong>Endpoint groups</strong></div></div>
        <div className="groupList">{groups.length === 0 ? <p className="deploymentEmpty">No endpoint groups yet.</p> : groups.map(group => {
          const groupMembers = members.filter(item => item.group_id === group.group_id)
          return <div className="groupRow" key={group.group_id}>
            <div><strong>{group.name}</strong><span>{group.description || 'No description'}</span><small>{groupMembers.length} PC{groupMembers.length === 1 ? '' : 's'}: {groupMembers.map(member => terminalMap.get(member.terminal_id)?.computer_name || member.terminal_id).join(', ') || 'None'}</small></div>
            <button className="linkButton" onClick={() => editGroup(group)}>Edit</button>
          </div>
        })}</div>
      </div>
    </div>}

    {tab === 'history' && <div className="deploymentPanel">
      <div className="deploymentPanelHead"><div><span>Live per-client status</span><strong>Application deployment history</strong></div><button className="secondary compactButton" onClick={load}>Refresh</button></div>
      <div className="tableWrap"><table className="deploymentHistory"><thead><tr><th>Requested</th><th>Deployment</th><th>Scope</th><th>Overall progress</th><th>Status</th></tr></thead><tbody>
        {batches.length === 0 ? <tr><td colSpan={5} className="empty">No application deployments yet.</td></tr> : batches.flatMap(batch => {
          const stats = batchStats(batch.batch_id)
          const rows = tasks.filter(task => task.batch_id === batch.batch_id)
          return [
            <tr key={batch.batch_id}>
              <td>{dateTime(batch.requested_at)}</td>
              <td><strong>{batch.name}</strong><small>{batch.app_count} app{batch.app_count === 1 ? '' : 's'} · {stats.total} task{stats.total === 1 ? '' : 's'}</small></td>
              <td>{batch.terminal_count} PC{batch.terminal_count === 1 ? '' : 's'}<small>{[...new Set(rows.map(task => terminalMap.get(task.terminal_id)?.computer_name || task.terminal_id))].slice(0, 4).join(', ')}{batch.terminal_count > 4 ? '…' : ''}</small></td>
              <td><div className="deploymentProgress"><div style={{ width: `${stats.progress}%` }} /></div><small><strong>{stats.progress}%</strong> · {stats.completed} successful · {stats.failed} failed · {stats.active} active</small></td>
              <td><span className={`batchStatus ${batch.status}`}>{batch.status.replace('_', ' ')}</span></td>
            </tr>,
            <tr className="clientProgressRow" key={`${batch.batch_id}-clients`}>
              <td colSpan={5}>
                <div className="clientProgressGrid">
                  {rows.length === 0 ? <span className="deploymentEmpty">Waiting for deployment tasks…</span> : rows.map(task => {
                    const terminal = terminalMap.get(task.terminal_id)
                    const app = appMap.get(task.app_id)
                    const lastProgress = task.last_progress_at ? new Date(task.last_progress_at).getTime() : 0
                    const stalled = ['pending', 'acknowledged'].includes(task.status) && Date.now() - lastProgress >= 5 * 60 * 1000
                    const canRetry = task.status === 'failed' || task.status === 'cancelled' || stalled
                    const percent = Math.max(0, Math.min(100, task.progress_percent || 0))
                    return <div className={`clientProgressCard ${task.status} ${stalled ? 'stalled' : ''}`} key={task.task_id}>
                      <div className="clientProgressHead">
                        <div><strong>{terminal?.computer_name || task.terminal_id}</strong><span>{app?.name || 'Application'} {app?.version || ''}</span></div>
                        <b>{percent}%</b>
                      </div>
                      <div className="clientProgressBar"><div style={{ width: `${percent}%` }} /></div>
                      <div className="clientProgressMeta">
                        <span className={`stageBadge ${task.progress_stage || task.status}`}>{stalled ? 'Delayed' : (task.progress_stage || task.status).replaceAll('_', ' ')}</span>
                        {task.defender_scan_status === 'clean' && <span className="defenderClean">Defender clean</span>}
                        <span>Attempt {task.attempt_count || 1}</span>
                        <span>Updated {dateTime(task.last_progress_at)}</span>
                      </div>
                      <p>{task.progress_message || task.message || (task.status === 'pending' ? 'Waiting for endpoint…' : 'Processing deployment…')}</p>
                      <div className="clientProgressActions">
                        {task.status === 'completed' && <span className="deploymentSuccess">Installation successful</span>}
                        {task.status === 'failed' && <span className="deploymentFailed">Installation failed</span>}
                        {stalled && <span className="deploymentDelayed">No progress for 5+ minutes</span>}
                        {canRetry && <button className="secondary compactButton" disabled={busy !== ''} onClick={() => retryDeploymentTask(task)}>{busy === `retry:${task.task_id}` ? 'Retrying…' : 'Force retry'}</button>}
                      </div>
                    </div>
                  })}
                </div>
              </td>
            </tr>,
          ]
        })}</tbody></table></div>
    </div>}
  </section>
}

function Metric({ label, value, detail }: { label: string, value: string, detail: string }) {
  return <div className="metric"><span>{label}</span><strong>{value}</strong><small>{detail}</small></div>
}
