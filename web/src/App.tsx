import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import type { Session } from '@supabase/supabase-js'
import { isBackendConfigured, supabase } from './lib/supabase'
import { EndpointManager, type EndpointView } from './EndpointManager'
import { SecuritySettings } from './SecuritySettings'
import { UsageMonitor } from './UsageMonitor'
import { EndpointServices } from './EndpointServices'
import { FileSharing, PublicShareRedirect } from './FileSharing'
import { SecurityOverview } from './SecurityOverview'
import { useAppDialog } from './AppDialogs'
import './lib/usageTelemetry'

type View = 'overview' | 'file-sharing' | 'transfers' | 'terminals' | 'devices' | 'enrollment' | 'usage-monitor' | 'services' | 'settings' | EndpointView
const DEFAULT_CONSOLE_USER = 'martinkabanda@creccommw.org'
const SMART_CONSOLE_GRAPH_TOKEN = 'smart-console:graph-provider-token'
const SMART_CONSOLE_GRAPH_TOKEN_EXPIRES = 'smart-console:graph-provider-token-expires'
const RETURN_TO_REMOTE_SUPPORT = 'smart-console:return-remote-support'

const rememberMicrosoftProviderToken = (session: Session | null) => {
  if (!session) {
    sessionStorage.removeItem(SMART_CONSOLE_GRAPH_TOKEN)
    sessionStorage.removeItem(SMART_CONSOLE_GRAPH_TOKEN_EXPIRES)
    return
  }

  if (session.provider_token) {
    sessionStorage.setItem(SMART_CONSOLE_GRAPH_TOKEN, session.provider_token)
    try {
      const [, payload] = session.provider_token.split('.')
      const json = JSON.parse(atob(payload.replace(/-/g, '+').replace(/_/g, '/')))
      if (json?.exp) sessionStorage.setItem(SMART_CONSOLE_GRAPH_TOKEN_EXPIRES, String(Number(json.exp) * 1000))
    } catch {
      sessionStorage.removeItem(SMART_CONSOLE_GRAPH_TOKEN_EXPIRES)
    }
  }
}

type Terminal = {
  terminal_id: string
  computer_name: string
  windows_user: string | null
  app_version: string | null
  enrollment_status: 'active' | 'revoked'
  last_seen_at: string
}

type AuditEvent = {
  event_id: string
  terminal_id: string
  timestamp: string
  kind: string
  direction: string | null
  windows_user: string | null
  device_name: string | null
  device_serial: string | null
  drive_letter: string | null
  volume_label: string | null
  file_name: string | null
  source_path: string | null
  destination_path: string | null
  file_size_bytes: number | null
  sha256: string | null
  evidence: string | null
}

type TerminalDevice = {
  terminal_id: string
  device_key: string
  drive_letter: string | null
  device_name: string | null
  device_serial: string | null
  volume_label: string | null
  file_system: string | null
  total_size_bytes: number | null
  connected_at: string | null
}

type MachineEnrollmentRequest = {
  request_id: string
  terminal_id: string
  computer_name: string
  app_version: string | null
  serial_number: string | null
  manufacturer: string | null
  model: string | null
  status: 'pending' | 'approved' | 'denied' | 'completed'
  requested_at: string
  last_seen_at: string
}

const bytes = (value?: number | null) => {
  if (!value) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  let size = value
  let unit = 0
  while (size >= 1024 && unit < units.length - 1) { size /= 1024; unit++ }
  return `${size >= 100 || unit === 0 ? Math.round(size) : size.toFixed(1)} ${units[unit]}`
}
const dateTime = (value?: string | null) => value ? new Date(value).toLocaleString() : '—'
const isOnline = (lastSeen: string) => Date.now() - new Date(lastSeen).getTime() < 600_000
const endpointViews = new Set<View>(['endpoints', 'smart-console', 'network', 'software', 'deployment', 'policies', 'remote', 'endpoint-audit'])

function App() {
  const { confirm, notify } = useAppDialog()
  const [session, setSession] = useState<Session | null>(null)
  const [view, setView] = useState<View>('overview')
  const [terminals, setTerminals] = useState<Terminal[]>([])
  const [events, setEvents] = useState<AuditEvent[]>([])
  const [devices, setDevices] = useState<TerminalDevice[]>([])
  const [machineEnrollmentRequests, setMachineEnrollmentRequests] = useState<MachineEnrollmentRequest[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [search, setSearch] = useState('')
  const [direction, setDirection] = useState('all')
  const [enrollmentLabel, setEnrollmentLabel] = useState('')
  const [enrollmentCode, setEnrollmentCode] = useState<{ code: string, expiresAt: string } | null>(null)
  const [adminBusy, setAdminBusy] = useState(false)
  const [endpointNavOpen, setEndpointNavOpen] = useState(true)
  const [usbNavOpen, setUsbNavOpen] = useState(true)
  const [sidebarVisible, setSidebarVisible] = useState(() => localStorage.getItem('smart-console:sidebar-visible') !== '0')
  const [profileName, setProfileName] = useState('')
  const [profileAvatarPath, setProfileAvatarPath] = useState<string | null>(null)
  const [profileAvatarUrl, setProfileAvatarUrl] = useState('')
  const [profileEditorOpen, setProfileEditorOpen] = useState(false)
  const [profileDraftName, setProfileDraftName] = useState('')
  const [profileDraftFile, setProfileDraftFile] = useState<File | null>(null)
  const [profileDraftPreviewUrl, setProfileDraftPreviewUrl] = useState('')
  const [profileRemoveAvatar, setProfileRemoveAvatar] = useState(false)
  const [profileSaving, setProfileSaving] = useState(false)
  const [internetOnline, setInternetOnline] = useState(() => navigator.onLine)
  const networkStatusRef = useRef<boolean | null>(null)

  useEffect(() => {
    localStorage.setItem('smart-console:sidebar-visible', sidebarVisible ? '1' : '0')
  }, [sidebarVisible])

  useEffect(() => {
    if (!supabase) return
    const restoreReturnView = (next: Session | null) => {
      if (!next) return
      if (sessionStorage.getItem(RETURN_TO_REMOTE_SUPPORT) === '1') {
        sessionStorage.removeItem(RETURN_TO_REMOTE_SUPPORT)
        setView('remote')
      }
    }

    supabase.auth.getSession().then(({ data }) => {
      rememberMicrosoftProviderToken(data.session)
      setSession(data.session)
      restoreReturnView(data.session)
    })
    const { data } = supabase.auth.onAuthStateChange((_event, next) => {
      rememberMicrosoftProviderToken(next)
      setSession(next)
      restoreReturnView(next)
    })
    return () => data.subscription.unsubscribe()
  }, [])


  const refreshProfile = useCallback(async () => {
    if (!supabase || !session) return
    const { data, error: profileError } = await supabase.rpc('get_console_profile')
    if (profileError || !data) return

    const displayName = String(data.displayName || session.user.user_metadata?.full_name || session.user.user_metadata?.name || 'Console Administrator')
    const avatarPath = data.avatarPath ? String(data.avatarPath) : null
    let avatarUrl = ''

    if (avatarPath) {
      const { data: signed } = await supabase.storage
        .from('console-profile-images')
        .createSignedUrl(avatarPath, 86400)
      avatarUrl = signed?.signedUrl || ''
    }

    setProfileName(displayName)
    setProfileAvatarPath(avatarPath)
    setProfileAvatarUrl(avatarUrl)
  }, [session])

  useEffect(() => {
    if (!session) {
      setProfileName('')
      setProfileAvatarPath(null)
      setProfileAvatarUrl('')
      return
    }
    void refreshProfile()
  }, [session, refreshProfile])


  useEffect(() => {
    if (!profileDraftFile) {
      setProfileDraftPreviewUrl('')
      return
    }
    const previewUrl = URL.createObjectURL(profileDraftFile)
    setProfileDraftPreviewUrl(previewUrl)
    return () => URL.revokeObjectURL(previewUrl)
  }, [profileDraftFile])

  const verifyInternetConnection = useCallback(async () => {
    let nextOnline = navigator.onLine
    if (nextOnline) {
      try {
        const controller = new AbortController()
        const timeout = window.setTimeout(() => controller.abort(), 6000)
        const response = await fetch(window.location.origin + '/?connectivity=' + Date.now(), {
          method: 'HEAD',
          cache: 'no-store',
          signal: controller.signal,
        })
        window.clearTimeout(timeout)
        nextOnline = response.ok
      } catch {
        nextOnline = false
      }
    }

    const previous = networkStatusRef.current
    networkStatusRef.current = nextOnline
    setInternetOnline(nextOnline)

    if (previous !== null && previous !== nextOnline) {
      void notify(nextOnline
        ? {
            title: 'Internet connection restored',
            message: 'The console is back online. Cloud-backed actions and live data can continue.',
            tone: 'success',
          }
        : {
            title: 'Internet connection lost',
            message: 'The console is offline. Cloud-backed actions may be delayed until the connection is restored.',
            tone: 'danger',
          })
    }
  }, [notify])

  useEffect(() => {
    void verifyInternetConnection()
    const onOffline = () => {
      const previous = networkStatusRef.current
      networkStatusRef.current = false
      setInternetOnline(false)
      if (previous !== null && previous !== false) {
        void notify({
          title: 'Internet connection lost',
          message: 'The console is offline. Cloud-backed actions may be delayed until the connection is restored.',
          tone: 'danger',
        })
      }
    }
    const onOnline = () => void verifyInternetConnection()
    window.addEventListener('offline', onOffline)
    window.addEventListener('online', onOnline)
    const timer = window.setInterval(() => void verifyInternetConnection(), 60000)
    return () => {
      window.removeEventListener('offline', onOffline)
      window.removeEventListener('online', onOnline)
      window.clearInterval(timer)
    }
  }, [notify, verifyInternetConnection])

  const loadData = async () => {
    if (!supabase || !session || endpointViews.has(view) || view === 'usage-monitor' || view === 'services' || view === 'file-sharing' || view === 'overview') return
    setLoading(true); setError('')

    try {
      if (view === 'transfers') {
        const [terminalResult, eventResult] = await Promise.all([
          supabase.from('terminals').select('terminal_id,computer_name,windows_user,app_version,enrollment_status,last_seen_at').order('last_seen_at', { ascending: false }),
          supabase.from('audit_events').select('event_id,terminal_id,timestamp,kind,direction,windows_user,device_name,device_serial,drive_letter,volume_label,file_name,source_path,destination_path,file_size_bytes,sha256,evidence').order('timestamp', { ascending: false }).limit(750),
        ])
        const firstError = terminalResult.error || eventResult.error
        if (firstError) setError(firstError.message)
        setTerminals((terminalResult.data ?? []) as Terminal[])
        setEvents((eventResult.data ?? []) as AuditEvent[])
        return
      }

      if (view === 'terminals' || view === 'devices') {
        const [terminalResult, deviceResult] = await Promise.all([
          supabase.from('terminals').select('terminal_id,computer_name,windows_user,app_version,enrollment_status,last_seen_at').order('last_seen_at', { ascending: false }),
          supabase.from('terminal_devices').select('terminal_id,device_key,drive_letter,device_name,device_serial,volume_label,file_system,total_size_bytes,connected_at').order('connected_at', { ascending: false }),
        ])
        const firstError = terminalResult.error || deviceResult.error
        if (firstError) setError(firstError.message)
        setTerminals((terminalResult.data ?? []) as Terminal[])
        setDevices((deviceResult.data ?? []) as TerminalDevice[])
        return
      }

      if (view === 'enrollment') {
        const [terminalResult, machineEnrollmentResult] = await Promise.all([
          supabase.from('terminals').select('terminal_id,computer_name,windows_user,app_version,enrollment_status,last_seen_at').order('last_seen_at', { ascending: false }),
          supabase.from('machine_enrollment_requests').select('request_id,terminal_id,computer_name,app_version,serial_number,manufacturer,model,status,requested_at,last_seen_at').order('requested_at', { ascending: false }).limit(100),
        ])
        const firstError = terminalResult.error || machineEnrollmentResult.error
        if (firstError) setError(firstError.message)
        setTerminals((terminalResult.data ?? []) as Terminal[])
        setMachineEnrollmentRequests((machineEnrollmentResult.data ?? []) as MachineEnrollmentRequest[])
        return
      }

      const terminalResult = await supabase.from('terminals')
        .select('terminal_id,computer_name,windows_user,app_version,enrollment_status,last_seen_at')
        .order('last_seen_at', { ascending: false })
      if (terminalResult.error) setError(terminalResult.error.message)
      setTerminals((terminalResult.data ?? []) as Terminal[])
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    if (!session || endpointViews.has(view) || view === 'usage-monitor' || view === 'services' || view === 'file-sharing' || view === 'overview') return
    void loadData()

    const refresh = () => {
      if (document.visibilityState === 'visible') void loadData()
    }
    const timer = window.setInterval(refresh, 300_000)
    document.addEventListener('visibilitychange', refresh)
    return () => {
      window.clearInterval(timer)
      document.removeEventListener('visibilitychange', refresh)
    }
  }, [session, view])

  const terminalMap = useMemo(() => new Map(terminals.map(item => [item.terminal_id, item])), [terminals])
  const onlineCount = terminals.filter(item => isOnline(item.last_seen_at)).length
  const today = new Date().toDateString()
  const transfersToday = events.filter(item => ['UsbWrite', 'UsbRead'].includes(item.kind) && new Date(item.timestamp).toDateString() === today).length
  const filteredEvents = useMemo(() => {
    const query = search.trim().toLowerCase()
    return events.filter(item => {
      if (direction !== 'all' && item.direction !== direction) return false
      if (!query) return true
      const terminal = terminalMap.get(item.terminal_id)
      return [item.file_name, item.device_name, item.device_serial, item.windows_user, item.source_path, item.destination_path, terminal?.computer_name]
        .some(value => value?.toLowerCase().includes(query))
    })
  }, [events, search, direction, terminalMap])

  const createEnrollment = async () => {
    if (!supabase) return
    setAdminBusy(true); setError(''); setEnrollmentCode(null)
    const { data, error: functionError } = await supabase.functions.invoke('terminal-admin', { body: { action: 'create_enrollment', label: enrollmentLabel.trim() } })
    if (functionError || data?.error) {
      const message = data?.error || functionError?.message || 'Could not create enrollment code'
      setError(message)
      await notify({ title: 'Enrollment code failed', message, tone: 'danger' })
    } else {
      setEnrollmentCode(data)
      await notify({
        title: 'Enrollment code created',
        message: 'A one-time terminal enrollment code was generated successfully.',
        tone: 'success',
      })
    }
    setAdminBusy(false)
  }

  const decideMachineEnrollment = async (requestId: string, approve: boolean) => {
    if (!supabase) return
    const request = machineEnrollmentRequests.find(item => item.request_id === requestId)
    const accepted = await confirm({
      title: approve ? 'Approve machine enrollment?' : 'Deny machine enrollment?',
      message: `${request?.computer_name || 'This machine'} will be ${approve ? 'approved for managed Smart Console access' : 'denied access to Smart Console'}.`,
      confirmLabel: approve ? 'Approve machine' : 'Deny machine',
      tone: approve ? 'info' : 'warning',
    })
    if (!accepted) return

    setAdminBusy(true); setError('')
    const { data, error: functionError } = await supabase.functions.invoke('terminal-admin', {
      body: {
        action: approve ? 'approve_machine_enrollment' : 'deny_machine_enrollment',
        requestId,
      },
    })
    if (functionError || data?.error) {
      const message = data?.error || functionError?.message || 'Could not update machine enrollment'
      setError(message)
      await notify({ title: 'Enrollment update failed', message, tone: 'danger' })
    } else {
      await loadData()
      await notify({
        title: approve ? 'Machine approved' : 'Machine denied',
        message: `${request?.computer_name || 'The machine'} was updated successfully.`,
        tone: 'success',
      })
    }
    setAdminBusy(false)
  }

  const revokeTerminal = async (terminalId: string) => {
    if (!supabase) return
    const accepted = await confirm({
      title: 'Revoke terminal?',
      message: 'This terminal will stop future uploads and will need administrator action before it can reconnect.',
      confirmLabel: 'Revoke terminal',
      tone: 'danger',
    })
    if (!accepted) return

    setAdminBusy(true); setError('')
    const { data, error: functionError } = await supabase.functions.invoke('terminal-admin', { body: { action: 'revoke_terminal', terminalId } })
    if (functionError || data?.error) {
      const message = data?.error || functionError?.message || 'Could not revoke terminal'
      setError(message)
      await notify({ title: 'Terminal revocation failed', message, tone: 'danger' })
    } else {
      await loadData()
      await notify({ title: 'Terminal revoked', message: 'The terminal has been revoked successfully.', tone: 'success' })
    }
    setAdminBusy(false)
  }

  const closeAccountMenu = () => {
    document.querySelector<HTMLDetailsElement>('details.accountMenu')?.removeAttribute('open')
  }

  const openProfileEditor = () => {
    closeAccountMenu()
    setProfileDraftName(profileName || session?.user.user_metadata?.full_name || session?.user.user_metadata?.name || 'Console Administrator')
    setProfileDraftFile(null)
    setProfileRemoveAvatar(false)
    setProfileEditorOpen(true)
  }

  const saveProfile = async () => {
    if (!supabase || !session || profileSaving) return
    const cleanName = profileDraftName.trim()
    if (!cleanName) {
      await notify({ title: 'Display name required', message: 'Enter a display name before saving the profile.', tone: 'warning' })
      return
    }

    if (profileDraftFile && !['image/jpeg','image/png','image/webp'].includes(profileDraftFile.type)) {
      await notify({ title: 'Unsupported profile image', message: 'Use a JPG, PNG or WebP image.', tone: 'warning' })
      return
    }
    if (profileDraftFile && profileDraftFile.size > 5 * 1024 * 1024) {
      await notify({ title: 'Profile image too large', message: 'Choose an image smaller than 5 MB.', tone: 'warning' })
      return
    }

    setProfileSaving(true)
    let nextAvatarPath = profileRemoveAvatar ? null : profileAvatarPath

    try {
      if (profileDraftFile) {
        const extension = profileDraftFile.type === 'image/png' ? 'png' : profileDraftFile.type === 'image/webp' ? 'webp' : 'jpg'
        nextAvatarPath = session.user.id + '/avatar.' + extension
        const { error: uploadError } = await supabase.storage
          .from('console-profile-images')
          .upload(nextAvatarPath, profileDraftFile, {
            upsert: true,
            contentType: profileDraftFile.type,
            cacheControl: '3600',
          })
        if (uploadError) throw uploadError
      }

      if (profileRemoveAvatar && profileAvatarPath) {
        const { error: removeError } = await supabase.storage
          .from('console-profile-images')
          .remove([profileAvatarPath])
        if (removeError) throw removeError
      }

      const { error: updateError } = await supabase.rpc('update_console_profile', {
        p_display_name: cleanName,
        p_avatar_path: nextAvatarPath,
      })
      if (updateError) throw updateError

      await refreshProfile()
      setProfileEditorOpen(false)
      await notify({
        title: 'Profile updated',
        message: 'Your console profile has been saved successfully.',
        tone: 'success',
      })
    } catch (profileError) {
      await notify({
        title: 'Profile update failed',
        message: profileError instanceof Error ? profileError.message : 'The profile could not be updated.',
        tone: 'danger',
      })
    } finally {
      setProfileSaving(false)
    }
  }

  const signOut = async () => {
    if (!supabase) return
    closeAccountMenu()
    const accepted = await confirm({
      title: 'Sign out of Smart Console?',
      message: 'Your administrator session will end on this browser.',
      confirmLabel: 'Sign out',
      tone: 'warning',
    })
    if (!accepted) return
    const { error: signOutError } = await supabase.auth.signOut()
    if (signOutError) {
      await notify({ title: 'Sign out failed', message: signOutError.message, tone: 'danger' })
      return
    }
    await notify({ title: 'Signed out', message: 'Your Smart Console administrator session has ended.', tone: 'success' })
  }

  const publicShareToken = window.location.pathname.match(/^\/share\/([a-f0-9]{36})\/?$/i)?.[1]
  if (publicShareToken) return <PublicShareRedirect token={publicShareToken.toLowerCase()} />

  if (!isBackendConfigured) return <ConfigurationMissing />
  if (!session) return <Login />
  if (session.user.email?.toLowerCase() !== DEFAULT_CONSOLE_USER) return <AccessDenied email={session.user.email} />

  const titles: Record<View, string> = {
    overview: 'Security Overview', 'file-sharing': 'File Sharing', transfers: 'USB Transfers', terminals: 'Client Terminals', devices: 'USB Devices', enrollment: 'Terminal Enrollment', 'usage-monitor': 'Usage Monitor', services: 'Services',
    endpoints: 'Managed Endpoints', 'smart-console': 'Smart Console', network: 'Network Track', software: 'Software Inventory', deployment: 'App Deployment', policies: 'Endpoint Policies', remote: 'Remote Support', 'endpoint-audit': 'Endpoint Audit Logs', settings: 'Settings',
  }
  const endpointView = endpointViews.has(view)
  const endpointContext = endpointView || view === 'enrollment' || view === 'usage-monitor' || view === 'services'
  const accountName = String(
    profileName ||
    session.user.user_metadata?.full_name ||
    session.user.user_metadata?.name ||
    'Console Administrator'
  )
  const accountInitials = accountName
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 2)
    .map(part => part.charAt(0).toUpperCase())
    .join('') || 'CA'

  return <div className={sidebarVisible ? 'shell' : 'shell sidebarHidden'}>
    {sidebarVisible && <aside className="sidebar">
      <div className="brand"><img className="brandLogo" src="/creccom-round-logo.png" alt="CRECCOM" /><div><strong>CRECCOM</strong><span>Smart Console</span></div></div>
      <nav>
        <NavButton active={view === 'overview'} onClick={() => setView('overview')}>Security Overview</NavButton>
        <NavButton active={view === 'file-sharing'} onClick={() => setView('file-sharing')}>File Sharing</NavButton>
        <NavSectionButton open={endpointNavOpen} onClick={() => setEndpointNavOpen(value => !value)}>Endpoint Manager</NavSectionButton>
        {endpointNavOpen && <div className="navGroup">
          <NavButton active={view === 'endpoints'} onClick={() => setView('endpoints')}>Managed Endpoints</NavButton>
          <NavButton active={view === 'smart-console'} onClick={() => setView('smart-console')}>Smart Console</NavButton>
          <NavButton active={view === 'network'} onClick={() => setView('network')}>Network Track</NavButton>
          <NavButton active={view === 'usage-monitor'} onClick={() => setView('usage-monitor')}>Usage Monitor</NavButton>
          <NavButton active={view === 'services'} onClick={() => setView('services')}>Services</NavButton>
          <NavButton active={view === 'software'} onClick={() => setView('software')}>Software</NavButton>
          <NavButton active={view === 'deployment'} onClick={() => setView('deployment')}>App Deployment</NavButton>
          <NavButton active={view === 'policies'} onClick={() => setView('policies')}>Policies</NavButton>
          <NavButton active={view === 'remote'} onClick={() => setView('remote')}>Remote Support</NavButton>
          <NavButton active={view === 'endpoint-audit'} onClick={() => setView('endpoint-audit')}>Audit Logs</NavButton>
          <NavButton active={view === 'enrollment'} onClick={() => setView('enrollment')}>Terminal Enrollment</NavButton>
        </div>}
        <NavSectionButton open={usbNavOpen} onClick={() => setUsbNavOpen(value => !value)}>USB Audit</NavSectionButton>
        {usbNavOpen && <div className="navGroup">
          <NavButton active={view === 'transfers'} onClick={() => setView('transfers')}>USB Transfers</NavButton>
          <NavButton active={view === 'terminals'} onClick={() => setView('terminals')}>Client Terminals</NavButton>
          <NavButton active={view === 'devices'} onClick={() => setView('devices')}>USB Devices</NavButton>
        </div>}
        <NavButton active={view === 'settings'} onClick={() => setView('settings')}>Settings</NavButton>
      </nav>
    </aside>}

    <main className="main">
      <header className="topbar">
        <div className="topbarLead">
          <button className="sidebarToggle" type="button" aria-label={sidebarVisible ? 'Hide sidebar' : 'Show sidebar'} title={sidebarVisible ? 'Hide sidebar' : 'Show sidebar'} onClick={() => setSidebarVisible(value => !value)}>
            <span></span><span></span><span></span>
          </button>
          <div><h1>{titles[view]}</h1><p>{endpointContext ? 'Central Windows endpoint inventory, enrollment, software policy and support controls' : view === 'overview' ? 'Whole-system security, endpoint health and operations summary' : view === 'file-sharing' ? 'Upload to CRECCOM OneDrive and issue controlled download links' : view === 'settings' ? 'Administrator controls for protected endpoint connections' : 'USB Audit module — endpoint removable-media activity'}</p></div>
        </div>
        <div className="topbarActions">
          {!endpointView && view !== 'overview' && view !== 'usage-monitor' && view !== 'services' && view !== 'file-sharing' && <button className="secondary topbarRefresh" onClick={() => void loadData()}>Refresh</button>}
          <div className={internetOnline ? 'connectionIndicator online' : 'connectionIndicator offline'} title={internetOnline ? 'Internet connected' : 'Internet offline'} aria-label={internetOnline ? 'Internet connected' : 'Internet offline'}>
            <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M2.5 8.8a15 15 0 0 1 19 0M5.8 12.1a10.3 10.3 0 0 1 12.4 0M9.1 15.5a5.5 5.5 0 0 1 5.8 0M12 19h.01" /></svg>
          </div>
          <details className="accountMenu">
            <summary className="accountTrigger" aria-label="Open account menu">
              {profileAvatarUrl ? <img className="accountAvatar accountAvatarImage" src={profileAvatarUrl} alt={accountName} /> : <span className="accountAvatar">{accountInitials}</span>}
              <span className="accountIdentity">
                <strong>{accountName}</strong>
                <small>{session.user.email}</small>
              </span>
              <span className="accountChevron">⌄</span>
            </summary>
            <div className="accountDropdown">
              <div className="accountDropdownHeader">
                {profileAvatarUrl ? <img className="accountAvatar largeAvatar accountAvatarImage" src={profileAvatarUrl} alt={accountName} /> : <span className="accountAvatar largeAvatar">{accountInitials}</span>}
                <div>
                  <strong>{accountName}</strong>
                  <span>{session.user.email}</span>
                  <small>CRECCOM Smart Console</small>
                </div>
              </div>
              <div className="accountDropdownDivider" />
              <button className="accountDropdownItem" type="button" onClick={openProfileEditor}>
                <span className="accountMenuIcon">✎</span>
                <span><strong>Edit profile</strong><small>Name and profile image</small></span>
              </button>
              <button className="accountDropdownItem" type="button" onClick={() => { closeAccountMenu(); setView('settings') }}>
                <span className="accountMenuIcon">⚙</span>
                <span><strong>Settings</strong><small>Security and administrator controls</small></span>
              </button>
              <button className="accountDropdownItem signOutItem" type="button" onClick={() => void signOut()}>
                <span className="accountMenuIcon">↪</span>
                <span><strong>Sign out</strong><small>End this administrator session</small></span>
              </button>
            </div>
          </details>
        </div>
      </header>
      {view === 'overview' ? <SecurityOverview onNavigate={destination => setView(destination)} /> : view === 'file-sharing' ? <FileSharing session={session} /> : view === 'usage-monitor' ? <UsageMonitor /> : view === 'services' ? <EndpointServices /> : view === 'settings' ? <SecuritySettings terminals={terminals} /> : endpointView ? <EndpointManager view={view as EndpointView} /> : <>
        {error && <div className="errorBanner">{error}</div>}
        {loading && terminals.length === 0 ? <div className="loading">Loading security data…</div> : <>
          {view === 'transfers' && <section><div className="filters"><input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search file, terminal, device, user or path" /><select value={direction} onChange={e => setDirection(e.target.value)}><option value="all">All directions</option><option value="PcToUsb">PC → USB</option><option value="UsbToPc">USB → PC</option></select><span>{filteredEvents.length} records</span></div><Panel title="USB transfer records"><TransferTable events={filteredEvents} terminals={terminalMap} /></Panel></section>}
          {view === 'terminals' && <Panel title="Installed security client terminals"><div className="tableWrap"><table><thead><tr><th>Status</th><th>Computer</th><th>User</th><th>Version</th><th>Last seen</th><th>USBs</th></tr></thead><tbody>{terminals.map(item => <tr key={item.terminal_id}><td>{item.enrollment_status === 'revoked' ? <span className="status offline"><i />Revoked</span> : <Status online={isOnline(item.last_seen_at)} />}</td><td><strong>{item.computer_name}</strong><small>{item.terminal_id}</small></td><td>{item.windows_user || '—'}</td><td>{item.app_version || '—'}</td><td>{dateTime(item.last_seen_at)}</td><td>{devices.filter(device => device.terminal_id === item.terminal_id).length} {item.enrollment_status !== 'revoked' && <button className="linkButton" disabled={adminBusy} onClick={() => revokeTerminal(item.terminal_id)}>Revoke</button>}</td></tr>)}</tbody></table></div></Panel>}
          {view === 'devices' && <Panel title="Currently connected USB storage"><div className="tableWrap"><table><thead><tr><th>Terminal</th><th>Drive</th><th>Device</th><th>Serial</th><th>Volume</th><th>Format</th><th>Capacity</th><th>Connected</th></tr></thead><tbody>{devices.map(item => <tr key={`${item.terminal_id}-${item.device_key}`}><td>{terminalMap.get(item.terminal_id)?.computer_name || item.terminal_id}</td><td><strong>{item.drive_letter || '—'}</strong></td><td>{item.device_name || 'USB storage'}</td><td className="mono">{item.device_serial || '—'}</td><td>{item.volume_label || '—'}</td><td>{item.file_system || '—'}</td><td>{bytes(item.total_size_bytes)}</td><td>{dateTime(item.connected_at)}</td></tr>)}</tbody></table></div></Panel>}
          {view === 'enrollment' && <section className="enrollmentPage">
            <Panel title="Pending machine connections">
              <div className="panelBody">
                <p>New Smart Console installations register from the Windows service before any user signs in. Approve a machine once and it will receive its own endpoint credential for future boot-time connections.</p>
                <div className="machineEnrollmentList">
                  {machineEnrollmentRequests.filter(item => item.status === 'pending').length === 0
                    ? <div className="empty machineEnrollmentEmpty">No machines are waiting for approval.</div>
                    : machineEnrollmentRequests.filter(item => item.status === 'pending').map(item => <div className="machineEnrollmentRow" key={item.request_id}>
                        <div className="machineEnrollmentIdentity">
                          <strong>{item.computer_name}</strong>
                          <span>{[item.manufacturer, item.model].filter(Boolean).join(' ') || 'Windows endpoint'}</span>
                          <small>{item.serial_number ? `Serial: ${item.serial_number}` : item.terminal_id}</small>
                        </div>
                        <div className="machineEnrollmentMeta">
                          <span>Agent {item.app_version || '—'}</span>
                          <small>Requested {dateTime(item.requested_at)}</small>
                          <small>Last contact {dateTime(item.last_seen_at)}</small>
                        </div>
                        <div className="machineEnrollmentActions">
                          <button className="secondary compactButton" disabled={adminBusy} onClick={() => decideMachineEnrollment(item.request_id, false)}>Deny</button>
                          <button className="primary compactButton" disabled={adminBusy} onClick={() => decideMachineEnrollment(item.request_id, true)}>Approve</button>
                        </div>
                      </div>)}
                </div>
              </div>
            </Panel>

            <div className="enrollmentGrid">
              <Panel title="Manual one-time enrollment code"><div className="panelBody"><p>This remains available for exceptional/manual enrollment. Normal new installations should now register themselves automatically.</p><label>Terminal label (optional)</label><input value={enrollmentLabel} onChange={event => setEnrollmentLabel(event.target.value)} placeholder="e.g. Zomba reception PC" maxLength={100} /><button className="primary" disabled={adminBusy} onClick={createEnrollment}>{adminBusy ? 'Creating…' : 'Generate enrollment code'}</button>{enrollmentCode && <div className="enrollmentResult"><span>Copy this code into the terminal’s “Terminal enrollment token” field:</span><strong className="mono">{enrollmentCode.code}</strong><small>Expires {dateTime(enrollmentCode.expiresAt)}. It will be replaced automatically after the first successful sync.</small></div>}</div></Panel>
              <Panel title="Machine connection model"><ol className="steps"><li>Install Smart Console as administrator.</li><li>The Smart Console Agent starts with Windows as LocalSystem.</li><li>The PC registers here automatically, even at the lock screen.</li><li>IT approves the machine once.</li><li>The service receives its own machine credential and reconnects at every boot without a Windows or Microsoft 365 user sign-in.</li></ol></Panel>
            </div>
          </section>}
        </>}
      </>}
    </main>

    {profileEditorOpen && <div className="profileEditorBackdrop" role="presentation">
      <div className="profileEditorCard" role="dialog" aria-modal="true" aria-labelledby="profile-editor-title">
        <div className="profileEditorHeader">
          <div>
            <h2 id="profile-editor-title">Edit profile</h2>
            <p>Update how your administrator profile appears in Smart Console.</p>
          </div>
          <button type="button" className="profileEditorClose" aria-label="Close profile editor" disabled={profileSaving} onClick={() => setProfileEditorOpen(false)}>×</button>
        </div>

        <div className="profileEditorBody">
          <div className="profilePhotoEditor">
            {profileDraftFile && profileDraftPreviewUrl
              ? <img className="profileEditorAvatar" src={profileDraftPreviewUrl} alt="Selected profile" />
              : profileRemoveAvatar || !profileAvatarUrl
                ? <div className="profileEditorAvatar fallback">{accountInitials}</div>
                : <img className="profileEditorAvatar" src={profileAvatarUrl} alt={accountName} />}
            <div>
              <label className="profilePhotoButton" htmlFor="profile-photo-input">Choose photo</label>
              <input
                id="profile-photo-input"
                type="file"
                accept="image/jpeg,image/png,image/webp"
                disabled={profileSaving}
                onChange={event => {
                  setProfileDraftFile(event.target.files?.[0] || null)
                  if (event.target.files?.[0]) setProfileRemoveAvatar(false)
                }}
              />
              {(profileAvatarPath || profileDraftFile) && <button type="button" className="profileRemoveButton" disabled={profileSaving} onClick={() => {
                setProfileDraftFile(null)
                setProfileRemoveAvatar(true)
              }}>Remove photo</button>}
              <small>JPG, PNG or WebP · maximum 5 MB</small>
            </div>
          </div>

          <label className="profileField">
            <span>Display name</span>
            <input value={profileDraftName} maxLength={100} disabled={profileSaving} onChange={event => setProfileDraftName(event.target.value)} />
          </label>
          <label className="profileField">
            <span>Email address</span>
            <input value={session.user.email || ''} disabled readOnly />
            <small>Managed by your Microsoft account.</small>
          </label>
        </div>

        <div className="profileEditorActions">
          <button className="secondary" type="button" disabled={profileSaving} onClick={() => setProfileEditorOpen(false)}>Cancel</button>
          <button className="primary" type="button" disabled={profileSaving || !profileDraftName.trim()} onClick={() => void saveProfile()}>{profileSaving ? 'Saving…' : 'Save profile'}</button>
        </div>
      </div>
    </div>}
  </div>
}

function Login() {
  const [message, setMessage] = useState('')
  const signIn = async () => {
    if (!supabase) return
    setMessage('Redirecting to Microsoft…')
    const { error } = await supabase.auth.signInWithOAuth({ provider: 'azure', options: { scopes: 'openid profile email offline_access User.Read User.Read.All Files.ReadWrite.All', redirectTo: window.location.origin } })
    if (error) setMessage(error.message)
  }
  return <div className="loginPage"><div className="loginCard"><img className="brandLogo large" src="/creccom-round-logo.png" alt="CRECCOM" /><h1>Smart Console</h1><p>Sign in with the authorized CRECCOM Microsoft account.</p><button className="microsoftButton" type="button" onClick={signIn}><span className="microsoftMark"><i /><i /><i /><i /></span>Continue with Microsoft</button><div className="authorizedAccount">Authorized account: <strong>{DEFAULT_CONSOLE_USER}</strong></div>{message && <div className="formMessage">{message}</div>}</div></div>
}
function AccessDenied({ email }: { email?: string }) { return <div className="loginPage"><div className="loginCard"><img className="brandLogo large" src="/creccom-round-logo.png" alt="CRECCOM" /><h1>Access not authorized</h1><p>{email || 'This Microsoft account'} is not approved for CRECCOM Smart Console.</p><button className="secondary fullWidth" onClick={() => supabase?.auth.signOut()}>Sign out and use another account</button></div></div> }
function ConfigurationMissing() { return <div className="loginPage"><div className="loginCard"><img className="brandLogo large" src="/creccom-round-logo.png" alt="CRECCOM" /><h1>Smart Console</h1><p>The Smart Console source is ready, but its Supabase environment variables have not been configured yet.</p></div></div> }
function NavSectionButton({ open, onClick, children }: { open: boolean, onClick: () => void, children: React.ReactNode }) { return <button className="navSectionToggle" onClick={onClick}><span>{children}</span><span className={open ? 'navChevron open' : 'navChevron'}>›</span></button> }
function NavButton({ active, onClick, children }: { active: boolean, onClick: () => void, children: React.ReactNode }) { return <button className={active ? 'nav active' : 'nav'} onClick={onClick}>{children}</button> }
function Metric({ label, value, detail }: { label: string, value: string, detail: string }) { return <div className="metric"><span>{label}</span><strong>{value}</strong><small>{detail}</small></div> }
function Panel({ title, children }: { title: string, children: React.ReactNode }) { return <div className="panel"><div className="panelTitle">{title}</div>{children}</div> }
function Status({ online }: { online: boolean }) { return <span className={online ? 'status online' : 'status offline'}><i />{online ? 'Online' : 'Offline'}</span> }
function TransferTable({ events, terminals, compact = false }: { events: AuditEvent[], terminals: Map<string, Terminal>, compact?: boolean }) {
  return <div className="tableWrap"><table><thead><tr><th>Time</th><th>Terminal</th><th>Direction</th><th>Device</th><th>File</th>{!compact && <><th>Source</th><th>Destination</th><th>Size</th><th>SHA-256</th></>}</tr></thead><tbody>{events.length === 0 ? <tr><td colSpan={compact ? 5 : 9} className="empty">No matching transfer records.</td></tr> : events.map(item => <tr key={item.event_id}><td>{dateTime(item.timestamp)}</td><td>{terminals.get(item.terminal_id)?.computer_name || item.terminal_id}</td><td><span className="direction">{item.direction === 'UsbToPc' ? 'USB → PC' : item.direction === 'PcToUsb' ? 'PC → USB' : item.direction || '—'}</span></td><td>{item.device_name || item.drive_letter || 'USB'}</td><td><strong>{item.file_name || '—'}</strong></td>{!compact && <><td className="path">{item.source_path || '—'}</td><td className="path">{item.destination_path || '—'}</td><td>{bytes(item.file_size_bytes)}</td><td className="mono">{item.sha256 ? `${item.sha256.slice(0, 14)}…` : '—'}</td></>}</tr>)}</tbody></table></div>
}

export default App
