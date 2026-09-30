import { useEffect, useMemo, useState } from 'react'
import type { Session } from '@supabase/supabase-js'
import { isBackendConfigured, supabase } from './lib/supabase'
import { EndpointManager, type EndpointView } from './EndpointManager'
import { SecuritySettings } from './SecuritySettings'

type View = 'overview' | 'transfers' | 'terminals' | 'devices' | 'enrollment' | 'settings' | EndpointView
const DEFAULT_CONSOLE_USER = 'martinkabanda@creccommw.org'
const SMART_CONSOLE_GRAPH_TOKEN = 'smart-console:graph-provider-token'
const SMART_CONSOLE_GRAPH_TOKEN_EXPIRES = 'smart-console:graph-provider-token-expires'

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
const isOnline = (lastSeen: string) => Date.now() - new Date(lastSeen).getTime() < 45_000
const endpointViews = new Set<View>(['endpoints', 'smart-console', 'network', 'software', 'deployment', 'policies', 'remote', 'endpoint-audit'])

function App() {
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

  useEffect(() => {
    localStorage.setItem('smart-console:sidebar-visible', sidebarVisible ? '1' : '0')
  }, [sidebarVisible])

  useEffect(() => {
    if (!supabase) return
    supabase.auth.getSession().then(({ data }) => {
      rememberMicrosoftProviderToken(data.session)
      setSession(data.session)
    })
    const { data } = supabase.auth.onAuthStateChange((_event, next) => {
      rememberMicrosoftProviderToken(next)
      setSession(next)
    })
    return () => data.subscription.unsubscribe()
  }, [])

  const loadData = async () => {
    if (!supabase || !session) return
    setLoading(true); setError('')
    const [terminalResult, eventResult, deviceResult, machineEnrollmentResult] = await Promise.all([
      supabase.from('terminals').select('*').order('last_seen_at', { ascending: false }),
      supabase.from('audit_events').select('*').order('timestamp', { ascending: false }).limit(750),
      supabase.from('terminal_devices').select('*').order('connected_at', { ascending: false }),
      supabase.from('machine_enrollment_requests').select('request_id,terminal_id,computer_name,app_version,serial_number,manufacturer,model,status,requested_at,last_seen_at').order('requested_at', { ascending: false }).limit(100),
    ])
    const firstError = terminalResult.error || eventResult.error || deviceResult.error || machineEnrollmentResult.error
    if (firstError) setError(firstError.message)
    setTerminals((terminalResult.data ?? []) as Terminal[])
    setEvents((eventResult.data ?? []) as AuditEvent[])
    setDevices((deviceResult.data ?? []) as TerminalDevice[])
    setMachineEnrollmentRequests((machineEnrollmentResult.data ?? []) as MachineEnrollmentRequest[])
    setLoading(false)
  }

  useEffect(() => {
    if (!session) return
    loadData()
    const timer = window.setInterval(loadData, 15_000)
    return () => window.clearInterval(timer)
  }, [session])

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
    if (functionError || data?.error) setError(data?.error || functionError?.message || 'Could not create enrollment code')
    else setEnrollmentCode(data)
    setAdminBusy(false)
  }

  const decideMachineEnrollment = async (requestId: string, approve: boolean) => {
    if (!supabase) return
    setAdminBusy(true); setError('')
    const { data, error: functionError } = await supabase.functions.invoke('terminal-admin', {
      body: {
        action: approve ? 'approve_machine_enrollment' : 'deny_machine_enrollment',
        requestId,
      },
    })
    if (functionError || data?.error) {
      setError(data?.error || functionError?.message || 'Could not update machine enrollment')
    } else {
      await loadData()
    }
    setAdminBusy(false)
  }

  const revokeTerminal = async (terminalId: string) => {
    if (!supabase || !window.confirm('Revoke this terminal and stop future uploads?')) return
    setAdminBusy(true); setError('')
    const { data, error: functionError } = await supabase.functions.invoke('terminal-admin', { body: { action: 'revoke_terminal', terminalId } })
    if (functionError || data?.error) setError(data?.error || functionError?.message || 'Could not revoke terminal')
    else await loadData()
    setAdminBusy(false)
  }

  if (!isBackendConfigured) return <ConfigurationMissing />
  if (!session) return <Login />
  if (session.user.email?.toLowerCase() !== DEFAULT_CONSOLE_USER) return <AccessDenied email={session.user.email} />

  const titles: Record<View, string> = {
    overview: 'Security Overview', transfers: 'USB Transfers', terminals: 'Client Terminals', devices: 'USB Devices', enrollment: 'Terminal Enrollment',
    endpoints: 'Managed Endpoints', 'smart-console': 'Smart Console', network: 'Network Track', software: 'Software Inventory', deployment: 'App Deployment', policies: 'Endpoint Policies', remote: 'Remote Support', 'endpoint-audit': 'Endpoint Audit Logs', settings: 'Settings',
  }
  const endpointView = endpointViews.has(view)
  const endpointContext = endpointView || view === 'enrollment'

  return <div className={sidebarVisible ? 'shell' : 'shell sidebarHidden'}>
    {sidebarVisible && <aside className="sidebar">
      <div className="brand"><img className="brandLogo" src="/creccom-round-logo.png" alt="CRECCOM" /><div><strong>CRECCOM</strong><span>Smart Console</span></div></div>
      <nav>
        <NavButton active={view === 'overview'} onClick={() => setView('overview')}>Security Overview</NavButton>
        <NavSectionButton open={endpointNavOpen} onClick={() => setEndpointNavOpen(value => !value)}>Endpoint Manager</NavSectionButton>
        {endpointNavOpen && <div className="navGroup">
          <NavButton active={view === 'endpoints'} onClick={() => setView('endpoints')}>Managed Endpoints</NavButton>
          <NavButton active={view === 'smart-console'} onClick={() => setView('smart-console')}>Smart Console</NavButton>
          <NavButton active={view === 'network'} onClick={() => setView('network')}>Network Track</NavButton>
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
      <div className="sidebarFooter"><span>{session.user.email}</span><button onClick={() => supabase?.auth.signOut()}>Sign out</button></div>
    </aside>}

    <main className="main">
      <header className="topbar">
        <div className="topbarLead">
          <button className="sidebarToggle" type="button" aria-label={sidebarVisible ? 'Hide sidebar' : 'Show sidebar'} title={sidebarVisible ? 'Hide sidebar' : 'Show sidebar'} onClick={() => setSidebarVisible(value => !value)}>
            <span></span><span></span><span></span>
          </button>
          <div><h1>{titles[view]}</h1><p>{endpointContext ? 'Central Windows endpoint inventory, enrollment, software policy and support controls' : view === 'overview' ? 'Central security activity and endpoint health' : view === 'settings' ? 'Administrator controls for protected endpoint connections' : 'USB Audit module — endpoint removable-media activity'}</p></div>
        </div>
        <button className="secondary" onClick={loadData}>Refresh</button>
      </header>
      {view === 'settings' ? <SecuritySettings terminals={terminals} /> : endpointView ? <EndpointManager view={view as EndpointView} /> : <>
        {error && <div className="errorBanner">{error}</div>}
        {loading && terminals.length === 0 ? <div className="loading">Loading security data…</div> : <>
          {view === 'overview' && <section><div className="cards"><Metric label="Online terminals" value={onlineCount.toString()} detail={`${terminals.length} enrolled`} /><Metric label="Offline terminals" value={Math.max(0, terminals.length - onlineCount).toString()} detail="No heartbeat in 45 seconds" /><Metric label="Connected USBs" value={devices.length.toString()} detail="Across reporting terminals" /><Metric label="USB transfers today" value={transfersToday.toString()} detail="PC ↔ USB" /></div><Panel title="Recent USB Audit activity"><TransferTable events={filteredEvents.slice(0, 25)} terminals={terminalMap} compact /></Panel></section>}
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
  </div>
}

function Login() {
  const [message, setMessage] = useState('')
  const signIn = async () => {
    if (!supabase) return
    setMessage('Redirecting to Microsoft…')
    const { error } = await supabase.auth.signInWithOAuth({ provider: 'azure', options: { scopes: 'openid profile email offline_access User.Read Files.ReadWrite.All', redirectTo: window.location.origin } })
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
