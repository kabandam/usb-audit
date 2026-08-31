import { FormEvent, useEffect, useMemo, useState } from 'react'
import type { Session } from '@supabase/supabase-js'
import { isBackendConfigured, supabase } from './lib/supabase'

type View = 'overview' | 'transfers' | 'terminals' | 'devices'

type Terminal = {
  terminal_id: string
  computer_name: string
  windows_user: string | null
  app_version: string | null
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

const bytes = (value?: number | null) => {
  if (!value) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  let size = value
  let unit = 0
  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024
    unit++
  }
  return `${size >= 100 || unit === 0 ? Math.round(size) : size.toFixed(1)} ${units[unit]}`
}

const dateTime = (value?: string | null) => value ? new Date(value).toLocaleString() : '—'
const isOnline = (lastSeen: string) => Date.now() - new Date(lastSeen).getTime() < 45_000

function App() {
  const [session, setSession] = useState<Session | null>(null)
  const [view, setView] = useState<View>('overview')
  const [terminals, setTerminals] = useState<Terminal[]>([])
  const [events, setEvents] = useState<AuditEvent[]>([])
  const [devices, setDevices] = useState<TerminalDevice[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [search, setSearch] = useState('')
  const [direction, setDirection] = useState('all')

  useEffect(() => {
    if (!supabase) return
    supabase.auth.getSession().then(({ data }) => setSession(data.session))
    const { data } = supabase.auth.onAuthStateChange((_event, next) => setSession(next))
    return () => data.subscription.unsubscribe()
  }, [])

  const loadData = async () => {
    if (!supabase || !session) return
    setLoading(true)
    setError('')
    const [terminalResult, eventResult, deviceResult] = await Promise.all([
      supabase.from('terminals').select('*').order('last_seen_at', { ascending: false }),
      supabase.from('audit_events').select('*').order('timestamp', { ascending: false }).limit(750),
      supabase.from('terminal_devices').select('*').order('connected_at', { ascending: false }),
    ])

    const firstError = terminalResult.error || eventResult.error || deviceResult.error
    if (firstError) setError(firstError.message)
    setTerminals((terminalResult.data ?? []) as Terminal[])
    setEvents((eventResult.data ?? []) as AuditEvent[])
    setDevices((deviceResult.data ?? []) as TerminalDevice[])
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
      return [
        item.file_name, item.device_name, item.device_serial, item.windows_user,
        item.source_path, item.destination_path, terminal?.computer_name,
      ].some(value => value?.toLowerCase().includes(query))
    })
  }, [events, search, direction, terminalMap])

  if (!isBackendConfigured) return <ConfigurationMissing />
  if (!session) return <Login />

  const pageTitle = view === 'overview' ? 'Security Overview' : view === 'transfers' ? 'USB Transfers' : view === 'terminals' ? 'Client Terminals' : 'USB Devices'

  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brandMark">S</div>
          <div><strong>CRECCOM Security</strong><span>Security Console</span></div>
        </div>
        <nav>
          <NavButton active={view === 'overview'} onClick={() => setView('overview')}>Security Overview</NavButton>
          <div className="navSectionLabel">USB Audit</div>
          <NavButton active={view === 'transfers'} onClick={() => setView('transfers')}>USB Transfers</NavButton>
          <NavButton active={view === 'terminals'} onClick={() => setView('terminals')}>Client Terminals</NavButton>
          <NavButton active={view === 'devices'} onClick={() => setView('devices')}>USB Devices</NavButton>
        </nav>
        <div className="sidebarFooter">
          <span>{session.user.email}</span>
          <button onClick={() => supabase?.auth.signOut()}>Sign out</button>
        </div>
      </aside>

      <main className="main">
        <header className="topbar">
          <div>
            <h1>{pageTitle}</h1>
            <p>{view === 'overview' ? 'Central security activity and endpoint health' : 'USB Audit module — endpoint removable-media activity'}</p>
          </div>
          <button className="secondary" onClick={loadData}>Refresh</button>
        </header>

        {error && <div className="errorBanner">{error}</div>}
        {loading && terminals.length === 0 ? <div className="loading">Loading security data…</div> : (
          <>
            {view === 'overview' && (
              <section>
                <div className="cards">
                  <Metric label="Online terminals" value={onlineCount.toString()} detail={`${terminals.length} enrolled`} />
                  <Metric label="Offline terminals" value={Math.max(0, terminals.length - onlineCount).toString()} detail="No heartbeat in 45 seconds" />
                  <Metric label="Connected USBs" value={devices.length.toString()} detail="Across reporting terminals" />
                  <Metric label="USB transfers today" value={transfersToday.toString()} detail="PC ↔ USB" />
                </div>
                <Panel title="Recent USB Audit activity">
                  <TransferTable events={filteredEvents.slice(0, 25)} terminals={terminalMap} compact />
                </Panel>
              </section>
            )}

            {view === 'transfers' && (
              <section>
                <div className="filters">
                  <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search file, terminal, device, user or path" />
                  <select value={direction} onChange={e => setDirection(e.target.value)}>
                    <option value="all">All directions</option>
                    <option value="PcToUsb">PC → USB</option>
                    <option value="UsbToPc">USB → PC</option>
                  </select>
                  <span>{filteredEvents.length} records</span>
                </div>
                <Panel title="USB transfer records">
                  <TransferTable events={filteredEvents} terminals={terminalMap} />
                </Panel>
              </section>
            )}

            {view === 'terminals' && (
              <Panel title="Installed security client terminals">
                <div className="tableWrap"><table><thead><tr><th>Status</th><th>Computer</th><th>User</th><th>Version</th><th>Last seen</th><th>USBs</th></tr></thead>
                  <tbody>{terminals.map(item => <tr key={item.terminal_id}>
                    <td><Status online={isOnline(item.last_seen_at)} /></td><td><strong>{item.computer_name}</strong><small>{item.terminal_id}</small></td>
                    <td>{item.windows_user || '—'}</td><td>{item.app_version || '—'}</td><td>{dateTime(item.last_seen_at)}</td>
                    <td>{devices.filter(device => device.terminal_id === item.terminal_id).length}</td>
                  </tr>)}</tbody></table></div>
              </Panel>
            )}

            {view === 'devices' && (
              <Panel title="Currently connected USB storage">
                <div className="tableWrap"><table><thead><tr><th>Terminal</th><th>Drive</th><th>Device</th><th>Serial</th><th>Volume</th><th>Format</th><th>Capacity</th><th>Connected</th></tr></thead>
                  <tbody>{devices.map(item => <tr key={`${item.terminal_id}-${item.device_key}`}>
                    <td>{terminalMap.get(item.terminal_id)?.computer_name || item.terminal_id}</td><td><strong>{item.drive_letter || '—'}</strong></td>
                    <td>{item.device_name || 'USB storage'}</td><td className="mono">{item.device_serial || '—'}</td><td>{item.volume_label || '—'}</td>
                    <td>{item.file_system || '—'}</td><td>{bytes(item.total_size_bytes)}</td><td>{dateTime(item.connected_at)}</td>
                  </tr>)}</tbody></table></div>
              </Panel>
            )}
          </>
        )}
      </main>
    </div>
  )
}

function Login() {
  const [email, setEmail] = useState('')
  const [message, setMessage] = useState('')
  const submit = async (event: FormEvent) => {
    event.preventDefault()
    if (!supabase || !email.trim()) return
    const { error } = await supabase.auth.signInWithOtp({ email: email.trim(), options: { emailRedirectTo: window.location.origin } })
    setMessage(error ? error.message : 'Check your email for the sign-in link.')
  }
  return <div className="loginPage"><form className="loginCard" onSubmit={submit}>
    <div className="brandMark large">S</div><h1>CRECCOM Security Console</h1><p>Sign in to the central security monitoring console.</p>
    <label>Email address</label><input type="email" value={email} onChange={e => setEmail(e.target.value)} placeholder="you@creccommw.org" required />
    <button className="primary" type="submit">Send sign-in link</button>{message && <div className="formMessage">{message}</div>}
  </form></div>
}

function ConfigurationMissing() {
  return <div className="loginPage"><div className="loginCard"><div className="brandMark large">S</div><h1>CRECCOM Security Console</h1><p>The security console source is ready, but its Supabase environment variables have not been configured yet.</p></div></div>
}

function NavButton({ active, onClick, children }: { active: boolean, onClick: () => void, children: React.ReactNode }) {
  return <button className={active ? 'nav active' : 'nav'} onClick={onClick}>{children}</button>
}

function Metric({ label, value, detail }: { label: string, value: string, detail: string }) {
  return <div className="metric"><span>{label}</span><strong>{value}</strong><small>{detail}</small></div>
}

function Panel({ title, children }: { title: string, children: React.ReactNode }) {
  return <div className="panel"><div className="panelTitle">{title}</div>{children}</div>
}

function Status({ online }: { online: boolean }) {
  return <span className={online ? 'status online' : 'status offline'}><i />{online ? 'Online' : 'Offline'}</span>
}

function TransferTable({ events, terminals, compact = false }: { events: AuditEvent[], terminals: Map<string, Terminal>, compact?: boolean }) {
  return <div className="tableWrap"><table><thead><tr><th>Time</th><th>Terminal</th><th>Direction</th><th>Device</th><th>File</th>{!compact && <><th>Source</th><th>Destination</th><th>Size</th><th>SHA-256</th></>}</tr></thead>
    <tbody>{events.length === 0 ? <tr><td colSpan={compact ? 5 : 9} className="empty">No matching transfer records.</td></tr> : events.map(item => <tr key={item.event_id}>
      <td>{dateTime(item.timestamp)}</td><td>{terminals.get(item.terminal_id)?.computer_name || item.terminal_id}</td>
      <td><span className="direction">{item.direction === 'UsbToPc' ? 'USB → PC' : item.direction === 'PcToUsb' ? 'PC → USB' : item.direction || '—'}</span></td>
      <td>{item.device_name || item.drive_letter || 'USB'}</td><td><strong>{item.file_name || '—'}</strong></td>
      {!compact && <><td className="path">{item.source_path || '—'}</td><td className="path">{item.destination_path || '—'}</td><td>{bytes(item.file_size_bytes)}</td><td className="mono">{item.sha256 ? `${item.sha256.slice(0, 14)}…` : '—'}</td></>}
    </tr>)}</tbody></table></div>
}

export default App
