import { useEffect, useMemo, useState } from 'react'
import { supabase } from './lib/supabase'
import './endpoint-manager.css'

export type EndpointView = 'endpoints' | 'software' | 'policies' | 'remote' | 'endpoint-audit'

type Terminal = {
  terminal_id: string
  computer_name: string
  windows_user: string | null
  app_version: string | null
  enrollment_status: 'active' | 'revoked'
  last_seen_at: string
  os_name?: string | null
  os_version?: string | null
  manufacturer?: string | null
  model?: string | null
  serial_number?: string | null
  total_memory_bytes?: number | null
  processor_name?: string | null
  defender_status?: string | null
  firewall_enabled?: boolean | null
  inventory_at?: string | null
}

type Software = {
  terminal_id: string
  software_key: string
  name: string
  version: string | null
  publisher: string | null
  install_location: string | null
  last_seen_at: string
}

type Policy = {
  policy_id: string
  name: string
  description: string | null
  mode: 'audit' | 'enforce'
  is_default: boolean
  rules: Record<string, unknown>
  updated_at: string
}

type Command = {
  command_id: string
  terminal_id: string
  command_type: string
  status: string
  requested_at: string
  acknowledged_at: string | null
  completed_at: string | null
  result: Record<string, unknown> | null
}

type AuditRow = {
  audit_id: number
  terminal_id: string | null
  action: string
  details: Record<string, unknown>
  created_at: string
}

const dateTime = (value?: string | null) => value ? new Date(value).toLocaleString() : '—'
const isOnline = (lastSeen: string) => Date.now() - new Date(lastSeen).getTime() < 45_000
const bytes = (value?: number | null) => {
  if (!value) return '—'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  let size = value
  let unit = 0
  while (size >= 1024 && unit < units.length - 1) { size /= 1024; unit++ }
  return `${size >= 100 ? Math.round(size) : size.toFixed(1)} ${units[unit]}`
}

export function EndpointManager({ view }: { view: EndpointView }) {
  const [terminals, setTerminals] = useState<Terminal[]>([])
  const [software, setSoftware] = useState<Software[]>([])
  const [policies, setPolicies] = useState<Policy[]>([])
  const [commands, setCommands] = useState<Command[]>([])
  const [audit, setAudit] = useState<AuditRow[]>([])
  const [search, setSearch] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState('')

  const load = async () => {
    if (!supabase) return
    const results = await Promise.all([
      supabase.from('terminals').select('*').order('last_seen_at', { ascending: false }),
      supabase.from('installed_software').select('*').order('name').limit(5000),
      supabase.from('endpoint_policies').select('*').order('is_default', { ascending: false }).order('name'),
      supabase.from('endpoint_commands').select('*').order('requested_at', { ascending: false }).limit(250),
      supabase.from('endpoint_audit_log').select('*').order('created_at', { ascending: false }).limit(500),
    ])
    const firstError = results.find(result => result.error)?.error
    setError(firstError?.message || '')
    setTerminals((results[0].data ?? []) as Terminal[])
    setSoftware((results[1].data ?? []) as Software[])
    setPolicies((results[2].data ?? []) as Policy[])
    setCommands((results[3].data ?? []) as Command[])
    setAudit((results[4].data ?? []) as AuditRow[])
  }

  useEffect(() => {
    load()
    const timer = window.setInterval(load, 20_000)
    return () => window.clearInterval(timer)
  }, [])

  const terminalMap = useMemo(() => new Map(terminals.map(item => [item.terminal_id, item])), [terminals])
  const query = search.trim().toLowerCase()
  const visibleSoftware = useMemo(() => software.filter(item => !query || [item.name, item.version, item.publisher, terminalMap.get(item.terminal_id)?.computer_name].some(value => value?.toLowerCase().includes(query))), [software, query, terminalMap])
  const uniqueSoftware = new Set(software.map(item => item.software_key)).size
  const protectedCount = terminals.filter(item => item.defender_status === 'Protected' && item.firewall_enabled === true).length

  const requestCommand = async (terminalId: string, commandType: 'inventory' | 'remote_support') => {
    if (!supabase) return
    setBusy(`${terminalId}:${commandType}`); setError('')
    const { data, error: invokeError } = await supabase.functions.invoke('terminal-admin', {
      body: { action: 'request_command', terminalId, commandType },
    })
    if (invokeError || data?.error) setError(data?.error || invokeError?.message || 'Could not queue endpoint command')
    else await load()
    setBusy('')
  }

  if (view === 'endpoints') return <section className="endpointSection">
    {error && <div className="errorBanner">{error}</div>}
    <div className="cards endpointCards">
      <Metric label="Managed endpoints" value={terminals.length.toString()} detail={`${terminals.filter(t => isOnline(t.last_seen_at)).length} currently online`} />
      <Metric label="Protected endpoints" value={protectedCount.toString()} detail="Defender + Firewall reporting healthy" />
      <Metric label="Software titles" value={uniqueSoftware.toString()} detail={`${software.length} endpoint installations`} />
      <Metric label="Policy mode" value={policies.find(p => p.is_default)?.mode === 'enforce' ? 'Enforce' : 'Audit'} detail="Safe baseline collection" />
    </div>
    <Panel title="CRECCOM managed Windows endpoints">
      <div className="tableWrap"><table><thead><tr><th>Status</th><th>Computer</th><th>Windows</th><th>Device</th><th>Serial</th><th>Security</th><th>Memory</th><th>Inventory</th><th /></tr></thead>
        <tbody>{terminals.map(item => <tr key={item.terminal_id}>
          <td><span className={isOnline(item.last_seen_at) ? 'status online' : 'status offline'}><i />{isOnline(item.last_seen_at) ? 'Online' : 'Offline'}</span></td>
          <td><strong>{item.computer_name}</strong><small>{item.windows_user || item.terminal_id}</small></td>
          <td>{item.os_name || 'Windows'}<small>{item.os_version || '—'}</small></td>
          <td>{[item.manufacturer, item.model].filter(Boolean).join(' ') || '—'}</td>
          <td className="mono">{item.serial_number || '—'}</td>
          <td><span className={item.defender_status === 'Protected' ? 'health good' : 'health warn'}>Defender: {item.defender_status || 'Unknown'}</span><small>Firewall: {item.firewall_enabled === true ? 'On' : item.firewall_enabled === false ? 'Off' : 'Unknown'}</small></td>
          <td>{bytes(item.total_memory_bytes)}</td><td>{dateTime(item.inventory_at)}</td>
          <td><button className="linkButton" disabled={busy !== ''} onClick={() => requestCommand(item.terminal_id, 'inventory')}>{busy === `${item.terminal_id}:inventory` ? 'Queuing…' : 'Refresh inventory'}</button></td>
        </tr>)}</tbody></table></div>
    </Panel>
  </section>

  if (view === 'software') return <section className="endpointSection">
    {error && <div className="errorBanner">{error}</div>}
    <div className="filters"><input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search application, publisher, version or computer" /><span>{visibleSoftware.length} installations</span></div>
    <Panel title="Installed software inventory">
      <div className="auditModeNotice"><strong>Audit mode</strong><span>Software is being inventoried only. Nothing is blocked or removed by this release.</span></div>
      <div className="tableWrap"><table><thead><tr><th>Application</th><th>Version</th><th>Publisher</th><th>Endpoint</th><th>Last seen</th></tr></thead>
        <tbody>{visibleSoftware.length === 0 ? <tr><td colSpan={5} className="empty">No software inventory has been received yet.</td></tr> : visibleSoftware.map(item => <tr key={`${item.terminal_id}-${item.software_key}`}><td><strong>{item.name}</strong></td><td>{item.version || '—'}</td><td>{item.publisher || '—'}</td><td>{terminalMap.get(item.terminal_id)?.computer_name || item.terminal_id}</td><td>{dateTime(item.last_seen_at)}</td></tr>)}</tbody></table></div>
    </Panel>
  </section>

  if (view === 'policies') return <section className="endpointSection">
    {error && <div className="errorBanner">{error}</div>}
    <div className="policyGrid">{policies.map(policy => <div className="policyCard" key={policy.policy_id}><div className="policyHead"><div><strong>{policy.name}</strong><span>{policy.is_default ? 'Default policy' : 'Endpoint policy'}</span></div><span className={policy.mode === 'enforce' ? 'mode enforce' : 'mode audit'}>{policy.mode}</span></div><p>{policy.description || 'No description.'}</p><div className="policyRules"><div><span>Software</span><strong>Allow/block lists ready</strong></div><div><span>USB</span><strong>Monitoring enabled</strong></div><div><span>Security</span><strong>Defender + Firewall required</strong></div></div><small>Updated {dateTime(policy.updated_at)}</small></div>)}</div>
    <div className="auditModeNotice"><strong>Enforcement locked</strong><span>The policy engine remains in audit mode until CRECCOM reviews the software baseline. This prevents accidental blocking of legitimate applications.</span></div>
  </section>

  if (view === 'remote') return <section className="endpointSection">
    {error && <div className="errorBanner">{error}</div>}
    <div className="auditModeNotice"><strong>User-visible remote support</strong><span>Remote support requests are queued and auditable. The agent will not silently open an unrestricted remote shell.</span></div>
    <Panel title="Request support session">
      <div className="tableWrap"><table><thead><tr><th>Endpoint</th><th>User</th><th>Status</th><th>Last seen</th><th>Action</th></tr></thead><tbody>{terminals.filter(t => t.enrollment_status !== 'revoked').map(item => <tr key={item.terminal_id}><td><strong>{item.computer_name}</strong><small>{item.serial_number || item.terminal_id}</small></td><td>{item.windows_user || '—'}</td><td><span className={isOnline(item.last_seen_at) ? 'status online' : 'status offline'}><i />{isOnline(item.last_seen_at) ? 'Online' : 'Offline'}</span></td><td>{dateTime(item.last_seen_at)}</td><td><button className="primary compactButton" disabled={!isOnline(item.last_seen_at) || busy !== ''} onClick={() => requestCommand(item.terminal_id, 'remote_support')}>{busy === `${item.terminal_id}:remote_support` ? 'Queuing…' : 'Request Remote Support'}</button></td></tr>)}</tbody></table></div>
    </Panel>
    <Panel title="Recent endpoint commands"><div className="tableWrap"><table><thead><tr><th>Requested</th><th>Endpoint</th><th>Command</th><th>Status</th><th>Completed</th></tr></thead><tbody>{commands.length === 0 ? <tr><td colSpan={5} className="empty">No endpoint commands yet.</td></tr> : commands.map(item => <tr key={item.command_id}><td>{dateTime(item.requested_at)}</td><td>{terminalMap.get(item.terminal_id)?.computer_name || item.terminal_id}</td><td>{item.command_type.replaceAll('_', ' ')}</td><td><span className={`commandStatus ${item.status}`}>{item.status}</span></td><td>{dateTime(item.completed_at)}</td></tr>)}</tbody></table></div></Panel>
  </section>

  return <section className="endpointSection">
    {error && <div className="errorBanner">{error}</div>}
    <Panel title="Endpoint management audit log"><div className="tableWrap"><table><thead><tr><th>Time</th><th>Endpoint</th><th>Action</th><th>Details</th></tr></thead><tbody>{audit.length === 0 ? <tr><td colSpan={4} className="empty">No endpoint administration events yet.</td></tr> : audit.map(item => <tr key={item.audit_id}><td>{dateTime(item.created_at)}</td><td>{item.terminal_id ? terminalMap.get(item.terminal_id)?.computer_name || item.terminal_id : 'Console'}</td><td><strong>{item.action}</strong></td><td className="jsonDetails">{JSON.stringify(item.details)}</td></tr>)}</tbody></table></div></Panel>
  </section>
}

function Metric({ label, value, detail }: { label: string, value: string, detail: string }) { return <div className="metric"><span>{label}</span><strong>{value}</strong><small>{detail}</small></div> }
function Panel({ title, children }: { title: string, children: React.ReactNode }) { return <div className="panel"><div className="panelTitle">{title}</div>{children}</div> }
