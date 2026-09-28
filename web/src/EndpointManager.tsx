import { useEffect, useMemo, useState } from 'react'
import { supabase } from './lib/supabase'
import { DeploymentManager } from './DeploymentManager'
import './endpoint-manager.css'

export type EndpointView = 'endpoints' | 'software' | 'deployment' | 'policies' | 'remote' | 'endpoint-audit'

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
  executable_paths?: string[] | null
  last_seen_at: string
}

type SoftwareRule = {
  rule_id: string
  terminal_id: string
  software_key: string
  software_name: string
  publisher: string | null
  install_location: string | null
  executable_paths: string[] | null
  is_active: boolean
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
const canBlockSoftware = (item: Software) =>
  Boolean(item.install_location?.trim()) || Boolean(Array.isArray(item.executable_paths) && item.executable_paths.length > 0)

export function EndpointManager({ view }: { view: EndpointView }) {
  const [terminals, setTerminals] = useState<Terminal[]>([])
  const [software, setSoftware] = useState<Software[]>([])
  const [softwareRules, setSoftwareRules] = useState<SoftwareRule[]>([])
  const [policies, setPolicies] = useState<Policy[]>([])
  const [commands, setCommands] = useState<Command[]>([])
  const [audit, setAudit] = useState<AuditRow[]>([])
  const [search, setSearch] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState('')
  const [expandedEndpoints, setExpandedEndpoints] = useState<Set<string>>(new Set())
  const [softwareTarget, setSoftwareTarget] = useState<Software | null>(null)
  const [selectedTargets, setSelectedTargets] = useState<Set<string>>(new Set())

  const load = async () => {
    if (!supabase) return
    const results = await Promise.all([
      supabase.from('terminals').select('*').order('last_seen_at', { ascending: false }),
      supabase.from('installed_software').select('*').order('name').limit(5000),
      supabase.from('software_control_rules').select('*').eq('is_active', true).order('software_name'),
      supabase.from('endpoint_policies').select('*').order('is_default', { ascending: false }).order('name'),
      supabase.from('endpoint_commands').select('*').order('requested_at', { ascending: false }).limit(250),
      supabase.from('endpoint_audit_log').select('*').order('created_at', { ascending: false }).limit(500),
    ])
    const firstError = results.find(result => result.error)?.error
    setError(firstError?.message || '')
    setTerminals((results[0].data ?? []) as Terminal[])
    setSoftware((results[1].data ?? []) as Software[])
    setSoftwareRules((results[2].data ?? []) as SoftwareRule[])
    setPolicies((results[3].data ?? []) as Policy[])
    setCommands((results[4].data ?? []) as Command[])
    setAudit((results[5].data ?? []) as AuditRow[])
  }

  useEffect(() => {
    load()
    const timer = window.setInterval(load, 20_000)
    return () => window.clearInterval(timer)
  }, [])

  const terminalMap = useMemo(() => new Map(terminals.map(item => [item.terminal_id, item])), [terminals])
  const defaultPolicy = policies.find(item => item.is_default)
  const controlMode = defaultPolicy?.mode === 'enforce'
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

  const setPolicyMode = async (nextMode: 'audit' | 'enforce') => {
    if (!supabase || nextMode === defaultPolicy?.mode) return
    if (nextMode === 'enforce' && !window.confirm('Turn on Control mode? Active software block rules will begin enforcing when endpoints receive the policy.')) return

    setBusy('policy-mode'); setError('')
    const { data, error: invokeError } = await supabase.functions.invoke('terminal-admin', {
      body: { action: 'set_policy_mode', mode: nextMode },
    })
    if (invokeError || data?.error) setError(data?.error || invokeError?.message || 'Could not change policy mode')
    else await load()
    setBusy('')
  }

  const openSoftwareTargets = (item: Software) => {
    const selected = new Set(
      softwareRules
        .filter(rule => rule.software_key === item.software_key && rule.is_active)
        .map(rule => rule.terminal_id)
    )
    setSelectedTargets(selected)
    setSoftwareTarget(item)
  }

  const saveSoftwareTargets = async () => {
    if (!supabase || !softwareTarget) return
    const candidates = software.filter(item => item.software_key === softwareTarget.software_key)
    const allTerminalIds = [...new Set(candidates.map(item => item.terminal_id))]
    const terminalIds = [...selectedTargets].filter(id => allTerminalIds.includes(id))

    setBusy('software-targets'); setError('')
    const { data, error: invokeError } = await supabase.functions.invoke('terminal-admin', {
      body: {
        action: 'set_software_block_targets',
        softwareKey: softwareTarget.software_key,
        terminalIds,
        allTerminalIds,
      },
    })
    if (invokeError || data?.error) {
      setError(data?.error || invokeError?.message || 'Could not save software control targets')
    } else {
      setSoftwareTarget(null)
      await load()
    }
    setBusy('')
  }

  const softwareGroups = useMemo(() => {
    const query = search.trim().toLowerCase()
    return terminals.map(terminal => {
      const computerMatches = terminal.computer_name.toLowerCase().includes(query)
        || terminal.windows_user?.toLowerCase().includes(query)
      const items = software.filter(item => {
        if (item.terminal_id !== terminal.terminal_id) return false
        if (!query || computerMatches) return true
        return [item.name, item.version, item.publisher, item.install_location]
          .some(value => value?.toLowerCase().includes(query))
      })
      return { terminal, items }
    }).filter(group => group.items.length > 0)
  }, [terminals, software, search])

  const allSoftwareEndpointIds = softwareGroups.map(group => group.terminal.terminal_id)
  const allExpanded = allSoftwareEndpointIds.length > 0 && allSoftwareEndpointIds.every(id => expandedEndpoints.has(id))

  const toggleAllSoftwareGroups = () => {
    setExpandedEndpoints(allExpanded ? new Set() : new Set(allSoftwareEndpointIds))
  }

  if (view === 'deployment') return <DeploymentManager />

  if (view === 'endpoints') return <section className="endpointSection">
    {error && <div className="errorBanner">{error}</div>}
    <div className="cards endpointCards">
      <Metric label="Managed endpoints" value={terminals.length.toString()} detail={`${terminals.filter(t => isOnline(t.last_seen_at)).length} currently online`} />
      <Metric label="Protected endpoints" value={protectedCount.toString()} detail="Defender + Firewall reporting healthy" />
      <Metric label="Software titles" value={uniqueSoftware.toString()} detail={`${software.length} endpoint installations`} />
      <Metric label="Policy mode" value={controlMode ? 'Control' : 'Audit'} detail={controlMode ? 'Software controls active' : 'Inventory only'} />
    </div>
    <Panel title="CRECCOM managed Windows endpoints">
      <div className="tableWrap"><table><thead><tr><th>Status</th><th>Computer</th><th>Windows</th><th>Device</th><th>Serial</th><th>Security</th><th>Memory</th><th>Inventory</th><th /></tr></thead>
        <tbody>{terminals.map(item => <tr key={item.terminal_id}>
          <td><Status online={isOnline(item.last_seen_at)} /></td>
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

  if (view === 'software') {
    const targetCandidates = softwareTarget ? software.filter(item => item.software_key === softwareTarget.software_key) : []

    return <section className="endpointSection">
      {error && <div className="errorBanner">{error}</div>}

      <div className="softwareControlBar">
        <div>
          <span className="controlEyebrow">Application control</span>
          <strong>{controlMode ? 'Control mode' : 'Audit mode'}</strong>
          <small>{controlMode ? 'Configured software blocks are enforced on synchronized endpoints.' : 'Software is inventoried only. Nothing is blocked.'}</small>
        </div>
        <div className="modeSwitchWrap">
          <span className={!controlMode ? 'modeLabel active' : 'modeLabel'}>Audit</span>
          <button
            type="button"
            role="switch"
            aria-checked={controlMode}
            className={controlMode ? 'modeSwitch on' : 'modeSwitch'}
            disabled={busy === 'policy-mode'}
            onClick={() => setPolicyMode(controlMode ? 'audit' : 'enforce')}
          ><span /></button>
          <span className={controlMode ? 'modeLabel active' : 'modeLabel'}>Control</span>
        </div>
      </div>

      <div className={controlMode ? 'controlNotice controlActive' : 'controlNotice'}>
        <strong>{controlMode ? 'Control mode is active' : 'Audit mode'}</strong>
        <span>{controlMode ? 'Use Manage block to select one or multiple PCs for each software title. Changes are logged and synchronized to the Windows agent.' : 'Switch to Control when you are ready to manage application blocking. Existing inventory remains read-only in Audit mode.'}</span>
      </div>

      <div className="softwareToolbar">
        <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search software, publisher, version or computer" />
        <button className="secondary compactButton" onClick={toggleAllSoftwareGroups}>{allExpanded ? 'Collapse all' : 'Expand all'}</button>
        <span>{software.length} installations across {softwareGroups.length} PCs</span>
      </div>

      <div className="softwareClientList">
        {softwareGroups.length === 0 ? <div className="panel emptyPanel">No software inventory matches the current search.</div> : softwareGroups.map(({ terminal, items }) => {
          const expanded = expandedEndpoints.has(terminal.terminal_id)
          const blockedOnTerminal = softwareRules.filter(rule => rule.terminal_id === terminal.terminal_id && rule.is_active).length
          return <div className="softwareClientCard" key={terminal.terminal_id}>
            <button className="softwareClientHeader" onClick={() => {
              const next = new Set(expandedEndpoints)
              if (expanded) next.delete(terminal.terminal_id); else next.add(terminal.terminal_id)
              setExpandedEndpoints(next)
            }}>
              <span className={expanded ? 'clientChevron open' : 'clientChevron'}>›</span>
              <div className="softwareClientIdentity">
                <strong>{terminal.computer_name}</strong>
                <span>{terminal.windows_user || terminal.terminal_id}</span>
              </div>
              <div className="softwareClientMeta">
                <span>{items.length} apps</span>
                {blockedOnTerminal > 0 && <span className="blockedCount">{blockedOnTerminal} blocked</span>}
                <Status online={isOnline(terminal.last_seen_at)} />
              </div>
            </button>

            {expanded && <div className="softwareClientBody">
              <div className="tableWrap"><table><thead><tr><th>Application</th><th>Version</th><th>Publisher</th><th>Control</th><th>Last seen</th><th /></tr></thead>
                <tbody>{items.map(item => {
                  const blocked = softwareRules.some(rule => rule.terminal_id === item.terminal_id && rule.software_key === item.software_key && rule.is_active)
                  const eligible = canBlockSoftware(item)
                  return <tr key={`${item.terminal_id}-${item.software_key}`}>
                    <td><strong>{item.name}</strong>{!eligible && <small className="muted">Refresh inventory to detect an executable or install location.</small>}</td>
                    <td>{item.version || '—'}</td>
                    <td>{item.publisher || '—'}</td>
                    <td>{blocked ? <span className="softwareState blocked">Blocked</span> : <span className="softwareState allowed">{controlMode ? 'Allowed' : 'Observed'}</span>}</td>
                    <td>{dateTime(item.last_seen_at)}</td>
                    <td><button className="linkButton" disabled={!controlMode || busy !== '' || !eligible} onClick={() => openSoftwareTargets(item)}>{blocked ? 'Manage block' : 'Block / manage'}</button></td>
                  </tr>
                })}</tbody></table></div>
            </div>}
          </div>
        })}
      </div>

      {softwareTarget && <div className="modalBackdrop" onMouseDown={() => busy !== 'software-targets' && setSoftwareTarget(null)}>
        <div className="controlModal" onMouseDown={event => event.stopPropagation()}>
          <div className="controlModalHead">
            <div><span className="controlEyebrow">Software control</span><h3>{softwareTarget.name}</h3><p>Select the endpoints where this software should be blocked.</p></div>
            <button className="modalClose" onClick={() => setSoftwareTarget(null)} disabled={busy === 'software-targets'}>×</button>
          </div>

          <div className="targetList">
            {targetCandidates.map(item => {
              const terminal = terminalMap.get(item.terminal_id)
              const eligible = canBlockSoftware(item)
              const checked = selectedTargets.has(item.terminal_id)
              return <label className={eligible ? 'targetRow' : 'targetRow disabled'} key={item.terminal_id}>
                <input
                  type="checkbox"
                  checked={checked}
                  disabled={!eligible || busy === 'software-targets'}
                  onChange={event => {
                    const next = new Set(selectedTargets)
                    if (event.target.checked) next.add(item.terminal_id); else next.delete(item.terminal_id)
                    setSelectedTargets(next)
                  }}
                />
                <span className="targetCheck" />
                <div><strong>{terminal?.computer_name || item.terminal_id}</strong><span>{terminal?.windows_user || item.publisher || 'Managed endpoint'}</span></div>
                <span className="targetStatus">{eligible ? (checked ? 'Block' : 'Allow') : 'Needs inventory'}</span>
              </label>
            })}
          </div>

          <div className="controlModalFooter">
            <span>{selectedTargets.size} endpoint{selectedTargets.size === 1 ? '' : 's'} selected for blocking</span>
            <div><button className="secondary" onClick={() => setSoftwareTarget(null)} disabled={busy === 'software-targets'}>Cancel</button><button className="primary" onClick={saveSoftwareTargets} disabled={busy === 'software-targets'}>{busy === 'software-targets' ? 'Saving…' : 'Save control'}</button></div>
          </div>
        </div>
      </div>}
    </section>
  }

  if (view === 'policies') return <section className="endpointSection">
    {error && <div className="errorBanner">{error}</div>}
    <div className="policyGrid">{policies.map(policy => <div className="policyCard" key={policy.policy_id}><div className="policyHead"><div><strong>{policy.name}</strong><span>{policy.is_default ? 'Default policy' : 'Endpoint policy'}</span></div><span className={policy.mode === 'enforce' ? 'mode enforce' : 'mode audit'}>{policy.mode === 'enforce' ? 'control' : 'audit'}</span></div><p>{policy.description || 'No description.'}</p><div className="policyRules"><div><span>Software</span><strong>{softwareRules.length} block rule{softwareRules.length === 1 ? '' : 's'} configured</strong></div><div><span>USB</span><strong>Monitoring enabled</strong></div><div><span>Security</span><strong>Defender + Firewall required</strong></div></div><small>Updated {dateTime(policy.updated_at)}</small></div>)}</div>
    <div className={controlMode ? 'auditModeNotice enforceNotice' : 'auditModeNotice'}><strong>{controlMode ? 'Control mode' : 'Audit mode'}</strong><span>{controlMode ? 'Selected application controls are actively synchronized to managed endpoints.' : 'Software is inventoried only. Configure and enable Control mode from Software Inventory when ready.'}</span></div>
  </section>

  if (view === 'remote') return <section className="endpointSection">
    {error && <div className="errorBanner">{error}</div>}
    <div className="auditModeNotice"><strong>User-assisted remote support</strong><span>Support requests are queued and auditable. The Windows agent only shows the user a CRECCOM IT notice asking them to open Windows Quick Assist; no remote connection starts automatically.</span></div>
    <Panel title="Request user-assisted support">
      <div className="tableWrap"><table><thead><tr><th>Endpoint</th><th>User</th><th>Status</th><th>Last seen</th><th>Action</th></tr></thead><tbody>{terminals.filter(t => t.enrollment_status !== 'revoked').map(item => <tr key={item.terminal_id}><td><strong>{item.computer_name}</strong><small>{item.serial_number || item.terminal_id}</small></td><td>{item.windows_user || '—'}</td><td><Status online={isOnline(item.last_seen_at)} /></td><td>{dateTime(item.last_seen_at)}</td><td><button className="primary compactButton" disabled={!isOnline(item.last_seen_at) || busy !== ''} onClick={() => requestCommand(item.terminal_id, 'remote_support')}>{busy === `${item.terminal_id}:remote_support` ? 'Queuing…' : 'Send Support Notice'}</button></td></tr>)}</tbody></table></div>
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
function Status({ online }: { online: boolean }) { return <span className={online ? 'status online' : 'status offline'}><i />{online ? 'Online' : 'Offline'}</span> }
