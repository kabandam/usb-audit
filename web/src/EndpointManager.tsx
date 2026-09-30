import { useEffect, useMemo, useState } from 'react'
import { supabase } from './lib/supabase'
import { DeploymentManager } from './DeploymentManager'
import { NetworkTrack } from './NetworkTrack'
import './endpoint-manager.css'

export type EndpointView = 'endpoints' | 'network' | 'software' | 'deployment' | 'policies' | 'remote' | 'endpoint-audit'

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

type AgentUpdate = {
  terminal_id: string
  current_version: string | null
  latest_version: string | null
  state: string
  message: string | null
  last_checked_at: string | null
  reported_at: string
}

const supportsInventoryUpgrade = (version?: string | null) => {
  const v = (version || '').split('.').map(part => Number.parseInt(part, 10) || 0)
  return (v[0] || 0) > 1 || ((v[0] || 0) === 1 && ((v[1] || 0) > 2 || ((v[1] || 0) === 2 && (v[2] || 0) >= 140)))
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

const endpointStatus = (item: Terminal) => isOnline(item.last_seen_at) ? 'Online' : 'Offline'
const endpointLastSeen = (value?: string | null) => {
  if (!value) return '—'
  const date = new Date(value)
  return date.toLocaleString(undefined, {
    year: 'numeric', month: 'short', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
  })
}
const xmlEscape = (value: unknown) => String(value ?? '').replace(/[<>&"']/g, char => ({
  '<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;', "'": '&apos;',
}[char] || char))
const downloadBlob = (blob: Blob, filename: string) => {
  const url = URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = filename
  document.body.appendChild(anchor)
  anchor.click()
  anchor.remove()
  window.setTimeout(() => URL.revokeObjectURL(url), 1000)
}
const exportEndpointsExcel = (items: Terminal[]) => {
  const headings = ['Status','Last seen','Computer','Windows user','Windows','OS version','Manufacturer','Model','Serial number','Defender','Firewall','Memory','Inventory time','Smart Console version']
  const rows = items.map(item => [
    endpointStatus(item), endpointLastSeen(item.last_seen_at), item.computer_name, item.windows_user || '',
    item.os_name || 'Windows', item.os_version || '', item.manufacturer || '', item.model || '',
    item.serial_number || '', item.defender_status || 'Unknown',
    item.firewall_enabled === true ? 'On' : item.firewall_enabled === false ? 'Off' : 'Unknown',
    bytes(item.total_memory_bytes), endpointLastSeen(item.inventory_at), item.app_version || '',
  ])
  const rowXml = [headings, ...rows].map((row, rowIndex) =>
    `<Row>${row.map(cell => `<Cell><Data ss:Type="String">${xmlEscape(cell)}</Data></Cell>`).join('')}</Row>`
  ).join('')
  const xml = `<?xml version="1.0"?>
<?mso-application progid="Excel.Sheet"?>
<Workbook xmlns="urn:schemas-microsoft-com:office:spreadsheet"
 xmlns:o="urn:schemas-microsoft-com:office:office"
 xmlns:x="urn:schemas-microsoft-com:office:excel"
 xmlns:ss="urn:schemas-microsoft-com:office:spreadsheet">
 <Worksheet ss:Name="Managed Endpoints"><Table>${rowXml}</Table></Worksheet>
</Workbook>`
  downloadBlob(new Blob([xml], { type: 'application/vnd.ms-excel;charset=utf-8' }), `CRECCOM-Managed-Endpoints-${new Date().toISOString().slice(0,10)}.xls`)
}
const pdfEscape = (value: string) => value.replace(/\\/g, '\\\\').replace(/\(/g, '\\(').replace(/\)/g, '\\)')
const pdfAscii = (value: unknown) => String(value ?? '').normalize('NFKD').replace(/[^\x20-\x7E]/g, ' ').replace(/\s+/g, ' ').trim()
const fixed = (value: unknown, width: number) => pdfAscii(value).slice(0, width).padEnd(width, ' ')
const exportEndpointsPdf = (items: Terminal[]) => {
  const header = [
    fixed('Status',8), fixed('Computer',18), fixed('User',16), fixed('Windows',16),
    fixed('Device',20), fixed('Serial',16), fixed('Security',19), fixed('Last seen',22),
  ].join(' ')
  const divider = '-'.repeat(header.length)
  const rows = items.map(item => [
    fixed(endpointStatus(item),8),
    fixed(item.computer_name,18),
    fixed(item.windows_user || '—',16),
    fixed(`${item.os_name || 'Windows'} ${item.os_version || ''}`,16),
    fixed([item.manufacturer,item.model].filter(Boolean).join(' ') || '—',20),
    fixed(item.serial_number || '—',16),
    fixed(`Def:${item.defender_status || '?'} FW:${item.firewall_enabled === true ? 'On' : item.firewall_enabled === false ? 'Off' : '?'}`,19),
    fixed(endpointLastSeen(item.last_seen_at),22),
  ].join(' '))

  const perPage = 38
  const pages: string[][] = []
  for (let i = 0; i < rows.length; i += perPage) pages.push(rows.slice(i, i + perPage))
  if (pages.length === 0) pages.push([])

  const objects: string[] = ['']
  objects[1] = '<< /Type /Catalog /Pages 2 0 R >>'
  objects[2] = ''
  objects[3] = '<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>'
  const pageIds: number[] = []

  pages.forEach((pageRows, pageIndex) => {
    const reportTime = endpointLastSeen(new Date().toISOString())
    let stream = `BT /F1 15 Tf 28 560 Td (${pdfEscape('CRECCOM Smart Console - Managed Endpoints')}) Tj ET\n`
    stream += `BT /F1 7 Tf 28 544 Td (${pdfEscape(`Exported: ${reportTime}   Page ${pageIndex + 1} of ${pages.length}`)}) Tj ET\n`
    let y = 524
    ;[header, divider, ...pageRows].forEach(line => {
      stream += `BT /F1 5.7 Tf 20 ${y} Td (${pdfEscape(line)}) Tj ET\n`
      y -= 12
    })
    const contentId = objects.length
    objects.push(`<< /Length ${stream.length} >>\nstream\n${stream}endstream`)
    const pageId = objects.length
    objects.push(`<< /Type /Page /Parent 2 0 R /MediaBox [0 0 842 595] /Resources << /Font << /F1 3 0 R >> >> /Contents ${contentId} 0 R >>`)
    pageIds.push(pageId)
  })

  objects[2] = `<< /Type /Pages /Kids [${pageIds.map(id => `${id} 0 R`).join(' ')}] /Count ${pageIds.length} >>`

  let pdf = '%PDF-1.4\n'
  const offsets: number[] = [0]
  for (let i = 1; i < objects.length; i++) {
    offsets[i] = pdf.length
    pdf += `${i} 0 obj\n${objects[i]}\nendobj\n`
  }
  const xref = pdf.length
  pdf += `xref\n0 ${objects.length}\n0000000000 65535 f \n`
  for (let i = 1; i < objects.length; i++) pdf += `${String(offsets[i]).padStart(10,'0')} 00000 n \n`
  pdf += `trailer\n<< /Size ${objects.length} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF`

  downloadBlob(new Blob([pdf], { type: 'application/pdf' }), `CRECCOM-Managed-Endpoints-${new Date().toISOString().slice(0,10)}.pdf`)
}

export function EndpointManager({ view }: { view: EndpointView }) {
  const [terminals, setTerminals] = useState<Terminal[]>([])
  const [software, setSoftware] = useState<Software[]>([])
  const [agentUpdates, setAgentUpdates] = useState<AgentUpdate[]>([])
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
      supabase.from('endpoint_agent_update_status').select('*'),
    ])
    const firstError = results.find(result => result.error)?.error
    setError(firstError?.message || '')
    setTerminals((results[0].data ?? []) as Terminal[])
    setSoftware((results[1].data ?? []) as Software[])
    setSoftwareRules((results[2].data ?? []) as SoftwareRule[])
    setPolicies((results[3].data ?? []) as Policy[])
    setCommands((results[4].data ?? []) as Command[])
    setAudit((results[5].data ?? []) as AuditRow[])
    setAgentUpdates((results[6].data ?? []) as AgentUpdate[])
  }

  useEffect(() => {
    load()
    const timer = window.setInterval(load, 20_000)
    return () => window.clearInterval(timer)
  }, [])

  const terminalMap = useMemo(() => new Map(terminals.map(item => [item.terminal_id, item])), [terminals])
  const agentUpdateMap = useMemo(() => new Map(agentUpdates.map(item => [item.terminal_id, item])), [agentUpdates])
  const defaultPolicy = policies.find(item => item.is_default)
  const controlMode = defaultPolicy?.mode === 'enforce'
  const uniqueSoftware = new Set(software.map(item => item.software_key)).size
  const protectedCount = terminals.filter(item => item.defender_status === 'Protected' && item.firewall_enabled === true).length

  const requestCommand = async (terminalId: string, commandType: 'inventory' | 'remote_support') => {
    if (!supabase) return
    if (commandType === 'inventory') {
      const target = terminals.find(item => item.terminal_id === terminalId)
      const message = supportsInventoryUpgrade(target?.app_version)
        ? 'Refresh inventory and force a verified Smart Console update check? A newer approved version will install automatically and may restart the agent.'
        : 'This endpoint is using a legacy agent. Refresh will collect inventory only; its existing periodic updater must upgrade it first. Continue?'
      if (!window.confirm(message)) return
    }
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
  if (view === 'network') return <NetworkTrack />

  if (view === 'endpoints') return <section className="endpointSection">
    {error && <div className="errorBanner">{error}</div>}
    <div className="cards endpointCards">
      <Metric label="Managed endpoints" value={terminals.length.toString()} detail={`${terminals.filter(t => isOnline(t.last_seen_at)).length} currently online`} />
      <Metric label="Protected endpoints" value={protectedCount.toString()} detail="Defender + Firewall reporting healthy" />
      <Metric label="Software titles" value={uniqueSoftware.toString()} detail={`${software.length} endpoint installations`} />
      <Metric label="Policy mode" value={controlMode ? 'Control' : 'Audit'} detail={controlMode ? 'Software controls active' : 'Inventory only'} />
    </div>
    <div className="auditModeNotice"><strong>Agent updates and inventory refresh</strong><span>Smart Console 1.2.140+ checks for a newer verified release after inventory refresh. Older agents cannot interpret that new instruction and rely on their existing periodic updater. Update health is shown for agents that support telemetry; a queued command alone does not prove installation.</span></div>
    <div className="panel endpointTablePanel">
      <div className="panelTitle endpointPanelTitle">
        <span>Managed Endpoints</span>
        <div className="endpointExportActions">
          <button className="secondary compactButton" onClick={() => exportEndpointsExcel(terminals)}>Export Excel</button>
          <button className="secondary compactButton" onClick={() => exportEndpointsPdf(terminals)}>Export PDF</button>
        </div>
      </div>
      <div className="tableWrap"><table><thead><tr><th>Status</th><th>Computer</th><th>Windows</th><th>Device</th><th>Serial</th><th>Security</th><th>Memory</th><th>Inventory</th><th>Smart Console / Update</th><th /></tr></thead>
        <tbody>{terminals.map(item => <tr key={item.terminal_id}>
          <td><div className="endpointStatusCell"><Status online={isOnline(item.last_seen_at)} /><small>Last seen<br />{endpointLastSeen(item.last_seen_at)}</small></div></td>
          <td><strong>{item.computer_name}</strong><small>{item.windows_user || item.terminal_id}</small></td>
          <td>{item.os_name || 'Windows'}<small>{item.os_version || '—'}</small></td>
          <td>{[item.manufacturer, item.model].filter(Boolean).join(' ') || '—'}</td>
          <td className="mono">{item.serial_number || '—'}</td>
          <td><span className={item.defender_status === 'Protected' ? 'health good' : 'health warn'}>Defender: {item.defender_status || 'Unknown'}</span><small>Firewall: {item.firewall_enabled === true ? 'On' : item.firewall_enabled === false ? 'Off' : 'Unknown'}</small></td>
          <td>{bytes(item.total_memory_bytes)}</td><td>{dateTime(item.inventory_at)}</td>
          <td><strong>{item.app_version || 'Unknown'}</strong>{agentUpdateMap.get(item.terminal_id) ? <small title={agentUpdateMap.get(item.terminal_id)?.message || ''}>
            {agentUpdateMap.get(item.terminal_id)?.state || 'Not checked'}{agentUpdateMap.get(item.terminal_id)?.latest_version ? ' · latest ' + agentUpdateMap.get(item.terminal_id)?.latest_version : ''}<br />
            {agentUpdateMap.get(item.terminal_id)?.message || ''}<br />Checked: {dateTime(agentUpdateMap.get(item.terminal_id)?.last_checked_at)}
          </small> : <small>{supportsInventoryUpgrade(item.app_version) ? 'Awaiting update telemetry' : 'Legacy updater • no remote update status yet'}</small>}</td>
          <td><button className="linkButton" disabled={busy !== ''} onClick={() => requestCommand(item.terminal_id, 'inventory')}>{busy === `${item.terminal_id}:inventory` ? 'Queuing…' : supportsInventoryUpgrade(item.app_version) ? 'Refresh inventory + update' : 'Refresh inventory (legacy)'}</button>
            {!supportsInventoryUpgrade(item.app_version) && <small title="The existing periodic updater or a one-time verified installer upgrade is required first.">Update action unavailable until agent 1.2.140+</small>}</td>
        </tr>)}</tbody></table></div>
    </div>
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
