import { useEffect, useMemo, useState } from 'react'
import { supabase } from './lib/supabase'
import { DeploymentManager } from './DeploymentManager'
import { NetworkTrack } from './NetworkTrack'
import { useAppDialog } from './AppDialogs'
import './endpoint-manager.css'

export type EndpointView = 'endpoints' | 'smart-console' | 'network' | 'software' | 'deployment' | 'policies' | 'remote' | 'endpoint-audit'

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
  access_restricted?: boolean
  access_restricted_at?: string | null
  access_restricted_user?: string | null
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

const agentVersionAtLeast = (version: string | null | undefined, minimum: number) => {
  const v = (version || '').split('.').map(part => Number.parseInt(part, 10) || 0)
  return (v[0] || 0) > 1 || ((v[0] || 0) === 1 && ((v[1] || 0) > 2 || ((v[1] || 0) === 2 && (v[2] || 0) >= minimum)))
}
const supportsInventoryUpgrade = (version?: string | null) => agentVersionAtLeast(version, 140)
const supportsSeparateConsoleCommands = (version?: string | null) => agentVersionAtLeast(version, 152)
const supportsRemoteActions = (version?: string | null) => agentVersionAtLeast(version, 181)

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

type SoftwareApproval = {
  terminal_id: string
  software_key: string
  name: string
  version: string | null
  publisher: string | null
  status: 'pending' | 'approved' | 'denied'
  first_detected_at: string
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
  payload: { requestedAction?: string } | null
  result: { message?: string } | null
}
type OneDriveStatus = {
  terminal_id: string
  is_running: boolean | null
  account_configured: boolean | null
  user_email: string | null
  sync_root: string | null
  client_version: string | null
  tenant_id: string | null
  desktop_protected: boolean | null
  documents_protected: boolean | null
  pictures_protected: boolean | null
  health: string | null
  last_action: string | null
  last_error: string | null
  reported_at: string
}


type AuditRow = {
  audit_id: number
  terminal_id: string | null
  action: string
  details: Record<string, unknown>
  created_at: string
}

const dateTime = (value?: string | null) => value ? new Date(value).toLocaleString() : '—'
const isOnline = (lastSeen: string) => Date.now() - new Date(lastSeen).getTime() < 600_000
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
  const { confirm, notify } = useAppDialog()
  const [terminals, setTerminals] = useState<Terminal[]>([])
  const [software, setSoftware] = useState<Software[]>([])
  const [agentUpdates, setAgentUpdates] = useState<AgentUpdate[]>([])
  const [softwareRules, setSoftwareRules] = useState<SoftwareRule[]>([])
  const [softwareApprovals, setSoftwareApprovals] = useState<SoftwareApproval[]>([])
  const [policies, setPolicies] = useState<Policy[]>([])
  const [commands, setCommands] = useState<Command[]>([])
  const [oneDriveStatus, setOneDriveStatus] = useState<OneDriveStatus[]>([])
  const [audit, setAudit] = useState<AuditRow[]>([])
  const [search, setSearch] = useState('')
  const [consoleSearch, setConsoleSearch] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState('')
  const [expandedEndpoints, setExpandedEndpoints] = useState<Set<string>>(new Set())
  const [softwareTarget, setSoftwareTarget] = useState<Software | null>(null)
  const [selectedTargets, setSelectedTargets] = useState<Set<string>>(new Set())

  const load = async () => {
    if (!supabase || view === 'network' || view === 'deployment') return

    if (view === 'smart-console') {
      const results = await Promise.all([
        supabase.from('terminals')
          .select('terminal_id,computer_name,windows_user,app_version,enrollment_status,last_seen_at,serial_number')
          .order('last_seen_at', { ascending: false }),
        supabase.from('endpoint_commands')
          .select('command_id,terminal_id,command_type,status,requested_at,acknowledged_at,completed_at,payload,result')
          .order('requested_at', { ascending: false }).limit(120),
        supabase.from('endpoint_agent_update_status')
          .select('terminal_id,current_version,latest_version,state,message,last_checked_at,reported_at'),
      ])
      const firstError = results.find(result => result.error)?.error
      setError(firstError?.message || '')
      setTerminals((results[0].data ?? []) as Terminal[])
      setCommands((results[1].data ?? []) as Command[])
      setAgentUpdates((results[2].data ?? []) as AgentUpdate[])
      return
    }

    if (view === 'endpoints') {
      const results = await Promise.all([
        supabase.from('terminals')
          .select('terminal_id,computer_name,windows_user,app_version,enrollment_status,last_seen_at,os_name,os_version,manufacturer,model,serial_number,total_memory_bytes,processor_name,defender_status,firewall_enabled,inventory_at')
          .order('last_seen_at', { ascending: false }),
        supabase.from('installed_software')
          .select('terminal_id,software_key,name,version,publisher,install_location,executable_paths,last_seen_at')
          .order('name').limit(5000),
        supabase.from('endpoint_policies')
          .select('policy_id,name,description,mode,is_default,rules,updated_at')
          .order('is_default', { ascending: false }).order('name'),
      ])
      const firstError = results.find(result => result.error)?.error
      setError(firstError?.message || '')
      setTerminals((results[0].data ?? []) as Terminal[])
      setSoftware((results[1].data ?? []) as Software[])
      setPolicies((results[2].data ?? []) as Policy[])
      return
    }

    if (view === 'software') {
      const results = await Promise.all([
        supabase.from('terminals')
          .select('terminal_id,computer_name,windows_user,app_version,enrollment_status,last_seen_at')
          .order('computer_name'),
        supabase.from('installed_software')
          .select('terminal_id,software_key,name,version,publisher,install_location,executable_paths,last_seen_at')
          .order('name').limit(5000),
        supabase.from('software_control_rules')
          .select('rule_id,terminal_id,software_key,software_name,publisher,install_location,executable_paths,is_active')
          .eq('is_active', true).order('software_name'),
        supabase.from('endpoint_policies')
          .select('policy_id,name,description,mode,is_default,rules,updated_at')
          .order('is_default', { ascending: false }).order('name'),
        supabase.from('software_approvals')
          .select('terminal_id,software_key,name,version,publisher,status,first_detected_at')
          .order('first_detected_at', { ascending: false }).limit(5000),
      ])
      const firstError = results.find(result => result.error)?.error
      setError(firstError?.message || '')
      setTerminals((results[0].data ?? []) as Terminal[])
      setSoftware((results[1].data ?? []) as Software[])
      setSoftwareRules((results[2].data ?? []) as SoftwareRule[])
      setPolicies((results[3].data ?? []) as Policy[])
      setSoftwareApprovals((results[4].data ?? []) as SoftwareApproval[])
      return
    }

    if (view === 'policies') {
      const results = await Promise.all([
        supabase.from('endpoint_policies')
          .select('policy_id,name,description,mode,is_default,rules,updated_at')
          .order('is_default', { ascending: false }).order('name'),
        supabase.from('software_control_rules')
          .select('rule_id,terminal_id,software_key,software_name,publisher,install_location,executable_paths,is_active')
          .eq('is_active', true).order('software_name'),
      ])
      const firstError = results.find(result => result.error)?.error
      setError(firstError?.message || '')
      setPolicies((results[0].data ?? []) as Policy[])
      setSoftwareRules((results[1].data ?? []) as SoftwareRule[])
      return
    }

    if (view === 'remote') {
      const results = await Promise.all([
        supabase.from('terminals')
          .select('terminal_id,computer_name,windows_user,app_version,enrollment_status,last_seen_at,access_restricted,access_restricted_at,access_restricted_user')
          .order('computer_name'),
        supabase.from('endpoint_commands')
          .select('command_id,terminal_id,command_type,status,requested_at,acknowledged_at,completed_at,payload,result')
          .order('requested_at', { ascending: false }).limit(160),
        supabase.from('endpoint_onedrive_status')
          .select('terminal_id,is_running,account_configured,user_email,sync_root,client_version,tenant_id,desktop_protected,documents_protected,pictures_protected,health,last_action,last_error,reported_at'),
      ])
      const firstError = results.find(result => result.error)?.error
      setError(firstError?.message || '')
      setTerminals((results[0].data ?? []) as Terminal[])
      setCommands((results[1].data ?? []) as Command[])
      setOneDriveStatus((results[2].data ?? []) as OneDriveStatus[])
      return
    }

    const results = await Promise.all([
      supabase.from('terminals')
        .select('terminal_id,computer_name,windows_user,app_version,enrollment_status,last_seen_at')
        .order('computer_name'),
      supabase.from('endpoint_audit_log')
        .select('audit_id,terminal_id,action,details,created_at')
        .order('created_at', { ascending: false }).limit(250),
    ])
    const firstError = results.find(result => result.error)?.error
    setError(firstError?.message || '')
    setTerminals((results[0].data ?? []) as Terminal[])
    setAudit((results[1].data ?? []) as AuditRow[])
  }

  useEffect(() => {
    if (view === 'network' || view === 'deployment') return
    void load()
    const refresh = () => {
      if (document.visibilityState === 'visible') void load()
    }
    const timer = window.setInterval(refresh, 120_000)
    document.addEventListener('visibilitychange', refresh)
    return () => {
      window.clearInterval(timer)
      document.removeEventListener('visibilitychange', refresh)
    }
  }, [view])

  const terminalMap = useMemo(() => new Map(terminals.map(item => [item.terminal_id, item])), [terminals])
  const agentUpdateMap = useMemo(() => new Map(agentUpdates.map(item => [item.terminal_id, item])), [agentUpdates])
  const approvalMap = useMemo(() => new Map(softwareApprovals.map(item => [item.terminal_id + ':' + item.software_key,item])), [softwareApprovals])
  const awaitingReview = softwareApprovals.filter(item => item.status !== 'approved')
  const defaultPolicy = policies.find(item => item.is_default)
  const controlMode = defaultPolicy?.mode === 'enforce'
  const uniqueSoftware = new Set(software.map(item => item.software_key)).size
  const protectedCount = terminals.filter(item => item.defender_status === 'Protected' && item.firewall_enabled === true).length
  const activeTerminals = terminals.filter(item => item.enrollment_status === 'active')
  const filteredConsoleTerminals = activeTerminals.filter(item =>
    [item.computer_name, item.windows_user, item.serial_number, item.app_version, item.terminal_id]
      .some(value => value?.toLowerCase().includes(consoleSearch.trim().toLowerCase())))
  const latestConsoleCommand = (terminalId: string, type: 'force_update' | 'cloud_sync') =>
    commands.find(command => command.terminal_id === terminalId &&
      (command.command_type === type ||
        (type === 'force_update' && command.command_type === 'inventory' && command.payload?.requestedAction === type)))

  const requestCommand = async (terminalId: string, commandType: 'inventory' | 'remote_support' | 'force_update' | 'cloud_sync') => {
    if (!supabase) return
    const target = terminals.find(item => item.terminal_id === terminalId)
    if (!target || target.enrollment_status !== 'active') return

    if (commandType === 'inventory' && !supportsSeparateConsoleCommands(target.app_version)) {
      const accepted = await confirm({
        title: 'Continue with legacy inventory refresh?',
        message: 'This older agent still combines inventory refresh with its update check.',
        confirmLabel: 'Continue',
        tone: 'warning',
      })
      if (!accepted) return
    }

    if (commandType === 'force_update') {
      const accepted = await confirm({
        title: 'Enforce Smart Console update?',
        message: `The latest approved, SHA-256 verified Smart Console update will be enforced on ${target.computer_name}. Installation may restart the agent.`,
        confirmLabel: 'Enforce update',
        tone: 'warning',
      })
      if (!accepted) return
    }

    setBusy(`${terminalId}:${commandType}`); setError('')
    try {
      const { data, error: invokeError } = await supabase.functions.invoke('terminal-admin', {
        body: { action: 'request_command', terminalId, commandType },
      })
      if (invokeError || data?.error) {
        const message = data?.error || invokeError?.message || 'Could not queue endpoint command'
        setError(message)
        await notify({ title: 'Endpoint action failed', message, tone: 'danger' })
      } else {
        await load()
        await notify({
          title: 'Endpoint action queued',
          message: `${commandType === 'force_update' ? 'Smart Console update' : commandType === 'cloud_sync' ? 'Cloud sync' : 'Inventory refresh'} was queued for ${target.computer_name}.`,
          tone: 'success',
        })
      }
    } finally {
      setBusy('')
    }
  }

  const requestRemoteAction = async (
    terminalId: string,
    remoteAction: 'lock' | 'sign_out' | 'restart' | 'shutdown' | 'restrict_access' | 'restore_access' |
      'onedrive_status' | 'onedrive_start' | 'onedrive_restart' | 'enable_folder_protection',
  ) => {
    if (!supabase) return
    const target = terminals.find(item => item.terminal_id === terminalId)
    if (!target || target.enrollment_status !== 'active') return
    if (!supportsRemoteActions(target.app_version)) {
      const message = 'Update this endpoint to Smart Console Agent 1.2.181 or newer before using managed remote actions.'
      setError(message)
      await notify({ title: 'Remote action unavailable', message, tone: 'warning' })
      return
    }

    const confirmations: Record<string, string> = {
      lock: `Lock ${target.computer_name} now? The signed-in user will need to unlock Windows again.`,
      sign_out: `Sign out the current user on ${target.computer_name}? Unsaved work may be lost.`,
      restart: `Restart ${target.computer_name}? Windows will give the user 60 seconds to save work.`,
      shutdown: `Shut down ${target.computer_name}? Windows will give the user 60 seconds to save work.`,
      restrict_access: `Restrict interactive sign-in on ${target.computer_name}? The current managed user will be locked out, but the Smart Console service and network management channel will stay active so IT can restore access.`,
      restore_access: `Restore interactive sign-in on ${target.computer_name}?`,
      onedrive_start: `Start OneDrive for the signed-in user on ${target.computer_name}?`,
      onedrive_restart: `Restart OneDrive on ${target.computer_name}? This does not delete local or cloud files.`,
      enable_folder_protection: `Enable CRECCOM OneDrive folder protection on ${target.computer_name}? Desktop, Documents and Pictures will be redirected through Microsoft's Known Folder Move policy when OneDrive processes the policy.`,
    }
    const confirmation = confirmations[remoteAction]
    if (confirmation) {
      const accepted = await confirm({
        title: 'Confirm remote action',
        message: confirmation,
        confirmLabel: 'Continue',
        tone: ['restart','shutdown','restrict_access','sign_out'].includes(remoteAction) ? 'warning' : 'info',
      })
      if (!accepted) return
    }

    setBusy(`${terminalId}:${remoteAction}`); setError('')
    try {
      const { data, error: invokeError } = await supabase.functions.invoke('terminal-admin', {
        body: { action: 'request_remote_action', terminalId, remoteAction },
      })
      if (invokeError || data?.error) {
        const message = data?.error || invokeError?.message || 'Could not queue the managed endpoint action.'
        setError(message)
        await notify({ title: 'Remote action failed', message, tone: 'danger' })
      } else {
        await load()
        await notify({
          title: 'Remote action queued',
          message: `${remoteAction.replace(/_/g, ' ')} was queued successfully for ${target.computer_name}.`,
          tone: 'success',
        })
      }
    } finally {
      setBusy('')
    }
  }

  const setPolicyMode = async (nextMode: 'audit' | 'enforce') => {
    if (!supabase || nextMode === defaultPolicy?.mode) return
    if (nextMode === 'enforce') {
      const accepted = await confirm({
        title: 'Turn on Control mode?',
        message: 'Active software block rules will begin enforcing when endpoints receive the policy.',
        confirmLabel: 'Turn on Control mode',
        tone: 'warning',
      })
      if (!accepted) return
    }

    setBusy('policy-mode'); setError('')
    const { data, error: invokeError } = await supabase.functions.invoke('terminal-admin', {
      body: { action: 'set_policy_mode', mode: nextMode },
    })
    if (invokeError || data?.error) {
      const message = data?.error || invokeError?.message || 'Could not change policy mode'
      setError(message)
      await notify({ title: 'Policy update failed', message, tone: 'danger' })
    } else {
      await load()
      await notify({
        title: 'Policy mode updated',
        message: `Software Control is now in ${nextMode === 'enforce' ? 'Control' : 'Audit'} mode.`,
        tone: 'success',
      })
    }
    setBusy('')
  }

  const reviewApplication = async (item: SoftwareApproval, decision: 'approved' | 'denied') => {
    if (!supabase) return
    const accepted = await confirm({
      title: decision === 'approved' ? 'Approve application?' : 'Keep application blocked?',
      message: `${item.name}${item.publisher ? ' · ' + item.publisher : ''}`,
      confirmLabel: decision === 'approved' ? 'Approve' : 'Keep blocked',
      tone: decision === 'approved' ? 'info' : 'warning',
    })
    if (!accepted) return

    setBusy(item.terminal_id + ':' + item.software_key); setError('')
    try {
      const { data, error: invokeError } = await supabase.functions.invoke('terminal-admin', {
        body: { action: 'review_software_approval',terminalId:item.terminal_id,softwareKey:item.software_key,decision },
      })
      if (invokeError || data?.error) {
        const message = data?.error || invokeError?.message || 'Could not record software review'
        setError(message)
        await notify({ title: 'Software review failed', message, tone: 'danger' })
      } else {
        await load()
        await notify({
          title: decision === 'approved' ? 'Application approved' : 'Application remains blocked',
          message: `${item.name} was updated successfully.`,
          tone: 'success',
        })
      }
    } finally { setBusy('') }
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
      const message = data?.error || invokeError?.message || 'Could not save software control targets'
      setError(message)
      await notify({ title: 'Software targeting failed', message, tone: 'danger' })
    } else {
      setSoftwareTarget(null)
      await load()
      await notify({
        title: 'Software targets updated',
        message: 'The software-control target list was saved successfully.',
        tone: 'success',
      })
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
    <div className="auditModeNotice"><strong>Inventory only</strong><span>Manage agent versions, verified remote updates and cloud synchronization from Endpoint Manager → Smart Console. Agents older than 1.2.152 retain their legacy combined inventory/update behaviour until upgraded.</span></div>
    <div className="panel endpointTablePanel">
      <div className="panelTitle endpointPanelTitle">
        <span>Managed Endpoints</span>
        <div className="endpointExportActions">
          <button className="secondary compactButton" onClick={() => exportEndpointsExcel(terminals)}>Export Excel</button>
          <button className="secondary compactButton" onClick={() => exportEndpointsPdf(terminals)}>Export PDF</button>
        </div>
      </div>
      <div className="tableWrap"><table><thead><tr><th>Status</th><th>Computer</th><th>Windows</th><th>Device</th><th>Serial</th><th>Security</th><th>Memory</th><th>Inventory</th><th /></tr></thead>
        <tbody>{terminals.map(item => <tr key={item.terminal_id}>
          <td><div className="endpointStatusCell"><Status online={isOnline(item.last_seen_at)} /><small>Last seen<br />{endpointLastSeen(item.last_seen_at)}</small></div></td>
          <td><strong>{item.computer_name}</strong><small>{item.windows_user || item.terminal_id}</small></td>
          <td>{item.os_name || 'Windows'}<small>{item.os_version || '—'}</small></td>
          <td>{[item.manufacturer, item.model].filter(Boolean).join(' ') || '—'}</td>
          <td className="mono">{item.serial_number || '—'}</td>
          <td><span className={item.defender_status === 'Protected' ? 'health good' : 'health warn'}>Defender: {item.defender_status || 'Unknown'}</span><small>Firewall: {item.firewall_enabled === true ? 'On' : item.firewall_enabled === false ? 'Off' : 'Unknown'}</small></td>
          <td>{bytes(item.total_memory_bytes)}</td><td>{dateTime(item.inventory_at)}</td>
          <td><button className="linkButton" disabled={busy !== '' || item.enrollment_status !== 'active'} onClick={() => requestCommand(item.terminal_id, 'inventory')}>{busy === `${item.terminal_id}:inventory` ? 'Queuing…' : 'Refresh inventory'}</button></td>
        </tr>)}</tbody></table></div>
    </div>
  </section>


  if (view === 'smart-console') return <section className="endpointSection smartConsolePage">
    {error && <div className="errorBanner">{error}</div>}
    <div className="cards endpointCards">
      <Metric label="Managed terminals" value={activeTerminals.length.toString()} detail="Active enrollment" />
      <Metric label="Online now" value={activeTerminals.filter(item => isOnline(item.last_seen_at)).length.toString()} detail="Heartbeat within 10 minutes" />
      <Metric label="Update in progress" value={commands.filter(item => (item.command_type === 'force_update' || item.payload?.requestedAction === 'force_update') && ['pending', 'acknowledged', 'running'].includes(item.status)).length.toString()} detail="Requests not yet acknowledged" />
      <Metric label="Sync requests pending" value={commands.filter(item => item.command_type === 'cloud_sync' && ['pending', 'acknowledged', 'running'].includes(item.status)).length.toString()} detail="Waiting for agent response" />
    </div>
    <div className="auditModeNotice smartConsoleNotice">
      <strong>Agent management</strong>
      <span>Remote update uses only the approved managed release with package verification. A completed update request means the agent accepted it; confirm installation using the reported version and update state. Offline PCs receive queued actions when their cloud connection resumes.</span>
    </div>
    <div className="panel">
      <div className="panelTitle smartConsoleToolbar">
        <span>Smart Console terminals</span>
        <div>
          <input aria-label="Search Smart Console terminals" placeholder="Search computer, user, serial or version" value={consoleSearch} onChange={event => setConsoleSearch(event.target.value)} />
          <button className="secondary compactButton" onClick={load} disabled={busy !== ''}>Refresh status</button>
        </div>
      </div>
      <div className="tableWrap"><table className="smartConsoleTable"><thead><tr>
        <th>Terminal</th><th>Connection</th><th>Installed</th><th>Latest reported</th><th>Update health</th><th>Remote actions</th>
      </tr></thead><tbody>
        {filteredConsoleTerminals.length === 0 && <tr><td className="empty" colSpan={6}>No active terminals match the search.</td></tr>}
        {filteredConsoleTerminals.map(item => {
          const status = agentUpdateMap.get(item.terminal_id)
          const updateCommand = latestConsoleCommand(item.terminal_id, 'force_update')
          const syncCommand = latestConsoleCommand(item.terminal_id, 'cloud_sync')
          const online = isOnline(item.last_seen_at)
          const updateReady = supportsInventoryUpgrade(item.app_version)
          const syncReady = supportsSeparateConsoleCommands(item.app_version)
          const updateWorking = updateCommand && ['pending','acknowledged','running'].includes(updateCommand.status)
          const syncWorking = syncCommand && ['pending','acknowledged','running'].includes(syncCommand.status)
          return <tr key={item.terminal_id}>
            <td><strong>{item.computer_name}</strong><small>{item.windows_user || 'No signed-in user'}</small><small title={item.terminal_id}>{item.serial_number || item.terminal_id}</small></td>
            <td><Status online={online} /><small>Last seen {dateTime(item.last_seen_at)}</small></td>
            <td><strong className="mono">{item.app_version || 'Unknown'}</strong>{!syncReady && <small className="smartLegacyLabel">Legacy management protocol</small>}</td>
            <td><strong className="mono">{status?.latest_version || 'Not reported'}</strong><small>Checked {dateTime(status?.last_checked_at)}</small></td>
            <td><span className="smartUpdateState">{status?.state || 'Awaiting telemetry'}</span><small title={status?.message || ''}>{status?.message || 'Agent has not yet submitted update status.'}</small>
              {updateCommand && <small>Update request: <span className={`commandStatus ${updateCommand.status}`}>{updateCommand.status}</span> · {dateTime(updateCommand.completed_at || updateCommand.requested_at)}</small>}
              {syncCommand && <small>Cloud sync: <span className={`commandStatus ${syncCommand.status}`}>{syncCommand.status}</span> · {dateTime(syncCommand.completed_at || syncCommand.requested_at)}</small>}
            </td>
            <td><div className="smartConsoleActions">
              <button className="primary compactButton" disabled={!online || !updateReady || busy !== '' || Boolean(updateWorking)}
                title={!updateReady ? 'Agents before 1.2.140 must upgrade through their existing periodic updater or verified installer.' : !online ? 'Updates require an active cloud connection.' : 'Request the latest approved release.'}
                onClick={() => requestCommand(item.terminal_id, 'force_update')}>{busy === `${item.terminal_id}:force_update` ? 'Queuing…' : updateWorking ? 'Update queued' : 'Force update'}</button>
              <button className="secondary compactButton" disabled={!online || !syncReady || busy !== '' || Boolean(syncWorking)}
                title={!syncReady ? 'Requires the new management protocol (agent 1.2.152+).' : !online ? 'An agent must reconnect before a remote command can be delivered.' : 'Request immediate cloud synchronization.'}
                onClick={() => requestCommand(item.terminal_id, 'cloud_sync')}>{busy === `${item.terminal_id}:cloud_sync` ? 'Queuing…' : syncWorking ? 'Sync queued' : 'Force cloud sync'}</button>
              {!syncReady && <small>Update agent to 1.2.152+ to unlock separate sync controls.</small>}
            </div></td>
          </tr>
        })}
      </tbody></table></div>
    </div>
  </section>

  if (view === 'software') {
    const targetCandidates = softwareTarget ? software.filter(item => item.software_key === softwareTarget.software_key) : []

    return <section className="endpointSection">
      {error && <div className="errorBanner">{error}</div>}
      <div className="panel">
        <div className="panelTitle">New application approvals · {awaitingReview.length} awaiting review</div>
        <div className="auditModeNotice">
          <strong>Install allowed · run after approval</strong>
          <span>Previously inventoried software stays approved. Newly detected applications require IT review. A runnable path must be identified before the agent can enforce a restriction, and Control mode must be active.</span>
        </div>
        <div className="tableWrap"><table><thead><tr>
          <th>Application</th><th>Terminal</th><th>Detected</th><th>Review</th><th>Restriction</th><th>Actions</th>
        </tr></thead><tbody>
          {awaitingReview.length === 0 && <tr><td colSpan={6} className="empty">No new applications are awaiting review.</td></tr>}
          {awaitingReview.map(item => {
            const restricted = softwareRules.some(rule => rule.terminal_id === item.terminal_id && rule.software_key === item.software_key && rule.is_active)
            const key = item.terminal_id + ':' + item.software_key
            return <tr key={key}>
              <td><strong>{item.name}</strong><small>{item.publisher || 'Unknown publisher'} · {item.version || 'Version unavailable'}</small></td>
              <td>{terminalMap.get(item.terminal_id)?.computer_name || item.terminal_id}</td>
              <td>{dateTime(item.first_detected_at)}</td>
              <td><span className={item.status === 'denied' ? 'softwareState blocked' : 'softwareState pending'}>{item.status === 'denied' ? 'Denied' : 'Pending approval'}</span></td>
              <td>{restricted ? (controlMode ? 'Queued / enforced on sync' : 'Configured · Audit mode') : 'Executable path needed'}</td>
              <td><div className="approvalActions">
                <button className="primary compactButton" disabled={busy !== ''} onClick={() => reviewApplication(item,'approved')}>{busy === key ? 'Saving…' : 'Approve'}</button>
                {item.status !== 'denied' && <button className="secondary compactButton" disabled={busy !== ''} onClick={() => reviewApplication(item,'denied')}>Deny</button>}
              </div></td>
            </tr>
          })}
        </tbody></table></div>
      </div>

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
                  const approval = approvalMap.get(item.terminal_id + ':' + item.software_key)
                  const pendingApproval = Boolean(approval && approval.status !== 'approved')
                  const eligible = canBlockSoftware(item)
                  return <tr key={`${item.terminal_id}-${item.software_key}`}>
                    <td><strong>{item.name}</strong>{!eligible && <small className="muted">Refresh inventory to detect an executable or install location.</small>}</td>
                    <td>{item.version || '—'}</td>
                    <td>{item.publisher || '—'}</td>
                    <td>{pendingApproval ? <span className="softwareState blocked">{approval?.status === 'denied' ? 'Denied by IT' : 'Awaiting IT approval'}</span> : blocked ? <span className="softwareState blocked">Blocked</span> : <span className="softwareState allowed">{controlMode ? 'Approved / allowed' : 'Observed'}</span>}</td>
                    <td>{dateTime(item.last_seen_at)}</td>
                    <td><button className="linkButton" disabled={pendingApproval || !controlMode || busy !== '' || !eligible} onClick={() => openSoftwareTargets(item)}>{pendingApproval ? 'Review above' : blocked ? 'Manage block' : 'Block / manage'}</button></td>
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

  if (view === 'remote') {
    const oneDriveMap = new Map(oneDriveStatus.map(item => [item.terminal_id, item]))
    const live = terminals.filter(item => item.enrollment_status !== 'revoked')
    const restricted = live.filter(item => item.access_restricted).length
    const protectedOneDrive = oneDriveStatus.filter(item =>
      item.is_running && item.desktop_protected && item.documents_protected && item.pictures_protected).length

    return <section className="endpointSection remoteSupportPage">
      {error && <div className="errorBanner">{error}</div>}
      <div className="cards endpointCards">
        <Metric label="Managed endpoints" value={live.length.toString()} detail={`${live.filter(item => isOnline(item.last_seen_at)).length} currently online`} />
        <Metric label="Access restricted" value={restricted.toString()} detail="Interactive sign-in restrictions" />
        <Metric label="OneDrive protected" value={protectedOneDrive.toString()} detail="Desktop + Documents + Pictures" />
        <Metric label="Action channel" value="Managed" detail="Admin-only and audited" />
      </div>

      <div className="auditModeNotice">
        <strong>Endpoint Actions & Security Response</strong>
        <span>Commands are queued through Smart Console and executed by the Windows service. Lock, restart, shutdown and access restriction require explicit administrator confirmation. Access restriction blocks only the recorded interactive user and keeps the Smart Console service online for recovery.</span>
      </div>

      <Panel title="Device control">
        <div className="tableWrap"><table className="remoteActionTable"><thead><tr>
          <th>Endpoint</th><th>Status</th><th>Access</th><th>Session actions</th><th>Power</th><th>Security response</th>
        </tr></thead><tbody>{live.map(item => {
          const supported = supportsRemoteActions(item.app_version)
          return <tr key={item.terminal_id}>
            <td><strong>{item.computer_name}</strong><small>{item.windows_user || 'No interactive user'} · v{item.app_version || '—'}</small></td>
            <td><Status online={isOnline(item.last_seen_at)} /><small>{dateTime(item.last_seen_at)}</small></td>
            <td>{item.access_restricted
              ? <span className="health warn">Restricted</span>
              : <span className="health good">Available</span>}<small>{item.access_restricted_user || (supported ? 'Managed' : 'Agent update required')}</small></td>
            <td><div className="remoteActionGroup">
              <button className="secondary compactButton" disabled={!supported || busy !== ''} onClick={() => requestRemoteAction(item.terminal_id,'lock')}>{busy===`${item.terminal_id}:lock`?'Queuing…':'Lock'}</button>
              <button className="secondary compactButton" disabled={!supported || busy !== ''} onClick={() => requestRemoteAction(item.terminal_id,'sign_out')}>Sign out</button>
            </div></td>
            <td><div className="remoteActionGroup">
              <button className="secondary compactButton" disabled={!supported || busy !== ''} onClick={() => requestRemoteAction(item.terminal_id,'restart')}>Restart</button>
              <button className="secondary compactButton" disabled={!supported || busy !== ''} onClick={() => requestRemoteAction(item.terminal_id,'shutdown')}>Shutdown</button>
            </div></td>
            <td>{item.access_restricted
              ? <button className="primary compactButton" disabled={!supported || busy !== ''} onClick={() => requestRemoteAction(item.terminal_id,'restore_access')}>Restore access</button>
              : <button className="secondary compactButton dangerAction" disabled={!supported || busy !== ''} onClick={() => requestRemoteAction(item.terminal_id,'restrict_access')}>Restrict access</button>}</td>
          </tr>
        })}</tbody></table></div>
      </Panel>

      <Panel title="OneDrive protection">
        <div className="tableWrap"><table className="remoteActionTable"><thead><tr>
          <th>Endpoint</th><th>OneDrive</th><th>Folder protection</th><th>Account</th><th>Last checked</th><th>Actions</th>
        </tr></thead><tbody>{live.map(item => {
          const status = oneDriveMap.get(item.terminal_id)
          const supported = supportsRemoteActions(item.app_version)
          const folders = status
            ? [status.desktop_protected ? 'Desktop' : null,status.documents_protected ? 'Documents' : null,status.pictures_protected ? 'Pictures' : null].filter(Boolean).join(', ')
            : ''
          return <tr key={item.terminal_id}>
            <td><strong>{item.computer_name}</strong><small>v{item.app_version || '—'}</small></td>
            <td>{status
              ? <span className={status.is_running ? 'health good' : 'health warn'}>{status.is_running ? 'Running' : status.account_configured ? 'Stopped' : 'Not configured'}</span>
              : <span className="health warn">Not checked</span>}<small>{status?.client_version || '—'}</small></td>
            <td>{status
              ? <span className={status.desktop_protected && status.documents_protected && status.pictures_protected ? 'health good' : 'health warn'}>
                  {status.desktop_protected && status.documents_protected && status.pictures_protected ? 'Protected' : 'Partial / off'}
                </span>
              : '—'}<small>{folders || 'Desktop · Documents · Pictures'}</small></td>
            <td>{status?.user_email || '—'}<small>{status?.sync_root || ''}</small></td>
            <td>{dateTime(status?.reported_at)}</td>
            <td><div className="remoteActionGroup">
              <button className="secondary compactButton" disabled={!supported || busy !== ''} onClick={() => requestRemoteAction(item.terminal_id,'onedrive_status')}>Check</button>
              <button className="secondary compactButton" disabled={!supported || busy !== ''} onClick={() => requestRemoteAction(item.terminal_id,'onedrive_start')}>Start</button>
              <button className="secondary compactButton" disabled={!supported || busy !== ''} onClick={() => requestRemoteAction(item.terminal_id,'onedrive_restart')}>Restart</button>
              <button className="primary compactButton" disabled={!supported || busy !== ''} onClick={() => requestRemoteAction(item.terminal_id,'enable_folder_protection')}>Protect folders</button>
            </div></td>
          </tr>
        })}</tbody></table></div>
      </Panel>

      <Panel title="User-assisted Quick Assist">
        <div className="tableWrap"><table><thead><tr><th>Endpoint</th><th>User</th><th>Status</th><th>Last seen</th><th>Action</th></tr></thead><tbody>{live.map(item => <tr key={item.terminal_id}><td><strong>{item.computer_name}</strong></td><td>{item.windows_user || '—'}</td><td><Status online={isOnline(item.last_seen_at)} /></td><td>{dateTime(item.last_seen_at)}</td><td><button className="secondary compactButton" disabled={!isOnline(item.last_seen_at) || busy !== ''} onClick={() => requestCommand(item.terminal_id, 'remote_support')}>{busy === `${item.terminal_id}:remote_support` ? 'Queuing…' : 'Send Support Notice'}</button></td></tr>)}</tbody></table></div>
      </Panel>

      <Panel title="Recent endpoint commands"><div className="tableWrap"><table><thead><tr><th>Requested</th><th>Endpoint</th><th>Command</th><th>Status</th><th>Result</th><th>Completed</th></tr></thead><tbody>{commands.length === 0 ? <tr><td colSpan={6} className="empty">No endpoint commands yet.</td></tr> : commands.map(item => <tr key={item.command_id}><td>{dateTime(item.requested_at)}</td><td>{terminalMap.get(item.terminal_id)?.computer_name || item.terminal_id}</td><td>{item.command_type.replaceAll('_', ' ')}{item.payload?.requestedAction ? <small>{item.payload.requestedAction.replaceAll('_',' ')}</small> : null}</td><td><span className={`commandStatus ${item.status}`}>{item.status}</span></td><td>{item.result?.message || '—'}</td><td>{dateTime(item.completed_at)}</td></tr>)}</tbody></table></div></Panel>
    </section>
  }

  return <section className="endpointSection">
    {error && <div className="errorBanner">{error}</div>}
    <Panel title="Endpoint management audit log"><div className="tableWrap"><table><thead><tr><th>Time</th><th>Endpoint</th><th>Action</th><th>Details</th></tr></thead><tbody>{audit.length === 0 ? <tr><td colSpan={4} className="empty">No endpoint administration events yet.</td></tr> : audit.map(item => <tr key={item.audit_id}><td>{dateTime(item.created_at)}</td><td>{item.terminal_id ? terminalMap.get(item.terminal_id)?.computer_name || item.terminal_id : 'Console'}</td><td><strong>{item.action}</strong></td><td className="jsonDetails">{JSON.stringify(item.details)}</td></tr>)}</tbody></table></div></Panel>
  </section>
}

function Metric({ label, value, detail }: { label: string, value: string, detail: string }) { return <div className="metric"><span>{label}</span><strong>{value}</strong><small>{detail}</small></div> }
function Panel({ title, children }: { title: string, children: React.ReactNode }) { return <div className="panel"><div className="panelTitle">{title}</div>{children}</div> }
function Status({ online }: { online: boolean }) { return <span className={online ? 'status online' : 'status offline'}><i />{online ? 'Online' : 'Offline'}</span> }
