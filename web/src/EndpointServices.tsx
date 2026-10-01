import { useEffect, useMemo, useState } from 'react'
import { supabase } from './lib/supabase'
import { useAppDialog } from './AppDialogs'
import './endpoint-services.css'

type EndpointServiceRow = {
  terminal_id: string
  computer_name: string
  windows_user: string | null
  app_version: string | null
  enrollment_status: 'active' | 'revoked'
  last_seen_at: string
  usb_audit_enabled: boolean
  network_service_enabled: boolean
  location_service_enabled: boolean
  inventory_service_enabled: boolean
  deployment_service_enabled: boolean
  software_control_service_enabled: boolean
  remote_support_service_enabled: boolean
  service_policy_updated_at: string | null
}

type ServiceKey =
  | 'usbAudit'
  | 'network'
  | 'location'
  | 'inventory'
  | 'deployment'
  | 'softwareControl'
  | 'remoteSupport'

const serviceColumn: Record<ServiceKey, keyof EndpointServiceRow> = {
  usbAudit: 'usb_audit_enabled',
  network: 'network_service_enabled',
  location: 'location_service_enabled',
  inventory: 'inventory_service_enabled',
  deployment: 'deployment_service_enabled',
  softwareControl: 'software_control_service_enabled',
  remoteSupport: 'remote_support_service_enabled',
}

const services: Array<{ key: ServiceKey, label: string, detail: string }> = [
  { key: 'usbAudit', label: 'USB Audit', detail: 'USB connection and file-transfer activity' },
  { key: 'network', label: 'Network Track', detail: 'Network, adapter and IP telemetry' },
  { key: 'location', label: 'Location', detail: 'Consented precise-location telemetry' },
  { key: 'inventory', label: 'Inventory', detail: 'Hardware and installed-software inventory' },
  { key: 'deployment', label: 'App Deployment', detail: 'Managed application delivery and install' },
  { key: 'softwareControl', label: 'Software Control', detail: 'Application approval and block enforcement' },
  { key: 'remoteSupport', label: 'Remote Support', detail: 'Remote-support commands from IT' },
]

const dateTime = (value?: string | null) => value ? new Date(value).toLocaleString() : '—'
const isOnline = (value: string) => Date.now() - new Date(value).getTime() < 10 * 60_000

export function EndpointServices() {
  const { confirm, notify } = useAppDialog()
  const [rows, setRows] = useState<EndpointServiceRow[]>([])
  const [usbServer, setUsbServer] = useState('')
  const [busy, setBusy] = useState('')
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')

  const load = async () => {
    if (!supabase) return
    const { data, error: queryError } = await supabase.from('terminals')
      .select('terminal_id,computer_name,windows_user,app_version,enrollment_status,last_seen_at,usb_audit_enabled,network_service_enabled,location_service_enabled,inventory_service_enabled,deployment_service_enabled,software_control_service_enabled,remote_support_service_enabled,service_policy_updated_at')
      .eq('enrollment_status', 'active')
      .order('computer_name')
    if (queryError) {
      setError(queryError.message)
      return
    }
    const next = (data ?? []) as EndpointServiceRow[]
    setRows(next)
    const selected = next.find(item => item.usb_audit_enabled)
    if (selected) setUsbServer(selected.terminal_id)
  }

  useEffect(() => {
    void load()
    const refresh = () => {
      if (document.visibilityState === 'visible') void load()
    }
    const timer = window.setInterval(refresh, 300_000)
    document.addEventListener('visibilitychange', refresh)
    return () => {
      window.clearInterval(timer)
      document.removeEventListener('visibilitychange', refresh)
    }
  }, [])

  const usbEnabled = rows.filter(item => item.usb_audit_enabled)
  const online = rows.filter(item => isOnline(item.last_seen_at)).length
  const enabledCount = useMemo(() => rows.reduce((total, row) => total + services.filter(service => Boolean(row[serviceColumn[service.key]])).length, 0), [rows])

  const setService = async (row: EndpointServiceRow, key: ServiceKey, enabled: boolean) => {
    if (!supabase) return
    const serviceLabel = services.find(item => item.key === key)?.label || 'Service'
    const accepted = await confirm({
      title: `${enabled ? 'Enable' : 'Disable'} ${serviceLabel}?`,
      message: `Apply this service change to ${row.computer_name}? The endpoint will receive it on its next heartbeat.`,
      confirmLabel: enabled ? 'Enable service' : 'Disable service',
      tone: enabled ? 'info' : 'warning',
    })
    if (!accepted) return

    setBusy(`${row.terminal_id}:${key}`)
    setError(''); setNotice('')
    const { data, error: invokeError } = await supabase.functions.invoke('terminal-admin', {
      body: {
        action: 'set_terminal_services',
        terminalId: row.terminal_id,
        services: { [key]: enabled },
      },
    })
    if (invokeError || data?.error) {
      const message = data?.error || invokeError?.message || 'Could not update endpoint services.'
      setError(message)
      await notify({ title: 'Service update failed', message, tone: 'danger' })
    } else {
      setRows(current => current.map(item => item.terminal_id === row.terminal_id
        ? { ...item, [serviceColumn[key]]: enabled, service_policy_updated_at: new Date().toISOString() }
        : item))
      const message = `${serviceLabel} ${enabled ? 'enabled' : 'disabled'} for ${row.computer_name}. The endpoint will apply it on its next heartbeat.`
      setNotice(message)
      await notify({ title: 'Service updated', message, tone: 'success' })
    }
    setBusy('')
  }

  const designateUsbServer = async () => {
    if (!supabase || !usbServer) return
    const selected = rows.find(item => item.terminal_id === usbServer)
    if (!selected) return

    const accepted = await confirm({
      title: 'Designate USB Audit endpoint?',
      message: `${selected.computer_name} will become the only endpoint running USB Audit. USB Audit will be disabled on all other active endpoints.`,
      confirmLabel: 'Designate endpoint',
      tone: 'warning',
    })
    if (!accepted) return

    setBusy('usb-server')
    setError(''); setNotice('')
    const { data, error: invokeError } = await supabase.functions.invoke('terminal-admin', {
      body: { action: 'set_usb_audit_server', terminalId: usbServer },
    })
    if (invokeError || data?.error) {
      const message = data?.error || invokeError?.message || 'Could not designate the USB Audit endpoint.'
      setError(message)
      await notify({ title: 'USB Audit designation failed', message, tone: 'danger' })
    } else {
      setRows(current => current.map(item => ({ ...item, usb_audit_enabled: item.terminal_id === usbServer })))
      const message = `${selected.computer_name} is now the designated USB Audit endpoint. USB monitoring is off on the other managed endpoints.`
      setNotice(message)
      await notify({ title: 'USB Audit endpoint updated', message, tone: 'success' })
    }
    setBusy('')
  }

  return <section className="endpointServices endpointSection">
    {error && <div className="errorBanner">{error}</div>}
    {notice && <div className="servicesNotice">{notice}</div>}

    <div className="servicesHero">
      <div>
        <span className="servicesEyebrow">Endpoint Manager</span>
        <h2>Services</h2>
        <p>Control which Smart Console services run on each endpoint. Core heartbeat and managed updates remain active so IT can re-enable a service remotely later.</p>
      </div>
      <button className="secondary compactButton" onClick={() => void load()}>Refresh services</button>
    </div>

    <div className="cards endpointCards servicesCards">
      <div className="metric"><span>Managed endpoints</span><strong>{rows.length}</strong><small>{online} online in the last 10 minutes</small></div>
      <div className="metric"><span>USB Audit endpoints</span><strong>{usbEnabled.length}</strong><small>{usbEnabled.length === 1 ? usbEnabled[0].computer_name : 'Recommended: one designated endpoint'}</small></div>
      <div className="metric"><span>Enabled service slots</span><strong>{enabledCount}</strong><small>Across {services.length} optional services</small></div>
      <div className="metric"><span>Core management</span><strong>Always on</strong><small>Heartbeat + managed update channel</small></div>
    </div>

    <div className="panel serviceServerPanel">
      <div className="panelTitle servicePanelTitle">
        <span>USB Audit assignment</span>
        <small>Recommended for your setup: one server/workstation only</small>
      </div>
      <div className="usbServerControl">
        <div>
          <strong>Designated USB Audit endpoint</strong>
          <p>Choose the computer that should record removable-media activity. Applying this will automatically switch USB Audit off on every other active endpoint, reducing local processing, event uploads and log ingestion.</p>
        </div>
        <div className="usbServerActions">
          <select value={usbServer} onChange={event => setUsbServer(event.target.value)}>
            <option value="">Choose endpoint…</option>
            {rows.map(row => <option key={row.terminal_id} value={row.terminal_id}>{row.computer_name}{row.windows_user ? ` — ${row.windows_user}` : ''}</option>)}
          </select>
          <button className="primary compactButton" disabled={!usbServer || busy !== ''} onClick={() => void designateUsbServer()}>
            {busy === 'usb-server' ? 'Applying…' : 'Set as USB Audit endpoint'}
          </button>
        </div>
      </div>
    </div>

    <div className="panel servicesMatrixPanel">
      <div className="panelTitle servicePanelTitle">
        <span>Endpoint service matrix</span>
        <small>Changes apply on the endpoint's next successful heartbeat</small>
      </div>
      <div className="servicesTableWrap">
        <table className="servicesTable">
          <thead>
            <tr>
              <th>Endpoint</th>
              <th>Core</th>
              {services.map(service => <th key={service.key} title={service.detail}>{service.label}</th>)}
              <th>Policy updated</th>
            </tr>
          </thead>
          <tbody>
            {rows.map(row => <tr key={row.terminal_id}>
              <td>
                <div className="serviceEndpointName"><i className={isOnline(row.last_seen_at) ? 'online' : 'offline'} /><div><strong>{row.computer_name}</strong><small>{row.windows_user || 'No interactive user'} · v{row.app_version || '—'}</small></div></div>
              </td>
              <td><span className="serviceCoreBadge">On</span></td>
              {services.map(service => {
                const enabled = Boolean(row[serviceColumn[service.key]])
                const rowBusy = busy === `${row.terminal_id}:${service.key}`
                return <td key={service.key}>
                  <label className="serviceSwitch" title={service.detail}>
                    <input type="checkbox" checked={enabled} disabled={busy !== ''} onChange={event => void setService(row, service.key, event.target.checked)} />
                    <span>{rowBusy ? '…' : enabled ? 'On' : 'Off'}</span>
                  </label>
                </td>
              })}
              <td><small>{dateTime(row.service_policy_updated_at)}</small></td>
            </tr>)}
          </tbody>
        </table>
      </div>
      <div className="servicesLegend">
        <span><strong>Core</strong> = cloud heartbeat, terminal enrollment and managed Smart Console updates. These stay enabled so the endpoint remains recoverable.</span>
        <span>Resource Guard still applies global traffic limits on top of these per-endpoint switches.</span>
      </div>
    </div>
  </section>
}
