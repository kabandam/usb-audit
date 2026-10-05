import { useEffect, useMemo, useState } from 'react'
import { supabase } from './lib/supabase'
import './network-track.css'

type Terminal = {
  terminal_id: string
  computer_name: string
  windows_user: string | null
  last_seen_at: string
  enrollment_status: string
}

type Network = {
  terminal_id: string
  network_name: string | null
  connection_type: string | null
  adapter_name: string | null
  local_ip: string | null
  public_ip: string | null
  mac_address: string | null
  gateway_ip: string | null
  dns_servers: string[]
  link_speed_mbps: number | null
  service_provider: string | null
  geo_city: string | null
  geo_region: string | null
  geo_country: string | null
  geo_latitude: number | null
  geo_longitude: number | null
  geo_accuracy: 'approximate_ip' | 'not_available'
  observed_at: string
  changed_at: string
}

type NetworkChange = {
  id: number
  terminal_id: string
  network_name: string | null
  connection_type: string | null
  public_ip: string | null
  local_ip: string | null
  service_provider: string | null
  change_reason: string
  observed_at: string
}

const show = (value: string | number | null | undefined) =>
  value === undefined || value === null || value === '' ? '—' : String(value)
const dateTime = (value?: string | null) => value ? new Date(value).toLocaleString() : '—'
const isOnline = (terminal: Terminal) => terminal.enrollment_status !== 'revoked' &&
  Date.now() - new Date(terminal.last_seen_at).getTime() < 600_000
const location = (item?: Network) =>
  item?.geo_accuracy === 'approximate_ip'
    ? [item.geo_city, item.geo_region, item.geo_country].filter(Boolean).join(', ') || 'Location unresolved'
    : 'Not available'
const csvField = (value: unknown) => {
  // Avoid spreadsheet-formula injection when opening telemetry exports in Excel.
  const text = String(value ?? '')
  const safe = /^[=+\-@]/.test(text) ? "'" + text : text
  return '"' + safe.replace(/"/g, '""') + '"'
}

export function NetworkTrack() {
  const [terminals, setTerminals] = useState<Terminal[]>([])
  const [network, setNetwork] = useState<Network[]>([])
  const [history, setHistory] = useState<NetworkChange[]>([])
  const [search, setSearch] = useState('')
  const [state, setState] = useState('all')
  const [selected, setSelected] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [refreshedAt, setRefreshedAt] = useState('')

  const load = async () => {
    if (!supabase) return
    setLoading(true)
    const results = await Promise.all([
      supabase.from('terminals').select('terminal_id,computer_name,windows_user,last_seen_at,enrollment_status')
        .order('computer_name'),
      supabase.from('endpoint_network_status').select('*').order('observed_at', { ascending: false }),
      supabase.from('endpoint_network_history').select('*').order('observed_at', { ascending: false }).limit(150),
    ])
    const failure = results.find(item => item.error)?.error
    setError(failure?.message || '')
    if (!failure) {
      setTerminals((results[0].data || []) as Terminal[])
      setNetwork((results[1].data || []) as Network[])
      setHistory((results[2].data || []) as NetworkChange[])
      setRefreshedAt(new Date().toISOString())
    }
    setLoading(false)
  }

  useEffect(() => {
    void load()
    const refresh = () => {
      if (document.visibilityState === 'visible') void load()
    }
    const id = window.setInterval(refresh, 300_000)
    document.addEventListener('visibilitychange', refresh)
    return () => {
      window.clearInterval(id)
      document.removeEventListener('visibilitychange', refresh)
    }
  }, [])

  const networkMap = useMemo(() => new Map(network.map(item => [item.terminal_id, item])), [network])
  const terminalMap = useMemo(() => new Map(terminals.map(item => [item.terminal_id, item])), [terminals])
  const rows = terminals.map(terminal => ({ terminal, item: networkMap.get(terminal.terminal_id) }))
  const filtered = rows.filter(({ terminal, item }) => {
    if (state === 'online' && !isOnline(terminal)) return false
    if (state === 'offline' && isOnline(terminal)) return false
    if (state === 'awaiting' && item) return false
    const value = [
      terminal.computer_name, terminal.windows_user, item?.network_name,
      item?.service_provider, item?.public_ip, item?.local_ip, item?.mac_address, location(item),
    ].join(' ').toLowerCase()
    return value.includes(search.trim().toLowerCase())
  })
  const selectedItem = networkMap.get(selected)
  const recentChanges = history.filter(item => !selected || selected === item.terminal_id)

  const exportCsv = () => {
    const headings = ['Computer', 'User', 'Status', 'Network', 'Connection type', 'Provider',
      'Public IP', 'Local IP', 'MAC address', 'Link speed (Mbps)', 'Approximate IP location', 'Last report']
    const values = filtered.map(({ terminal, item }) => [
      terminal.computer_name, terminal.windows_user, isOnline(terminal) ? 'Online' : 'Offline',
      item?.network_name, item?.connection_type, item?.service_provider, item?.public_ip,
      item?.local_ip, item?.mac_address, item?.link_speed_mbps, location(item), item?.observed_at,
    ])
    const csv = [headings, ...values].map(row => row.map(csvField).join(',')).join('\r\n')
    const href = URL.createObjectURL(new Blob(['\ufeff' + csv], { type: 'text/csv;charset=utf-8' }))
    const anchor = document.createElement('a')
    anchor.href = href
    anchor.download = 'CRECCOM-Network-Track-' + new Date().toISOString().slice(0, 10) + '.csv'
    anchor.click()
    window.setTimeout(() => URL.revokeObjectURL(href), 1000)
  }

  return <section className="networkTrack endpointSection">
    {error && <div className="errorBanner">{error}</div>}
    <div className="networkNotice">
      <strong>Network visibility for enrolled CRECCOM devices</strong>
      <span>Link speed is the negotiated adapter rate, not a live internet speed test. Service provider and the location shown in the table are approximate public-IP results. Authorized Windows location is separate: only administrators can request and view permitted readings, with an audit trail.</span>
    </div>
    <div className="cards endpointCards">
      <div className="metric"><span>Managed endpoints</span><strong>{terminals.length}</strong><small>{terminals.filter(isOnline).length} online</small></div>
      <div className="metric"><span>Network reporting</span><strong>{network.length}</strong><small>{terminals.length - network.length} awaiting upgraded agent</small></div>
      <div className="metric"><span>Identified providers</span><strong>{new Set(network.map(item => item.service_provider).filter(Boolean)).size}</strong><small>Based on public IP</small></div>
      <div className="metric"><span>Network changes (24h)</span><strong>{history.filter(item => Date.now() - new Date(item.observed_at).getTime() < 86_400_000).length}</strong><small>Connection/address changes</small></div>
    </div>
    <div className="panel">
      <div className="panelTitle networkTitle">
        <div><strong>Current network connections</strong><small>Automatically refreshed every 5 minutes · Last refreshed {dateTime(refreshedAt)}</small></div>
        <div className="networkActions">
          <button type="button" className="secondary compactButton" onClick={exportCsv}>Export CSV</button>
          <button type="button" className="primary compactButton" onClick={() => { void load() }} disabled={loading}>{loading ? 'Refreshing…' : 'Refresh now'}</button>
        </div>
      </div>
      <div className="networkFilters">
        <input value={search} onChange={event => setSearch(event.target.value)} placeholder="Search endpoint, network, IP, MAC or provider" aria-label="Search networks" />
        <select value={state} onChange={event => setState(event.target.value)} aria-label="Filter endpoint status">
          <option value="all">All endpoints</option>
          <option value="online">Online</option>
          <option value="offline">Offline</option>
          <option value="awaiting">Awaiting telemetry</option>
        </select>
        <small>{filtered.length} device(s)</small>
      </div>
      <div className="tableWrap">
        <table className="networkTable"><thead><tr><th>Endpoint</th><th>Connected network</th><th>Service provider</th><th>IP addresses</th><th>MAC address</th><th>Link speed</th><th>Estimated location</th><th>Reported</th><th /></tr></thead>
          <tbody>{filtered.length === 0 ? <tr><td colSpan={9} className="empty">No matching endpoints found.</td></tr> :
            filtered.map(({ terminal, item }) => <tr key={terminal.terminal_id} className={selected === terminal.terminal_id ? 'networkSelected' : ''}>
              <td><strong>{terminal.computer_name}</strong><small>{terminal.windows_user || terminal.terminal_id}</small><span className={isOnline(terminal) ? 'networkState connected' : 'networkState'}>{isOnline(terminal) ? 'Online' : 'Offline'}</span></td>
              <td><strong>{show(item?.network_name)}</strong><small>{item?.connection_type || 'Awaiting agent data'}</small></td>
              <td>{show(item?.service_provider)}</td>
              <td className="networkIp"><span>Public: {show(item?.public_ip)}</span><small>Local: {show(item?.local_ip)}</small></td>
              <td className="mono">{show(item?.mac_address)}</td>
              <td><strong>{item?.link_speed_mbps != null ? Number(item.link_speed_mbps).toLocaleString() + ' Mbps' : '—'}</strong><small>Adapter link</small></td>
              <td>{location(item)}<small>{item?.geo_accuracy === 'approximate_ip' ? 'IP-based estimate' : 'Not verified'}</small></td>
              <td>{dateTime(item?.observed_at)}<small>{item ? 'Changed: ' + dateTime(item.changed_at) : 'Agent update needed'}</small></td>
              <td><button type="button" className="linkButton" aria-expanded={selected === terminal.terminal_id} onClick={() => setSelected(selected === terminal.terminal_id ? '' : terminal.terminal_id)}>{selected === terminal.terminal_id ? 'Hide' : 'Details'}</button></td>
            </tr>)}</tbody>
        </table>
      </div>
      {selected && <div className="networkDetails">
        <div className="networkDetailHead"><strong>{terminalMap.get(selected)?.computer_name || selected} — connection details</strong><button type="button" className="linkButton" onClick={() => setSelected('')}>Close</button></div>
        {selectedItem ? <div className="networkFacts">
          <div><span>Adapter</span><strong>{show(selectedItem.adapter_name)}</strong></div>
          <div><span>Gateway IP</span><strong className="mono">{show(selectedItem.gateway_ip)}</strong></div>
          <div><span>DNS servers</span><strong className="mono">{selectedItem.dns_servers?.join(', ') || '—'}</strong></div>
          <div><span>MAC address</span><strong className="mono">{show(selectedItem.mac_address)}</strong></div>
          <div><span>Public IP</span><strong className="mono">{show(selectedItem.public_ip)}</strong></div>
          <div><span>Service provider</span><strong>{show(selectedItem.service_provider)}</strong></div>
          <div><span>Location confidence</span><strong>{selectedItem.geo_accuracy === 'approximate_ip' ? 'Approximate, based on public IP' : 'Unavailable'}</strong></div>
          <div><span>IP-estimated coordinates</span><strong className="mono">{selectedItem.geo_latitude != null && selectedItem.geo_longitude != null ? String(selectedItem.geo_latitude) + ', ' + String(selectedItem.geo_longitude) : '—'}</strong></div>
        </div> : <div className="networkEmpty">This device has not uploaded network telemetry yet. Install the latest agent and synchronize.</div>}
      </div>}
    </div>
    <div className="panel">
      <div className="panelTitle networkTitle"><div><strong>Connection history</strong><small>New entries are logged only when network identity or IP changes.</small></div><small>{selected ? 'Filtered to selected device' : 'Latest 150 changes'}</small></div>
      <div className="tableWrap"><table><thead><tr><th>When</th><th>Endpoint</th><th>Change</th><th>Network</th><th>Provider</th><th>Public IP</th><th>Local IP</th></tr></thead>
        <tbody>{recentChanges.length === 0 ? <tr><td colSpan={7} className="empty">No network changes recorded yet.</td></tr> :
          recentChanges.map(item => <tr key={item.id}><td>{dateTime(item.observed_at)}</td><td><strong>{terminalMap.get(item.terminal_id)?.computer_name || item.terminal_id}</strong></td><td>{item.change_reason.replaceAll('_', ' ')}</td><td>{show(item.network_name)}<small>{show(item.connection_type)}</small></td><td>{show(item.service_provider)}</td><td className="mono">{show(item.public_ip)}</td><td className="mono">{show(item.local_ip)}</td></tr>)}</tbody></table></div>
    </div>
  </section>
}
