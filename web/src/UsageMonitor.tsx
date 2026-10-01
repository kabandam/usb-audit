import { useEffect, useMemo, useState } from 'react'
import { supabase } from './lib/supabase'
import './usage-monitor.css'

type GuardMode = 'balanced' | 'conserve' | 'critical'

type MonitorData = {
  generatedAt: string
  cycleStart: string
  cycleEnd: string
  limits: {
    egressBytes: number
    databaseBytes: number
    monthlyActiveUsers: number
    fileStorageBytes: number
    logIngestionBytes: number
    logQueryBytes: number
  }
  measured: {
    databaseBytes: number
    fileStorageBytes: number
    monthlyActiveUsers: number
  }
  traffic: {
    activeTerminals: number
    onlineTerminals: number
    auditEventsThisCycle: number
    commandsThisCycle: number
    networkChangesThisCycle: number
    softwareRows: number
    projectedHeartbeatRequests30d: number
    projectedNetworkReports30d: number
  }
  guard: {
    mode: GuardMode
    network_enabled: boolean
    location_enabled: boolean
    heartbeat_seconds: number
    inventory_probe_minutes: number
    inventory_resend_hours: number
    network_probe_minutes: number
    network_resend_minutes: number
    device_resend_minutes: number
    location_resend_minutes: number
    update_status_resend_minutes: number
    updated_at: string
  }
  topTables: Array<{ table: string, bytes: number, estimatedRows: number }>
}

const formatBytes = (value?: number | null) => {
  if (!value) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  let size = value
  let unit = 0
  while (size >= 1024 && unit < units.length - 1) { size /= 1024; unit += 1 }
  return `${size >= 100 || unit === 0 ? Math.round(size) : size.toFixed(1)} ${units[unit]}`
}

const percent = (used: number, limit: number) => limit > 0 ? Math.min(100, (used / limit) * 100) : 0
const dateTime = (value?: string) => value ? new Date(value).toLocaleString() : '—'
const dateOnly = (value?: string) => value ? new Date(value).toLocaleDateString() : '—'

function QuotaRow({ label, used, limit, unit = 'bytes', platformOnly = false }: {
  label: string
  used?: number
  limit: number
  unit?: 'bytes' | 'count'
  platformOnly?: boolean
}) {
  const pct = platformOnly || used == null ? null : percent(used, limit)
  const usageText = platformOnly
    ? 'Exact usage: Supabase billing meter'
    : unit === 'bytes'
      ? `${formatBytes(used)} / ${formatBytes(limit)}`
      : `${Number(used || 0).toLocaleString()} / ${limit.toLocaleString()}`

  return <div className="usageQuotaRow">
    <div className="usageQuotaTitle"><strong>{label}</strong><span>{usageText}</span></div>
    <div className="usageBar"><i style={{ width: `${pct ?? 0}%` }} className={pct != null && pct >= 85 ? 'danger' : pct != null && pct >= 70 ? 'warn' : ''} /></div>
    <small>{pct == null ? 'Protected indirectly by Resource Guard traffic controls.' : `${pct.toFixed(1)}% used`}</small>
  </div>
}

export function UsageMonitor() {
  const [data, setData] = useState<MonitorData | null>(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState('')
  const [notice, setNotice] = useState('')

  const load = async () => {
    if (!supabase) return
    const { data: result, error: rpcError } = await supabase.rpc('get_free_tier_monitor')
    if (rpcError) {
      setError(rpcError.message)
      return
    }
    setError('')
    setData(result as MonitorData)
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

  const measurablePeak = useMemo(() => {
    if (!data) return 0
    return Math.max(
      percent(data.measured.databaseBytes, data.limits.databaseBytes),
      percent(data.measured.fileStorageBytes, data.limits.fileStorageBytes),
      percent(data.measured.monthlyActiveUsers, data.limits.monthlyActiveUsers),
    )
  }, [data])

  const applyGuard = async (
    mode: GuardMode,
    networkEnabled?: boolean,
    locationEnabled?: boolean,
  ) => {
    if (!supabase || !data) return
    setBusy(mode); setError(''); setNotice('')
    const { data: result, error: invokeError } = await supabase.functions.invoke('terminal-admin', {
      body: {
        action: 'set_resource_guard',
        resourceMode: mode,
        networkEnabled,
        locationEnabled,
      },
    })
    if (invokeError || result?.error) {
      setError(result?.error || invokeError?.message || 'Could not change the resource guard.')
    } else {
      setNotice('Resource Guard updated. New agents receive the policy on their next heartbeat.')
      await load()
    }
    setBusy('')
  }

  if (!data) return <section className="usageMonitor endpointSection">
    {error ? <div className="errorBanner">{error}</div> : <div className="loading">Loading Free-tier usage monitor…</div>}
  </section>

  const guard = data.guard
  const recommendation = measurablePeak >= 85 ? 'Conserve or Critical' : measurablePeak >= 70 ? 'Conserve' : 'Balanced'

  return <section className="usageMonitor endpointSection">
    {error && <div className="errorBanner">{error}</div>}
    {notice && <div className="usageNotice">{notice}</div>}

    <div className="usageHero">
      <div>
        <span className="usageEyebrow">Supabase Free plan protection</span>
        <h2>Usage Monitor</h2>
        <p>Tracks the quotas Smart Console can measure directly and controls the endpoint traffic that drives egress, database activity and log volume.</p>
      </div>
      <div className="usageHeroActions">
        <span className={`usageGuardBadge ${guard.mode}`}>{guard.mode} mode</span>
        <button className="secondary compactButton" onClick={() => void load()}>Refresh monitor</button>
      </div>
    </div>

    <div className="cards endpointCards usageCards">
      <div className="metric"><span>Database size</span><strong>{formatBytes(data.measured.databaseBytes)}</strong><small>{percent(data.measured.databaseBytes, data.limits.databaseBytes).toFixed(1)}% of 500 MB</small></div>
      <div className="metric"><span>File storage</span><strong>{formatBytes(data.measured.fileStorageBytes)}</strong><small>{percent(data.measured.fileStorageBytes, data.limits.fileStorageBytes).toFixed(1)}% of 1 GB</small></div>
      <div className="metric"><span>Monthly active users</span><strong>{data.measured.monthlyActiveUsers.toLocaleString()}</strong><small>of 50,000</small></div>
      <div className="metric"><span>Projected heartbeats</span><strong>{data.traffic.projectedHeartbeatRequests30d.toLocaleString()}</strong><small>30-day estimate at current guard</small></div>
    </div>

    <div className="usageGrid">
      <div className="panel usagePanel">
        <div className="panelTitle usagePanelTitle"><span>Free-tier limits</span><small>Cycle estimate: {dateOnly(data.cycleStart)} – {dateOnly(data.cycleEnd)}</small></div>
        <div className="usageQuotaList">
          <QuotaRow label="Egress" limit={data.limits.egressBytes} platformOnly />
          <QuotaRow label="Database size" used={data.measured.databaseBytes} limit={data.limits.databaseBytes} />
          <QuotaRow label="Monthly active users" used={data.measured.monthlyActiveUsers} limit={data.limits.monthlyActiveUsers} unit="count" />
          <QuotaRow label="File storage" used={data.measured.fileStorageBytes} limit={data.limits.fileStorageBytes} />
          <QuotaRow label="Log ingestion" limit={data.limits.logIngestionBytes} platformOnly />
          <QuotaRow label="Log query" limit={data.limits.logQueryBytes} platformOnly />
        </div>
        <p className="usageFootnote">Database size, storage and MAU are measured directly. Supabase does not expose the exact billing egress/log meters to the browser client, so those three remain platform-metered while this page limits the traffic that produces them.</p>
      </div>

      <div className="panel usagePanel">
        <div className="panelTitle usagePanelTitle"><span>Resource Guard</span><small>Recommended now: {recommendation}</small></div>
        <div className="usageModes">
          <button className={guard.mode === 'balanced' ? 'usageMode active' : 'usageMode'} disabled={busy !== ''} onClick={() => void applyGuard('balanced')}>
            <strong>Balanced</strong><span>2 min heartbeat · Network 15 min · Location on</span>
          </button>
          <button className={guard.mode === 'conserve' ? 'usageMode active' : 'usageMode'} disabled={busy !== ''} onClick={() => void applyGuard('conserve')}>
            <strong>Conserve</strong><span>3 min heartbeat · Network 60 min · Location off</span>
          </button>
          <button className={guard.mode === 'critical' ? 'usageMode active' : 'usageMode'} disabled={busy !== ''} onClick={() => void applyGuard('critical')}>
            <strong>Critical</strong><span>5 min heartbeat · Network/location off</span>
          </button>
        </div>

        <div className="usageFeatureControls">
          <label><input type="checkbox" checked={guard.network_enabled} disabled={busy !== ''} onChange={event => void applyGuard(guard.mode, event.target.checked, guard.location_enabled)} /><span><strong>Network tracking</strong><small>{guard.network_enabled ? `Enabled · probe every ${guard.network_probe_minutes} min` : 'Paused for this billing cycle'}</small></span></label>
          <label><input type="checkbox" checked={guard.location_enabled} disabled={busy !== ''} onChange={event => void applyGuard(guard.mode, guard.network_enabled, event.target.checked)} /><span><strong>Precise location telemetry</strong><small>{guard.location_enabled ? `Enabled · resend every ${guard.location_resend_minutes} min` : 'Paused for this billing cycle'}</small></span></label>
        </div>

        <div className="usageGuardFacts">
          <div><span>Heartbeat</span><strong>{guard.heartbeat_seconds}s</strong></div>
          <div><span>Inventory probe</span><strong>{guard.inventory_probe_minutes} min</strong></div>
          <div><span>Inventory reconcile</span><strong>{guard.inventory_resend_hours} hr</strong></div>
          <div><span>Network reconcile</span><strong>{guard.network_enabled ? `${guard.network_resend_minutes} min` : 'Paused'}</strong></div>
        </div>
        <p className="usageFootnote">USB audit events, endpoint enrollment, security commands and application deployment remain enabled in every mode.</p>
      </div>
    </div>

    <div className="usageGrid">
      <div className="panel usagePanel">
        <div className="panelTitle usagePanelTitle"><span>Operational traffic</span><small>Generated {dateTime(data.generatedAt)}</small></div>
        <div className="usageTraffic">
          <div><span>Active endpoints</span><strong>{data.traffic.activeTerminals}</strong><small>{data.traffic.onlineTerminals} seen in last 10 minutes</small></div>
          <div><span>Network reports</span><strong>{data.traffic.projectedNetworkReports30d.toLocaleString()}</strong><small>30-day maximum unchanged-state projection</small></div>
          <div><span>USB audit events</span><strong>{data.traffic.auditEventsThisCycle.toLocaleString()}</strong><small>This cycle</small></div>
          <div><span>Endpoint commands</span><strong>{data.traffic.commandsThisCycle.toLocaleString()}</strong><small>This cycle</small></div>
          <div><span>Network changes</span><strong>{data.traffic.networkChangesThisCycle.toLocaleString()}</strong><small>This cycle</small></div>
          <div><span>Software rows</span><strong>{data.traffic.softwareRows.toLocaleString()}</strong><small>Current inventory records</small></div>
        </div>
      </div>

      <div className="panel usagePanel">
        <div className="panelTitle usagePanelTitle"><span>Largest database tables</span><small>Includes indexes and table storage</small></div>
        <div className="usageTableSizes">
          {data.topTables.map(item => <div key={item.table}><span>{item.table}</span><strong>{formatBytes(item.bytes)}</strong><small>~{item.estimatedRows.toLocaleString()} rows</small></div>)}
        </div>
      </div>
    </div>
  </section>
}
