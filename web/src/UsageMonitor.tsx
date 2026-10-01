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

type DirectUsage = {
  connected: boolean
  lastCapturedAt: string | null
  windowStart: string | null
  windowEnd: string | null
  coverageStatus: string | null
  error: string | null
  apiRequestsThisCycle: number
  logEventsThisCycle: number
  observedLogIngestBytesThisCycle: number
  trackedLogQueryBytesThisCycle: number
  exactEgressBytesThisCycle: number | null
  measuredSmartConsoleEgressBytesThisCycle: number
  sourceBreakdown: Record<string, { events?: number, bytes?: number }>
  managementAvailable: boolean
  note: string
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
const dateTime = (value?: string | null) => value ? new Date(value).toLocaleString() : '—'
const dateOnly = (value?: string | null) => value ? new Date(value).toLocaleDateString() : '—'

function QuotaRow({ label, used, limit, unit = 'bytes', quality }: {
  label: string
  used: number
  limit: number
  unit?: 'bytes' | 'count'
  quality?: string
}) {
  const pct = percent(used, limit)
  const usageText = unit === 'bytes'
    ? `${formatBytes(used)} / ${formatBytes(limit)}`
    : `${Number(used || 0).toLocaleString()} / ${limit.toLocaleString()}`

  return <div className="usageQuotaRow">
    <div className="usageQuotaTitle"><strong>{label}</strong><span>{usageText}</span></div>
    <div className="usageBar"><i style={{ width: `${pct}%` }} className={pct >= 85 ? 'danger' : pct >= 70 ? 'warn' : ''} /></div>
    <small>{pct.toFixed(1)}% tracked{quality ? ` · ${quality}` : ''}</small>
  </div>
}

export function UsageMonitor() {
  const [data, setData] = useState<MonitorData | null>(null)
  const [direct, setDirect] = useState<DirectUsage | null>(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState('')
  const [notice, setNotice] = useState('')
  const [managementToken, setManagementToken] = useState('')

  const load = async () => {
    if (!supabase) return
    const [baseResult, directResult] = await Promise.all([
      supabase.rpc('get_free_tier_monitor'),
      supabase.rpc('get_direct_usage_summary'),
    ])
    const failure = baseResult.error || directResult.error
    if (failure) {
      setError(failure.message)
      return
    }
    setError('')
    setData(baseResult.data as MonitorData)
    setDirect(directResult.data as DirectUsage)
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
    const tracked = [
      percent(data.measured.databaseBytes, data.limits.databaseBytes),
      percent(data.measured.fileStorageBytes, data.limits.fileStorageBytes),
      percent(data.measured.monthlyActiveUsers, data.limits.monthlyActiveUsers),
    ]
    if (direct) {
      tracked.push(
        percent(direct.exactEgressBytesThisCycle ?? direct.measuredSmartConsoleEgressBytesThisCycle, data.limits.egressBytes),
        percent(direct.observedLogIngestBytesThisCycle, data.limits.logIngestionBytes),
        percent(direct.trackedLogQueryBytesThisCycle, data.limits.logQueryBytes),
      )
    }
    return Math.max(...tracked)
  }, [data, direct])

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

  const connectManagement = async () => {
    if (!supabase || !managementToken.trim()) return
    setBusy('management-connect'); setError(''); setNotice('')
    const { data: result, error: invokeError } = await supabase.functions.invoke('usage-platform-monitor', {
      body: { action: 'connect', token: managementToken.trim() },
    })
    if (invokeError || result?.error) {
      setError(result?.error || invokeError?.message || 'Could not connect the Supabase Management API.')
    } else {
      setManagementToken('')
      setNotice('Direct platform telemetry connected. The token is encrypted in Supabase Vault and the collector will sample once per hour.')
      await load()
    }
    setBusy('')
  }

  const collectNow = async () => {
    if (!supabase) return
    setBusy('management-collect'); setError(''); setNotice('')
    const { data: result, error: invokeError } = await supabase.functions.invoke('usage-platform-monitor', {
      body: { action: 'collect' },
    })
    if (invokeError || result?.error) {
      setError(result?.error || invokeError?.message || 'Could not collect platform usage.')
    } else {
      setNotice(result?.skipped ? result.reason : 'Platform usage snapshot collected.')
      await load()
    }
    setBusy('')
  }

  const disconnectManagement = async () => {
    if (!supabase || !window.confirm('Disconnect direct Supabase Management API telemetry? Existing usage snapshots will remain.')) return
    setBusy('management-disconnect'); setError(''); setNotice('')
    const { data: result, error: invokeError } = await supabase.functions.invoke('usage-platform-monitor', {
      body: { action: 'disconnect' },
    })
    if (invokeError || result?.error) {
      setError(result?.error || invokeError?.message || 'Could not disconnect direct platform telemetry.')
    } else {
      setNotice('Direct Management API telemetry disconnected.')
      await load()
    }
    setBusy('')
  }

  if (!data) return <section className="usageMonitor endpointSection">
    {error ? <div className="errorBanner">{error}</div> : <div className="loading">Loading Free-tier usage monitor…</div>}
  </section>

  const guard = data.guard
  const recommendation = measurablePeak >= 85 ? 'Critical' : measurablePeak >= 70 ? 'Conserve' : 'Balanced'
  const trackedEgress = direct?.exactEgressBytesThisCycle ?? direct?.measuredSmartConsoleEgressBytesThisCycle ?? 0
  const egressQuality = direct?.exactEgressBytesThisCycle != null
    ? 'Supabase platform meter'
    : 'measured Smart Console payloads; lower bound'
  const sourceRows = Object.entries(direct?.sourceBreakdown ?? {})
    .sort((a, b) => Number(b[1]?.bytes || 0) - Number(a[1]?.bytes || 0))

  return <section className="usageMonitor endpointSection">
    {error && <div className="errorBanner">{error}</div>}
    {notice && <div className="usageNotice">{notice}</div>}

    <div className="usageHero">
      <div>
        <span className="usageEyebrow">Supabase Free plan protection</span>
        <h2>Usage Monitor</h2>
        <p>Directly measures Smart Console payload egress, database/storage usage and Supabase log activity, while the Resource Guard can reduce non-essential traffic before the Free-tier limits are reached.</p>
      </div>
      <div className="usageHeroActions">
        <span className={`usageGuardBadge ${guard.mode}`}>{guard.mode} mode</span>
        <button className="secondary compactButton" onClick={() => void load()}>Refresh monitor</button>
      </div>
    </div>

    <div className="cards endpointCards usageCards">
      <div className="metric"><span>Tracked egress</span><strong>{formatBytes(trackedEgress)}</strong><small>{percent(trackedEgress, data.limits.egressBytes).toFixed(2)}% of 5 GB</small></div>
      <div className="metric"><span>Observed log ingest</span><strong>{formatBytes(direct?.observedLogIngestBytesThisCycle || 0)}</strong><small>{percent(direct?.observedLogIngestBytesThisCycle || 0, data.limits.logIngestionBytes).toFixed(2)}% of 1 GB</small></div>
      <div className="metric"><span>Tracked log query</span><strong>{formatBytes(direct?.trackedLogQueryBytesThisCycle || 0)}</strong><small>{percent(direct?.trackedLogQueryBytesThisCycle || 0, data.limits.logQueryBytes).toFixed(2)}% of 100 GB</small></div>
      <div className="metric"><span>Database size</span><strong>{formatBytes(data.measured.databaseBytes)}</strong><small>{percent(data.measured.databaseBytes, data.limits.databaseBytes).toFixed(1)}% of 500 MB</small></div>
    </div>

    <div className="usageGrid">
      <div className="panel usagePanel">
        <div className="panelTitle usagePanelTitle"><span>Free-tier limits</span><small>Cycle: {dateOnly(data.cycleStart)} – {dateOnly(data.cycleEnd)}</small></div>
        <div className="usageQuotaList">
          <QuotaRow label="Egress" used={trackedEgress} limit={data.limits.egressBytes} quality={egressQuality} />
          <QuotaRow label="Database size" used={data.measured.databaseBytes} limit={data.limits.databaseBytes} quality="direct database measurement" />
          <QuotaRow label="Monthly active users" used={data.measured.monthlyActiveUsers} limit={data.limits.monthlyActiveUsers} unit="count" quality="direct Auth measurement" />
          <QuotaRow label="File storage" used={data.measured.fileStorageBytes} limit={data.limits.fileStorageBytes} quality="direct Storage measurement" />
          <QuotaRow label="Log ingestion" used={direct?.observedLogIngestBytesThisCycle || 0} limit={data.limits.logIngestionBytes} quality="observed raw Supabase logs" />
          <QuotaRow label="Log query" used={direct?.trackedLogQueryBytesThisCycle || 0} limit={data.limits.logQueryBytes} quality="collector scan tracking" />
        </div>
        <p className="usageFootnote">The egress figure is a direct lower-bound measurement of Smart Console payloads unless Supabase exposes a supported unified billing meter to the collector. Log ingestion is measured from the project’s own unified log stream. These are deliberately labelled by measurement quality rather than presented as billing-exact when the platform API does not expose that value.</p>
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
        <div className="panelTitle usagePanelTitle">
          <span>Direct Supabase telemetry</span>
          <small>{direct?.connected ? 'Management API connected' : 'Management API not connected'}</small>
        </div>
        {direct?.connected ? <div className="usageDirectBody">
          <div className="usageConnectionStatus connected"><i /><div><strong>Connected securely</strong><span>Hourly collector enabled · credential encrypted in Supabase Vault</span></div></div>
          <div className="usageDirectStats">
            <div><span>Last platform sample</span><strong>{dateTime(direct.lastCapturedAt)}</strong></div>
            <div><span>Sample coverage</span><strong>{direct.coverageStatus || '—'}</strong></div>
            <div><span>API requests observed</span><strong>{direct.apiRequestsThisCycle.toLocaleString()}</strong></div>
            <div><span>Log events observed</span><strong>{direct.logEventsThisCycle.toLocaleString()}</strong></div>
          </div>
          <div className="usageDirectActions">
            <button className="secondary compactButton" disabled={busy !== ''} onClick={() => void collectNow()}>{busy === 'management-collect' ? 'Collecting…' : 'Collect now'}</button>
            <button className="linkButton" disabled={busy !== ''} onClick={() => void disconnectManagement()}>Disconnect</button>
          </div>
          <p className="usageFootnote noPad">The collector reads one non-overlapping log window per hour, rather than repeatedly polling logs. This keeps the monitor itself from becoming a significant Log Query consumer.</p>
        </div> : <div className="usageDirectBody">
          <div className="usageConnectionStatus"><i /><div><strong>Connect Supabase Management API</strong><span>Enables hourly direct API/log observations without exposing the token to the browser after setup.</span></div></div>
          <label className="usageTokenField">
            <span>Supabase account access token</span>
            <input type="password" autoComplete="off" value={managementToken} onChange={event => setManagementToken(event.target.value)} placeholder="Paste access token" />
            <small>Create a dedicated token in Supabase Account Settings → Access Tokens. It is validated once and stored encrypted in Supabase Vault.</small>
          </label>
          <button className="primary compactButton usageConnectButton" disabled={busy !== '' || !managementToken.trim()} onClick={() => void connectManagement()}>
            {busy === 'management-connect' ? 'Connecting…' : 'Connect direct telemetry'}
          </button>
        </div>}
      </div>

      <div className="panel usagePanel">
        <div className="panelTitle usagePanelTitle"><span>Log traffic by source</span><small>Latest collected window</small></div>
        <div className="usageSourceList">
          {sourceRows.length === 0 ? <div className="usageEmpty">No direct log-source sample yet.</div> :
            sourceRows.map(([source, item]) => <div key={source}><span>{source}</span><strong>{formatBytes(Number(item.bytes || 0))}</strong><small>{Number(item.events || 0).toLocaleString()} events</small></div>)}
        </div>
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
