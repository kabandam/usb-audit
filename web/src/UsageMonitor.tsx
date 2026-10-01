import { useEffect, useMemo, useState } from 'react'
import { supabase } from './lib/supabase'
import { useAppDialog } from './AppDialogs'
import './usage-monitor.css'

type GuardMode = 'balanced' | 'conserve' | 'critical'
type UsageTab = 'overview' | 'daily' | 'restriction'

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

type DailyUsageRow = {
  day: string
  egressBytes: number
  webEgressBytes: number
  agentEgressBytes: number
  egressReports: number
  logIngestBytes: number
  logQueryBytes: number
  apiRequests: number
  logEvents: number
  samples: number
  hasDirectCoverage: boolean
  cumulativeEgressBytes: number
  cumulativeLogIngestBytes: number
  cumulativeLogQueryBytes: number
}

type DailyUsageHistory = {
  cycleStart: string
  cycleEnd: string
  generatedAt: string
  limits: {
    egressBytes: number
    logIngestionBytes: number
    logQueryBytes: number
  }
  days: DailyUsageRow[]
}

type RestrictionStage = 'normal' | 'restricted' | 'severe' | 'critical' | 'survival'

type UsageRestrictionStatus = {
  autoEnabled: boolean
  manualStage: RestrictionStage | null
  currentStage: RestrictionStage
  triggerMetric: string | null
  triggerPercent: number
  cycleStart: string
  lastEvaluatedAt: string | null
  lastStageChangeAt: string | null
  thresholds: {
    restricted: number
    severe: number
    critical: number
    survival: number
  }
  controls: {
    auditEventUploadEnabled: boolean
    deploymentDeliveryEnabled: boolean
    remoteSupportDeliveryEnabled: boolean
    locationDeliveryEnabled: boolean
  }
  usage: {
    egressBytes: number
    egressPercent: number
    logIngestionBytes: number
    logIngestionPercent: number
    logQueryBytes: number
    logQueryPercent: number
    databaseBytes: number
    databasePercent: number
    fileStorageBytes: number
    fileStoragePercent: number
    monthlyActiveUsers: number
    monthlyActiveUsersPercent: number
  }
  guard: MonitorData['guard']
  profiles: Array<{
    stage: RestrictionStage
    fromPercent: number
    heartbeatSeconds: number
    inventory: string
    network: string
    events: string
    commands: string
  }>
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
const shortDay = (value: string) => new Date(`${value}T00:00:00Z`).toLocaleDateString(undefined, { month: 'short', day: 'numeric', timeZone: 'UTC' })
const daysBetween = (start: string, end: string) => Math.max(1, Math.round((new Date(end).getTime() - new Date(start).getTime()) / 86_400_000))
const clampPercent = (value: number) => Number.isFinite(value) ? Math.max(0, value) : 0

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

function UsageLineChart({ rows, cumulative = false }: { rows: DailyUsageRow[], cumulative?: boolean }) {
  const width = 1000
  const height = 300
  const left = 58
  const right = 20
  const top = 20
  const bottom = 48
  const plotWidth = width - left - right
  const plotHeight = height - top - bottom

  const points = rows.map(row => ({
    day: row.day,
    egress: clampPercent((cumulative ? row.cumulativeEgressBytes : row.egressBytes) / (5 * 1024 * 1024 * 1024) * 100),
    ingest: clampPercent((cumulative ? row.cumulativeLogIngestBytes : row.logIngestBytes) / (1 * 1024 * 1024 * 1024) * 100),
    query: clampPercent((cumulative ? row.cumulativeLogQueryBytes : row.logQueryBytes) / (100 * 1024 * 1024 * 1024) * 100),
  }))

  const peak = Math.max(0, ...points.flatMap(point => [point.egress, point.ingest, point.query]))
  const yMax = cumulative
    ? peak <= 10 ? 10 : peak <= 25 ? 25 : peak <= 50 ? 50 : peak <= 75 ? 75 : 100
    : peak <= 0.25 ? 0.25 : peak <= 0.5 ? 0.5 : peak <= 1 ? 1 : peak <= 2.5 ? 2.5 : peak <= 5 ? 5 : peak <= 10 ? 10 : Math.min(100, Math.ceil(peak / 10) * 10)

  const x = (index: number) => left + (points.length <= 1 ? plotWidth / 2 : index * plotWidth / (points.length - 1))
  const y = (value: number) => top + plotHeight - Math.min(yMax, value) / yMax * plotHeight
  const pathFor = (key: 'egress' | 'ingest' | 'query') => points.map((point, index) => `${index === 0 ? 'M' : 'L'} ${x(index).toFixed(2)} ${y(point[key]).toFixed(2)}`).join(' ')
  const labelEvery = Math.max(1, Math.ceil(points.length / 7))
  const ticks = [0, yMax / 2, yMax]

  return <div className="usageChartWrap">
    <div className="usageChartLegend">
      <span><i className="egress" />Egress</span>
      <span><i className="ingest" />Log ingestion</span>
      <span><i className="query" />Log query</span>
    </div>
    {points.length === 0 ? <div className="usageEmpty">No billing-cycle usage samples yet.</div> :
      <svg className="usageLineChart" viewBox={`0 0 ${width} ${height}`} role="img" aria-label={cumulative ? 'Cumulative billing-cycle quota usage graph' : 'Daily billing-cycle usage graph'}>
        {ticks.map(value => <g key={value}>
          <line className="usageChartGrid" x1={left} x2={width - right} y1={y(value)} y2={y(value)} />
          <text className="usageChartAxisText" x={left - 10} y={y(value) + 4} textAnchor="end">{value < 1 ? value.toFixed(2) : value.toFixed(1)}%</text>
        </g>)}
        <line className="usageChartAxis" x1={left} x2={left} y1={top} y2={top + plotHeight} />
        <line className="usageChartAxis" x1={left} x2={width - right} y1={top + plotHeight} y2={top + plotHeight} />

        {points.map((point, index) => (index % labelEvery === 0 || index === points.length - 1) &&
          <text key={point.day} className="usageChartAxisText" x={x(index)} y={height - 18} textAnchor="middle">{shortDay(point.day)}</text>)}

        <path className="usageSeries egress" d={pathFor('egress')} />
        <path className="usageSeries ingest" d={pathFor('ingest')} />
        <path className="usageSeries query" d={pathFor('query')} />
        {points.map((point, index) => <g key={point.day}>
          <circle className="usageDot egress" cx={x(index)} cy={y(point.egress)} r="4"><title>{`${shortDay(point.day)} · Egress ${point.egress.toFixed(3)}%`}</title></circle>
          <circle className="usageDot ingest" cx={x(index)} cy={y(point.ingest)} r="4"><title>{`${shortDay(point.day)} · Log ingestion ${point.ingest.toFixed(3)}%`}</title></circle>
          <circle className="usageDot query" cx={x(index)} cy={y(point.query)} r="4"><title>{`${shortDay(point.day)} · Log query ${point.query.toFixed(3)}%`}</title></circle>
        </g>)}
      </svg>}
    <small className="usageChartCaption">{cumulative
      ? 'Cumulative percentage of each monthly Free-tier allowance used across the billing cycle.'
      : 'Each point is that day’s tracked usage as a percentage of its monthly Free-tier allowance.'}</small>
  </div>
}

export function UsageMonitor() {
  const { confirm, notify } = useAppDialog()
  const [data, setData] = useState<MonitorData | null>(null)
  const [direct, setDirect] = useState<DirectUsage | null>(null)
  const [daily, setDaily] = useState<DailyUsageHistory | null>(null)
  const [restriction, setRestriction] = useState<UsageRestrictionStatus | null>(null)
  const [activeTab, setActiveTab] = useState<UsageTab>('overview')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState('')
  const [notice, setNotice] = useState('')
  const [managementToken, setManagementToken] = useState('')

  const load = async () => {
    if (!supabase) return
    const [baseResult, directResult, dailyResult, restrictionResult] = await Promise.all([
      supabase.rpc('get_free_tier_monitor'),
      supabase.rpc('get_direct_usage_summary'),
      supabase.rpc('get_daily_usage_history'),
      supabase.rpc('get_usage_restriction_status'),
    ])
    const failure = baseResult.error || directResult.error || dailyResult.error || restrictionResult.error
    if (failure) {
      setError(failure.message)
      return
    }
    setError('')
    setData(baseResult.data as MonitorData)
    setDirect(directResult.data as DirectUsage)
    setDaily(dailyResult.data as DailyUsageHistory)
    setRestriction(restrictionResult.data as UsageRestrictionStatus)
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

  const dailyAnalysis = useMemo(() => {
    const rows = daily?.days ?? []
    if (!daily || rows.length === 0) return null
    const elapsed = rows.length
    const cycleDays = daysBetween(daily.cycleStart, daily.cycleEnd)
    const latest = rows[rows.length - 1]
    const totals = {
      egress: latest.cumulativeEgressBytes,
      ingest: latest.cumulativeLogIngestBytes,
      query: latest.cumulativeLogQueryBytes,
    }
    const peakEgress = rows.reduce((best, row) => row.egressBytes > best.egressBytes ? row : best, rows[0])
    const peakIngest = rows.reduce((best, row) => row.logIngestBytes > best.logIngestBytes ? row : best, rows[0])
    const projectedEgress = Math.round(totals.egress / Math.max(1, elapsed) * cycleDays)
    const projectedIngest = Math.round(totals.ingest / Math.max(1, elapsed) * cycleDays)
    const remainingDays = Math.max(1, cycleDays - elapsed)
    const safeDailyEgress = Math.max(0, daily.limits.egressBytes - totals.egress) / remainingDays
    const safeDailyIngest = Math.max(0, daily.limits.logIngestionBytes - totals.ingest) / remainingDays
    const trend = projectedEgress / daily.limits.egressBytes
    return {
      elapsed, cycleDays, remainingDays, totals, peakEgress, peakIngest,
      projectedEgress, projectedIngest, safeDailyEgress, safeDailyIngest,
      egressTrend: trend >= .85 ? 'critical' : trend >= .7 ? 'watch' : 'safe',
    }
  }, [daily])

  const applyGuard = async (
    mode: GuardMode,
    networkEnabled?: boolean,
    locationEnabled?: boolean,
  ) => {
    if (!supabase || !data) return
    const accepted = await confirm({
      title: 'Apply Resource Guard changes?',
      message: `Mode: ${mode}. The updated policy will be delivered to agents on their next heartbeat.`,
      confirmLabel: 'Apply changes',
      tone: mode === 'critical' ? 'warning' : 'info',
    })
    if (!accepted) return

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
      const message = result?.error || invokeError?.message || 'Could not change the resource guard.'
      setError(message)
      await notify({ title: 'Resource Guard update failed', message, tone: 'danger' })
    } else {
      const message = 'Resource Guard updated. New agents receive the policy on their next heartbeat.'
      setNotice(message)
      await load()
      await notify({ title: 'Resource Guard updated', message, tone: 'success' })
    }
    setBusy('')
  }

  const updateRestriction = async (
    autoEnabled: boolean,
    manualStage: RestrictionStage | null,
  ) => {
    if (!supabase) return
    const accepted = await confirm({
      title: 'Change usage restriction policy?',
      message: manualStage
        ? `Force the console into ${manualStage} mode for this billing cycle?`
        : autoEnabled
          ? 'Return Usage Restriction to automatic Free-tier protection?'
          : 'Disable automatic Free-tier protection?',
      confirmLabel: 'Apply policy',
      tone: manualStage && ['critical','survival'].includes(manualStage) ? 'warning' : 'info',
    })
    if (!accepted) return

    setBusy('usage-restriction'); setError(''); setNotice('')
    const { data: result, error: invokeError } = await supabase.functions.invoke('terminal-admin', {
      body: {
        action: 'set_usage_restriction',
        usageRestrictionAutoEnabled: autoEnabled,
        usageRestrictionManualStage: manualStage,
      },
    })
    if (invokeError || result?.error) {
      const message = result?.error || invokeError?.message || 'Could not update Usage Restriction.'
      setError(message)
      await notify({ title: 'Usage Restriction update failed', message, tone: 'danger' })
    } else {
      const message = manualStage
        ? `Usage Restriction forced to ${manualStage} mode.`
        : autoEnabled
          ? 'Automatic Free-tier protection enabled. Restrictions will begin at 50% usage.'
          : 'Automatic usage restriction disabled.'
      setNotice(message)
      await load()
      await notify({ title: 'Usage Restriction updated', message, tone: 'success' })
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
      const message = result?.error || invokeError?.message || 'Could not connect the Supabase Management API.'
      setError(message)
      await notify({ title: 'Telemetry connection failed', message, tone: 'danger' })
    } else {
      setManagementToken('')
      const message = 'Direct platform telemetry connected. The token is encrypted in Supabase Vault and the collector will sample once per hour.'
      setNotice(message)
      await load()
      await notify({ title: 'Telemetry connected', message, tone: 'success' })
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
      const message = result?.error || invokeError?.message || 'Could not collect platform usage.'
      setError(message)
      await notify({ title: 'Usage collection failed', message, tone: 'danger' })
    } else {
      const message = result?.skipped ? result.reason : 'Platform usage snapshot collected.'
      setNotice(message)
      await load()
      await notify({ title: result?.skipped ? 'Usage collection skipped' : 'Usage snapshot collected', message, tone: result?.skipped ? 'warning' : 'success' })
    }
    setBusy('')
  }

  const disconnectManagement = async () => {
    if (!supabase) return
    const accepted = await confirm({
      title: 'Disconnect platform telemetry?',
      message: 'Direct Supabase Management API telemetry will be disconnected. Existing usage snapshots will remain.',
      confirmLabel: 'Disconnect',
      tone: 'warning',
    })
    if (!accepted) return

    setBusy('management-disconnect'); setError(''); setNotice('')
    const { data: result, error: invokeError } = await supabase.functions.invoke('usage-platform-monitor', {
      body: { action: 'disconnect' },
    })
    if (invokeError || result?.error) {
      const message = result?.error || invokeError?.message || 'Could not disconnect direct platform telemetry.'
      setError(message)
      await notify({ title: 'Telemetry disconnect failed', message, tone: 'danger' })
    } else {
      const message = 'Direct Management API telemetry disconnected.'
      setNotice(message)
      await load()
      await notify({ title: 'Telemetry disconnected', message, tone: 'success' })
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

    <div className="usageTabs" role="tablist" aria-label="Usage Monitor views">
      <button role="tab" aria-selected={activeTab === 'overview'} className={activeTab === 'overview' ? 'active' : ''} onClick={() => setActiveTab('overview')}>Overview</button>
      <button role="tab" aria-selected={activeTab === 'daily'} className={activeTab === 'daily' ? 'active' : ''} onClick={() => setActiveTab('daily')}>Daily usage</button>
      <button role="tab" aria-selected={activeTab === 'restriction'} className={activeTab === 'restriction' ? 'active' : ''} onClick={() => setActiveTab('restriction')}>Usage restriction</button>
    </div>

    {activeTab === 'overview' ? <>
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
              <strong>Balanced</strong><span>10 min heartbeat · Daily reconciliation · Location on</span>
            </button>
            <button className={guard.mode === 'conserve' ? 'usageMode active' : 'usageMode'} disabled={busy !== ''} onClick={() => void applyGuard('conserve')}>
              <strong>Conserve</strong><span>15 min heartbeat · Daily inventory · Location off</span>
            </button>
            <button className={guard.mode === 'critical' ? 'usageMode active' : 'usageMode'} disabled={busy !== ''} onClick={() => void applyGuard('critical')}>
              <strong>Critical</strong><span>30 min heartbeat · Network/location off</span>
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
          <p className="usageFootnote">Manual Resource Guard keeps core management available. Automatic Usage Restriction can tighten further to 6-hour or once-daily sync and can hold audit events locally when the Free-tier allowance is close to exhaustion.</p>
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
    </> : activeTab === 'daily' ? <>
      <div className="usageDailyHeader">
        <div>
          <h3>Daily billing-cycle analysis</h3>
          <p>{daily ? `${dateOnly(daily.cycleStart)} – ${dateOnly(daily.cycleEnd)}` : 'Current billing cycle'} · updated automatically as hourly telemetry arrives.</p>
        </div>
        <span className={`usageTrendBadge ${dailyAnalysis?.egressTrend || 'safe'}`}>
          {dailyAnalysis?.egressTrend === 'critical' ? 'High projected egress' : dailyAnalysis?.egressTrend === 'watch' ? 'Watch projected egress' : 'Usage pace within guard'}
        </span>
      </div>

      {dailyAnalysis && daily ? <>
        <div className="cards endpointCards usageCards usageDailyCards">
          <div className="metric"><span>Projected egress</span><strong>{formatBytes(dailyAnalysis.projectedEgress)}</strong><small>at current pace · limit 5 GB</small></div>
          <div className="metric"><span>Remaining egress budget</span><strong>{formatBytes(dailyAnalysis.safeDailyEgress)}/day</strong><small>average for remaining {dailyAnalysis.remainingDays} days</small></div>
          <div className="metric"><span>Peak egress day</span><strong>{formatBytes(dailyAnalysis.peakEgress.egressBytes)}</strong><small>{shortDay(dailyAnalysis.peakEgress.day)}</small></div>
          <div className="metric"><span>Peak log-ingest day</span><strong>{formatBytes(dailyAnalysis.peakIngest.logIngestBytes)}</strong><small>{shortDay(dailyAnalysis.peakIngest.day)}</small></div>
        </div>

        <div className="usageAnalysisStrip">
          <div><span>Cycle elapsed</span><strong>{dailyAnalysis.elapsed} / {dailyAnalysis.cycleDays} days</strong></div>
          <div><span>Egress used</span><strong>{percent(dailyAnalysis.totals.egress, daily.limits.egressBytes).toFixed(2)}%</strong></div>
          <div><span>Log ingest used</span><strong>{percent(dailyAnalysis.totals.ingest, daily.limits.logIngestionBytes).toFixed(2)}%</strong></div>
          <div><span>Safe log-ingest budget</span><strong>{formatBytes(dailyAnalysis.safeDailyIngest)}/day</strong></div>
        </div>

        <div className="panel usagePanel usageChartPanel">
          <div className="panelTitle usagePanelTitle"><span>Daily quota burn</span><small>Daily share of each monthly allowance</small></div>
          <UsageLineChart rows={daily.days} />
        </div>

        <div className="panel usagePanel usageChartPanel">
          <div className="panelTitle usagePanelTitle"><span>Cumulative quota trend</span><small>How quickly each allowance is being consumed</small></div>
          <UsageLineChart rows={daily.days} cumulative />
        </div>

        <div className="panel usagePanel">
          <div className="panelTitle usagePanelTitle"><span>Daily usage detail</span><small>{daily.days.length} day{daily.days.length === 1 ? '' : 's'} recorded</small></div>
          <div className="usageDailyTableWrap">
            <table className="usageDailyTable">
              <thead><tr><th>Date</th><th>Egress</th><th>Web</th><th>Agents</th><th>Log ingest</th><th>Log query</th><th>API requests</th><th>Log events</th><th>Coverage</th></tr></thead>
              <tbody>{[...daily.days].reverse().map(row => <tr key={row.day}>
                <td>{shortDay(row.day)}</td>
                <td>{formatBytes(row.egressBytes)}</td>
                <td>{formatBytes(row.webEgressBytes)}</td>
                <td>{formatBytes(row.agentEgressBytes)}</td>
                <td>{formatBytes(row.logIngestBytes)}</td>
                <td>{formatBytes(row.logQueryBytes)}</td>
                <td>{row.apiRequests.toLocaleString()}</td>
                <td>{row.logEvents.toLocaleString()}</td>
                <td><span className={row.hasDirectCoverage ? 'coverageBadge direct' : 'coverageBadge partial'}>{row.hasDirectCoverage ? 'Direct' : row.samples > 0 ? 'Partial' : 'Awaiting data'}</span></td>
              </tr>)}</tbody>
            </table>
          </div>
          <p className="usageFootnote">Egress is the Smart Console payload traffic we can measure directly; Supabase Unified Egress may also contain other service traffic. Log figures are based on the hourly non-overlapping platform collector windows.</p>
        </div>
      </> : <div className="panel usagePanel"><div className="usageEmpty">Daily usage will appear as soon as billing-cycle telemetry is recorded.</div></div>}
    </> : <>
      <div className="usageRestrictionHeader">
        <div>
          <span className="usageEyebrow">Automatic Free-tier protection</span>
          <h3>Usage Restriction</h3>
          <p>When any monitored Free-tier allowance reaches 50%, Smart Console automatically reduces background traffic. Restrictions become progressively stronger as the billing-cycle allowance is consumed.</p>
        </div>
        <span className={`restrictionStageBadge ${restriction?.currentStage || 'normal'}`}>{restriction?.currentStage || 'normal'}</span>
      </div>

      {restriction ? <>
        <div className="cards endpointCards usageCards usageRestrictionCards">
          <div className="metric"><span>Highest quota usage</span><strong>{Number(restriction.triggerPercent || 0).toFixed(2)}%</strong><small>{(restriction.triggerMetric || 'none').replaceAll('_',' ')}</small></div>
          <div className="metric"><span>Automatic protection</span><strong>{restriction.autoEnabled && !restriction.manualStage ? 'ON' : 'Manual'}</strong><small>first restriction at {restriction.thresholds.restricted}%</small></div>
          <div className="metric"><span>Current heartbeat</span><strong>{restriction.guard.heartbeat_seconds >= 3600 ? `${Math.round(restriction.guard.heartbeat_seconds / 3600)} hr` : `${Math.round(restriction.guard.heartbeat_seconds / 60)} min`}</strong><small>core endpoint presence</small></div>
          <div className="metric"><span>Audit event uploads</span><strong>{restriction.controls.auditEventUploadEnabled ? 'Enabled' : 'Held locally'}</strong><small>{restriction.controls.auditEventUploadEnabled ? 'batched with heartbeat' : 'retained until restrictions ease'}</small></div>
        </div>

        <div className="usageGrid">
          <div className="panel usagePanel">
            <div className="panelTitle usagePanelTitle"><span>Protection controls</span><small>Last checked {dateTime(restriction.lastEvaluatedAt)}</small></div>
            <div className="restrictionControlBody">
              <label className="restrictionAutoToggle">
                <input type="checkbox" checked={restriction.autoEnabled && !restriction.manualStage} disabled={busy !== ''} onChange={event => void updateRestriction(event.target.checked, null)} />
                <span><strong>Automatic restriction from 50%</strong><small>Recommended. The hourly usage collector evaluates the highest tracked Free-tier percentage and applies the matching protection stage.</small></span>
              </label>
              <div className="restrictionManual">
                <span>Manual override</span>
                <div>
                  {(['normal','restricted','severe','critical','survival'] as RestrictionStage[]).map(stage =>
                    <button key={stage} className={restriction.manualStage === stage ? 'usageMode active' : 'usageMode'} disabled={busy !== ''} onClick={() => void updateRestriction(false, stage)}>
                      <strong>{stage}</strong>
                    </button>)}
                  <button className="secondary compactButton" disabled={busy !== ''} onClick={() => void updateRestriction(true, null)}>Return to automatic</button>
                </div>
              </div>
              <p className="usageFootnote noPad">Automatic mode is intentionally allowed to sacrifice non-essential telemetry before the project reaches a Free-tier limit. Core enrollment and the managed-update path remain available.</p>
            </div>
          </div>

          <div className="panel usagePanel">
            <div className="panelTitle usagePanelTitle"><span>Current access restrictions</span><small>{restriction.currentStage} stage</small></div>
            <div className="restrictionAccessList">
              <div><span>Network telemetry</span><strong>{restriction.guard.network_enabled ? 'On' : 'Off'}</strong></div>
              <div><span>Location telemetry</span><strong>{restriction.guard.location_enabled && restriction.controls.locationDeliveryEnabled ? 'On' : 'Off'}</strong></div>
              <div><span>App deployment delivery</span><strong>{restriction.controls.deploymentDeliveryEnabled ? 'On' : 'Paused'}</strong></div>
              <div><span>Remote support delivery</span><strong>{restriction.controls.remoteSupportDeliveryEnabled ? 'On' : 'Paused'}</strong></div>
              <div><span>Audit event upload</span><strong>{restriction.controls.auditEventUploadEnabled ? 'On' : 'Held locally'}</strong></div>
              <div><span>Full inventory reconciliation</span><strong>Daily</strong></div>
            </div>
          </div>
        </div>

        <div className="panel usagePanel">
          <div className="panelTitle usagePanelTitle"><span>Restriction ladder</span><small>Escalates using the highest tracked Free-tier percentage</small></div>
          <div className="restrictionLadder">
            {restriction.profiles.map(profile => <div key={profile.stage} className={`restrictionStep ${profile.stage === restriction.currentStage ? 'active' : ''}`}>
              <div className="restrictionStepHead"><strong>{profile.stage}</strong><span>{profile.fromPercent}%+</span></div>
              <div><span>Heartbeat</span><strong>{profile.heartbeatSeconds >= 86400 ? 'Once/day' : profile.heartbeatSeconds >= 3600 ? `Every ${Math.round(profile.heartbeatSeconds/3600)} hr` : `Every ${Math.round(profile.heartbeatSeconds/60)} min`}</strong></div>
              <div><span>Inventory</span><strong>{profile.inventory}</strong></div>
              <div><span>Network</span><strong>{profile.network}</strong></div>
              <div><span>Events</span><strong>{profile.events}</strong></div>
              <div><span>Commands</span><strong>{profile.commands}</strong></div>
            </div>)}
          </div>
        </div>

        <div className="panel usagePanel">
          <div className="panelTitle usagePanelTitle"><span>Free-tier pressure</span><small>Current billing cycle</small></div>
          <div className="restrictionPressure">
            {[
              ['Egress', restriction.usage.egressPercent, formatBytes(restriction.usage.egressBytes)],
              ['Log ingestion', restriction.usage.logIngestionPercent, formatBytes(restriction.usage.logIngestionBytes)],
              ['Log query', restriction.usage.logQueryPercent, formatBytes(restriction.usage.logQueryBytes)],
              ['Database', restriction.usage.databasePercent, formatBytes(restriction.usage.databaseBytes)],
              ['File storage', restriction.usage.fileStoragePercent, formatBytes(restriction.usage.fileStorageBytes)],
              ['Monthly active users', restriction.usage.monthlyActiveUsersPercent, restriction.usage.monthlyActiveUsers.toLocaleString()],
            ].map(([label,pct,value]) => <div key={String(label)}>
              <div><strong>{label}</strong><span>{Number(pct).toFixed(2)}% · {value}</span></div>
              <div className="usageBar"><i style={{width:`${Math.min(100,Number(pct))}%`}} className={Number(pct)>=80?'danger':Number(pct)>=50?'warn':''} /></div>
            </div>)}
          </div>
          <p className="usageFootnote">Tracked egress remains a lower-bound Smart Console measurement unless Supabase exposes the unified billing meter. Automatic restriction therefore also watches Log Ingestion, Database, Storage, MAU and Log Query and reacts to whichever tracked percentage is highest.</p>
        </div>
      </> : <div className="panel usagePanel"><div className="usageEmpty">Usage Restriction status is not available yet.</div></div>}
    </>}
  </section>
}
