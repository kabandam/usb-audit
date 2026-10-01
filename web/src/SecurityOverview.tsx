import { useCallback, useEffect, useMemo, useState } from 'react'
import { supabase } from './lib/supabase'
import './security-overview.css'

export type OverviewDestination =
  | 'endpoints'
  | 'smart-console'
  | 'network'
  | 'software'
  | 'deployment'
  | 'remote'
  | 'file-sharing'
  | 'usage-monitor'
  | 'transfers'
  | 'enrollment'

type OverviewTab = 'overview' | 'endpoints' | 'security' | 'operations' | 'activity'

type ActivityItem = {
  occurredAt: string
  type: 'usb' | 'remote' | 'deployment' | string
  title: string
  detail: string
  status: string
}

type OverviewSnapshot = {
  generatedAt: string
  endpoints: {
    total: number
    online: number
    offline: number
    offline24h: number
    protected: number
    firewallOn: number
    accessRestricted: number
    agentCurrent: number
    agentIssues: number
    pendingEnrollment: number
  }
  security: {
    connectedUsb: number
    usbTransfersToday: number
    softwarePending: number
    softwareBlockRules: number
  }
  operations: {
    remoteActive: number
    remoteFailedToday: number
    deploymentActive: number
    deploymentFailed: number
    onedriveHealthy: number
    onedriveIssues: number
    networksReporting: number
    locationsAvailable: number
  }
  fileSharing: {
    total: number
    active: number
    downloads: number
    expiringSoon: number
  }
  usage: {
    currentStage?: string
    triggerMetric?: string
    triggerPercent?: number
    thresholds?: {
      restricted?: number
      severe?: number
      critical?: number
      survival?: number
    }
    usage?: Record<string, number>
  }
  recentActivity: ActivityItem[]
}

type AttentionItem = {
  title: string
  detail: string
  tone: 'warning' | 'danger' | 'info'
  destination: OverviewDestination
}

const EMPTY_SNAPSHOT: OverviewSnapshot = {
  generatedAt: '',
  endpoints: {
    total: 0, online: 0, offline: 0, offline24h: 0, protected: 0, firewallOn: 0,
    accessRestricted: 0, agentCurrent: 0, agentIssues: 0, pendingEnrollment: 0,
  },
  security: { connectedUsb: 0, usbTransfersToday: 0, softwarePending: 0, softwareBlockRules: 0 },
  operations: {
    remoteActive: 0, remoteFailedToday: 0, deploymentActive: 0, deploymentFailed: 0,
    onedriveHealthy: 0, onedriveIssues: 0, networksReporting: 0, locationsAvailable: 0,
  },
  fileSharing: { total: 0, active: 0, downloads: 0, expiringSoon: 0 },
  usage: { currentStage: 'unknown', triggerPercent: 0, usage: {} },
  recentActivity: [],
}

const dateTime = (value?: string | null) => value ? new Date(value).toLocaleString() : '—'
const plural = (count: number, one: string, many = one + 's') => count === 1 ? one : many
const clampPercent = (value: number) => Math.max(0, Math.min(100, Number.isFinite(value) ? value : 0))

const prettify = (value?: string | null) => {
  if (!value) return '—'
  return value.replace(/_/g, ' ').replace(/\b\w/g, letter => letter.toUpperCase())
}

const numericUsagePercentages = (snapshot: OverviewSnapshot) => {
  const usage = snapshot.usage?.usage || {}
  return Object.entries(usage)
    .filter(([key, value]) => key.toLowerCase().endsWith('percent') && typeof value === 'number')
    .map(([, value]) => Number(value))
    .filter(value => Number.isFinite(value))
}

const destinationForActivity = (type: string): OverviewDestination => {
  if (type === 'remote') return 'remote'
  if (type === 'deployment') return 'deployment'
  return 'transfers'
}

export function SecurityOverview({ onNavigate }: { onNavigate: (destination: OverviewDestination) => void }) {
  const [tab, setTab] = useState<OverviewTab>('overview')
  const [snapshot, setSnapshot] = useState<OverviewSnapshot>(EMPTY_SNAPSHOT)
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)
  const [error, setError] = useState('')

  const load = useCallback(async (manual = false) => {
    if (!supabase) return
    manual ? setRefreshing(true) : setLoading(true)
    setError('')

    const { data, error: rpcError } = await supabase.rpc('get_security_overview')
    if (rpcError) setError(rpcError.message)
    else if (data) setSnapshot(data as OverviewSnapshot)

    setLoading(false)
    setRefreshing(false)
  }, [])

  useEffect(() => {
    void load()
    const timer = window.setInterval(() => {
      if (document.visibilityState === 'visible') void load()
    }, 120_000)
    return () => window.clearInterval(timer)
  }, [load])

  const highestUsage = useMemo(() => {
    const values = numericUsagePercentages(snapshot)
    return values.length ? Math.max(...values) : Number(snapshot.usage?.triggerPercent || 0)
  }, [snapshot])

  const attention = useMemo<AttentionItem[]>(() => {
    const items: AttentionItem[] = []
    const endpoints = snapshot.endpoints
    const operations = snapshot.operations

    if (endpoints.offline24h > 0) items.push({
      title: endpoints.offline24h + ' ' + plural(endpoints.offline24h, 'endpoint') + ' offline for more than 24 hours',
      detail: 'Prioritize connectivity and heartbeat checks.',
      tone: 'danger',
      destination: 'endpoints',
    })

    if (endpoints.agentIssues > 0) items.push({
      title: endpoints.agentIssues + ' Smart Console ' + plural(endpoints.agentIssues, 'agent') + ' need attention',
      detail: 'Update checks are not reporting as fully up to date.',
      tone: 'warning',
      destination: 'smart-console',
    })

    const protectionGap = Math.max(0, endpoints.total - Math.min(endpoints.protected, endpoints.firewallOn))
    if (protectionGap > 0) items.push({
      title: protectionGap + ' ' + plural(protectionGap, 'endpoint') + ' missing full protection confirmation',
      detail: 'Review Microsoft Defender and Windows Firewall status.',
      tone: 'warning',
      destination: 'endpoints',
    })

    if (snapshot.security.softwarePending > 0) items.push({
      title: snapshot.security.softwarePending + ' software ' + plural(snapshot.security.softwarePending, 'approval') + ' waiting for review',
      detail: 'Review newly detected applications before allowing them.',
      tone: 'warning',
      destination: 'software',
    })

    if (operations.onedriveIssues > 0) items.push({
      title: operations.onedriveIssues + ' OneDrive ' + plural(operations.onedriveIssues, 'endpoint') + ' need attention',
      detail: 'Backup or sync protection is not healthy.',
      tone: 'warning',
      destination: 'remote',
    })

    if (operations.remoteFailedToday > 0) items.push({
      title: operations.remoteFailedToday + ' remote ' + plural(operations.remoteFailedToday, 'action') + ' failed today',
      detail: 'Review failed endpoint commands.',
      tone: 'danger',
      destination: 'remote',
    })

    if (operations.deploymentFailed > 0) items.push({
      title: operations.deploymentFailed + ' application deployment ' + plural(operations.deploymentFailed, 'task') + ' failed',
      detail: 'Open deployment history to review failures and retry where appropriate.',
      tone: 'danger',
      destination: 'deployment',
    })

    if (endpoints.pendingEnrollment > 0) items.push({
      title: endpoints.pendingEnrollment + ' machine ' + plural(endpoints.pendingEnrollment, 'enrollment') + ' awaiting approval',
      detail: 'Approve or deny the pending machine connection.',
      tone: 'info',
      destination: 'enrollment',
    })

    if ((snapshot.usage.currentStage || 'normal') !== 'normal' || highestUsage >= 50) items.push({
      title: 'Free-tier protection is in ' + prettify(snapshot.usage.currentStage || 'normal') + ' mode',
      detail: 'Highest monitored resource is at ' + highestUsage.toFixed(1) + '%.',
      tone: highestUsage >= 80 ? 'danger' : 'warning',
      destination: 'usage-monitor',
    })

    if (snapshot.fileSharing.expiringSoon > 0) items.push({
      title: snapshot.fileSharing.expiringSoon + ' shared file ' + plural(snapshot.fileSharing.expiringSoon, 'link') + ' expire within 7 days',
      detail: 'Review whether the links should remain available.',
      tone: 'info',
      destination: 'file-sharing',
    })

    return items
  }, [snapshot, highestUsage])

  const endpointProtectionPercent = snapshot.endpoints.total
    ? Math.round((Math.min(snapshot.endpoints.protected, snapshot.endpoints.firewallOn) / snapshot.endpoints.total) * 100)
    : 0

  const onlinePercent = snapshot.endpoints.total
    ? Math.round((snapshot.endpoints.online / snapshot.endpoints.total) * 100)
    : 0

  const tabs: Array<{ id: OverviewTab, label: string }> = [
    { id: 'overview', label: 'Overview' },
    { id: 'endpoints', label: 'Endpoints' },
    { id: 'security', label: 'Security' },
    { id: 'operations', label: 'Operations' },
    { id: 'activity', label: 'Activity' },
  ]

  if (loading && !snapshot.generatedAt) {
    return <div className="securityOverviewLoading">Loading complete system overview…</div>
  }

  return <section className="securityOverview">
    <div className="overviewCommandBar">
      <div>
        <strong>System command centre</strong>
        <span>Live summary across endpoint management, security, operations and sharing.</span>
      </div>
      <div className="overviewRefresh">
        <span>Updated {dateTime(snapshot.generatedAt)}</span>
        <button className="secondary" type="button" disabled={refreshing} onClick={() => void load(true)}>
          {refreshing ? 'Refreshing…' : 'Refresh'}
        </button>
      </div>
    </div>

    {error && <div className="errorBanner overviewError">{error}</div>}

    <div className="overviewTabs" role="tablist" aria-label="Security overview sections">
      {tabs.map(item => <button
        key={item.id}
        type="button"
        role="tab"
        aria-selected={tab === item.id}
        className={tab === item.id ? 'active' : ''}
        onClick={() => setTab(item.id)}
      >{item.label}</button>)}
    </div>

    {tab === 'overview' && <>
      <div className="overviewHeroCards">
        <OverviewCard
          eyebrow="Managed endpoints"
          value={String(snapshot.endpoints.total)}
          detail={snapshot.endpoints.online + ' online · ' + snapshot.endpoints.offline + ' offline'}
          tone={snapshot.endpoints.offline24h > 0 ? 'warning' : 'positive'}
          badge={onlinePercent + '% online'}
          onClick={() => onNavigate('endpoints')}
        />
        <OverviewCard
          eyebrow="Needs attention"
          value={String(attention.length)}
          detail={attention.length ? 'Areas currently requiring review' : 'No priority issues detected'}
          tone={attention.some(item => item.tone === 'danger') ? 'danger' : attention.length ? 'warning' : 'positive'}
          badge={attention.length ? 'Review' : 'All clear'}
        />
        <OverviewCard
          eyebrow="Free-tier usage"
          value={highestUsage.toFixed(1) + '%'}
          detail={'Resource guard · ' + prettify(snapshot.usage.currentStage || 'unknown')}
          tone={highestUsage >= 80 ? 'danger' : highestUsage >= 50 ? 'warning' : 'positive'}
          badge={prettify(snapshot.usage.currentStage || 'unknown')}
          progress={highestUsage}
          onClick={() => onNavigate('usage-monitor')}
        />
        <OverviewCard
          eyebrow="File sharing"
          value={String(snapshot.fileSharing.active)}
          detail={snapshot.fileSharing.downloads + ' downloads · ' + snapshot.fileSharing.total + ' total files'}
          tone="neutral"
          badge={snapshot.fileSharing.expiringSoon ? snapshot.fileSharing.expiringSoon + ' expiring' : 'Active links'}
          onClick={() => onNavigate('file-sharing')}
        />
      </div>

      <div className="overviewTwoColumn">
        <div className="overviewPanel">
          <div className="overviewPanelHeading">
            <div><strong>Needs attention</strong><span>Priority items from across the console</span></div>
          </div>
          <div className="attentionList">
            {attention.length === 0
              ? <div className="overviewEmptyState"><strong>No priority issues</strong><span>The monitored areas are not currently reporting anything that needs immediate review.</span></div>
              : attention.slice(0, 7).map((item, index) => <button
                  key={item.title + index}
                  className="attentionRow"
                  type="button"
                  onClick={() => onNavigate(item.destination)}
                >
                  <i className={'attentionDot ' + item.tone} />
                  <div><strong>{item.title}</strong><span>{item.detail}</span></div>
                  <b>›</b>
                </button>)}
          </div>
        </div>

        <div className="overviewPanel">
          <div className="overviewPanelHeading">
            <div><strong>Coverage snapshot</strong><span>How much of the managed environment is visible and protected</span></div>
          </div>
          <div className="coverageList">
            <CoverageRow label="Endpoint heartbeat" value={snapshot.endpoints.online} total={snapshot.endpoints.total} />
            <CoverageRow label="Defender protected" value={snapshot.endpoints.protected} total={snapshot.endpoints.total} />
            <CoverageRow label="Firewall enabled" value={snapshot.endpoints.firewallOn} total={snapshot.endpoints.total} />
            <CoverageRow label="Network reporting" value={snapshot.operations.networksReporting} total={snapshot.endpoints.total} />
            <CoverageRow label="Location available" value={snapshot.operations.locationsAvailable} total={snapshot.endpoints.total} />
          </div>
        </div>
      </div>

      <div className="overviewQuickGrid">
        <QuickStat label="Agent current" value={snapshot.endpoints.agentCurrent} detail={snapshot.endpoints.agentIssues + ' issue(s)'} onClick={() => onNavigate('smart-console')} />
        <QuickStat label="USB activity today" value={snapshot.security.usbTransfersToday} detail={snapshot.security.connectedUsb + ' connected USBs'} onClick={() => onNavigate('transfers')} />
        <QuickStat label="Remote actions active" value={snapshot.operations.remoteActive} detail={snapshot.operations.remoteFailedToday + ' failed today'} onClick={() => onNavigate('remote')} />
        <QuickStat label="Deployment failures" value={snapshot.operations.deploymentFailed} detail={snapshot.operations.deploymentActive + ' active now'} onClick={() => onNavigate('deployment')} />
      </div>
    </>}

    {tab === 'endpoints' && <div className="overviewCardGrid">
      <OverviewCard eyebrow="Managed endpoints" value={String(snapshot.endpoints.total)} detail={snapshot.endpoints.online + ' online · ' + snapshot.endpoints.offline + ' offline'} badge={onlinePercent + '% online'} tone={snapshot.endpoints.offline24h ? 'warning' : 'positive'} onClick={() => onNavigate('endpoints')} />
      <OverviewCard eyebrow="Agent health" value={String(snapshot.endpoints.agentCurrent)} detail={snapshot.endpoints.agentIssues + ' update/check issues'} badge="Smart Console" tone={snapshot.endpoints.agentIssues ? 'warning' : 'positive'} onClick={() => onNavigate('smart-console')} />
      <OverviewCard eyebrow="Endpoint protection" value={endpointProtectionPercent + '%'} detail={snapshot.endpoints.protected + ' Defender · ' + snapshot.endpoints.firewallOn + ' firewall'} badge="Protection" tone={endpointProtectionPercent < 100 ? 'warning' : 'positive'} onClick={() => onNavigate('endpoints')} />
      <OverviewCard eyebrow="Network visibility" value={String(snapshot.operations.networksReporting)} detail={'of ' + snapshot.endpoints.total + ' endpoints reporting network data'} badge="Network Track" tone="neutral" onClick={() => onNavigate('network')} />
      <OverviewCard eyebrow="Device location" value={String(snapshot.operations.locationsAvailable)} detail={'of ' + snapshot.endpoints.total + ' endpoints with a usable position'} badge="Location" tone="neutral" onClick={() => onNavigate('network')} />
      <OverviewCard eyebrow="OneDrive protection" value={String(snapshot.operations.onedriveHealthy)} detail={snapshot.operations.onedriveIssues + ' endpoints need attention'} badge="Backup" tone={snapshot.operations.onedriveIssues ? 'warning' : 'neutral'} onClick={() => onNavigate('remote')} />
      <OverviewCard eyebrow="Access restricted" value={String(snapshot.endpoints.accessRestricted)} detail="Endpoints currently security restricted" badge="Remote security" tone={snapshot.endpoints.accessRestricted ? 'warning' : 'positive'} onClick={() => onNavigate('remote')} />
      <OverviewCard eyebrow="Enrollment requests" value={String(snapshot.endpoints.pendingEnrollment)} detail="Machines awaiting administrator decision" badge="Enrollment" tone={snapshot.endpoints.pendingEnrollment ? 'warning' : 'positive'} onClick={() => onNavigate('enrollment')} />
    </div>}

    {tab === 'security' && <>
      <div className="overviewCardGrid">
        <OverviewCard eyebrow="USB security" value={String(snapshot.security.usbTransfersToday)} detail={snapshot.security.connectedUsb + ' USB devices currently reported'} badge="Transfers today" tone="neutral" onClick={() => onNavigate('transfers')} />
        <OverviewCard eyebrow="Software approvals" value={String(snapshot.security.softwarePending)} detail="Newly detected applications awaiting review" badge="Software control" tone={snapshot.security.softwarePending ? 'warning' : 'positive'} onClick={() => onNavigate('software')} />
        <OverviewCard eyebrow="Active block rules" value={String(snapshot.security.softwareBlockRules)} detail="Software-control block rules currently enabled" badge="Policy" tone="neutral" onClick={() => onNavigate('software')} />
        <OverviewCard eyebrow="Endpoint restrictions" value={String(snapshot.endpoints.accessRestricted)} detail="Computers with security access restrictions" badge="Security control" tone={snapshot.endpoints.accessRestricted ? 'warning' : 'positive'} onClick={() => onNavigate('remote')} />
      </div>
      <ActivityPanel
        title="Recent security activity"
        items={snapshot.recentActivity.filter(item => item.type === 'usb').slice(0, 12)}
        onNavigate={onNavigate}
      />
    </>}

    {tab === 'operations' && <div className="overviewCardGrid">
      <OverviewCard eyebrow="Remote support" value={String(snapshot.operations.remoteActive)} detail={snapshot.operations.remoteFailedToday + ' failed today'} badge="Active commands" tone={snapshot.operations.remoteFailedToday ? 'warning' : 'neutral'} onClick={() => onNavigate('remote')} />
      <OverviewCard eyebrow="App deployment" value={String(snapshot.operations.deploymentActive)} detail={snapshot.operations.deploymentFailed + ' failed deployment tasks'} badge="Deployment" tone={snapshot.operations.deploymentFailed ? 'warning' : 'neutral'} onClick={() => onNavigate('deployment')} />
      <OverviewCard eyebrow="File sharing" value={String(snapshot.fileSharing.active)} detail={snapshot.fileSharing.downloads + ' downloads across ' + snapshot.fileSharing.total + ' files'} badge={snapshot.fileSharing.expiringSoon ? snapshot.fileSharing.expiringSoon + ' expiring' : 'Links active'} tone="neutral" onClick={() => onNavigate('file-sharing')} />
      <OverviewCard eyebrow="Free-tier guard" value={highestUsage.toFixed(1) + '%'} detail={'Current stage: ' + prettify(snapshot.usage.currentStage || 'unknown')} badge={'Trigger: ' + prettify(snapshot.usage.triggerMetric || '—')} tone={highestUsage >= 80 ? 'danger' : highestUsage >= 50 ? 'warning' : 'positive'} progress={highestUsage} onClick={() => onNavigate('usage-monitor')} />
      <OverviewCard eyebrow="OneDrive health" value={String(snapshot.operations.onedriveHealthy)} detail={snapshot.operations.onedriveIssues + ' endpoints need backup/sync attention'} badge="Cloud backup" tone={snapshot.operations.onedriveIssues ? 'warning' : 'neutral'} onClick={() => onNavigate('remote')} />
      <OverviewCard eyebrow="Pending enrollment" value={String(snapshot.endpoints.pendingEnrollment)} detail="New machines waiting for administrator approval" badge="Endpoint onboarding" tone={snapshot.endpoints.pendingEnrollment ? 'warning' : 'positive'} onClick={() => onNavigate('enrollment')} />
    </div>}

    {tab === 'activity' && <ActivityPanel title="Recent system activity" items={snapshot.recentActivity} onNavigate={onNavigate} />}
  </section>
}

function OverviewCard({
  eyebrow,
  value,
  detail,
  badge,
  tone = 'neutral',
  progress,
  onClick,
}: {
  eyebrow: string
  value: string
  detail: string
  badge?: string
  tone?: 'neutral' | 'positive' | 'warning' | 'danger'
  progress?: number
  onClick?: () => void
}) {
  const Tag = onClick ? 'button' : 'div'
  return <Tag className={'overviewCard ' + tone + (onClick ? ' clickable' : '')} {...(onClick ? { type: 'button' as const, onClick } : {})}>
    <div className="overviewCardTop"><span>{eyebrow}</span>{badge && <b>{badge}</b>}</div>
    <strong className="overviewCardValue">{value}</strong>
    <small>{detail}</small>
    {progress !== undefined && <div className="overviewMeter"><div style={{ width: clampPercent(progress) + '%' }} /></div>}
    {onClick && <span className="overviewOpen">Open module →</span>}
  </Tag>
}

function QuickStat({ label, value, detail, onClick }: { label: string, value: number, detail: string, onClick: () => void }) {
  return <button className="overviewQuickStat" type="button" onClick={onClick}>
    <span>{label}</span><strong>{value}</strong><small>{detail}</small>
  </button>
}

function CoverageRow({ label, value, total }: { label: string, value: number, total: number }) {
  const percent = total ? Math.round((value / total) * 100) : 0
  return <div className="coverageRow">
    <div><span>{label}</span><strong>{value} / {total}</strong></div>
    <div className="coverageTrack"><div style={{ width: clampPercent(percent) + '%' }} /></div>
    <small>{percent}% coverage</small>
  </div>
}

function ActivityPanel({
  title,
  items,
  onNavigate,
}: {
  title: string
  items: ActivityItem[]
  onNavigate: (destination: OverviewDestination) => void
}) {
  return <div className="overviewPanel activityPanel">
    <div className="overviewPanelHeading"><div><strong>{title}</strong><span>Latest events recorded across the console</span></div></div>
    <div className="activityList">
      {items.length === 0
        ? <div className="overviewEmptyState"><strong>No recent activity</strong><span>New events will appear here as modules report them.</span></div>
        : items.map((item, index) => <button
            className="activityRow"
            type="button"
            key={item.occurredAt + item.type + index}
            onClick={() => onNavigate(destinationForActivity(item.type))}
          >
            <span className={'activityType ' + item.type}>{item.type === 'remote' ? 'RM' : item.type === 'deployment' ? 'DP' : 'USB'}</span>
            <div><strong>{item.title || prettify(item.type)}</strong><span>{item.detail || 'No additional detail'}</span></div>
            <div className="activityMeta"><span>{dateTime(item.occurredAt)}</span><b>{prettify(item.status)}</b></div>
          </button>)}
    </div>
  </div>
}
