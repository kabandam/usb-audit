import { useEffect, useMemo, useState } from 'react'
import { supabase } from './lib/supabase'
import './deployment-manager.css'

type Terminal = {
  terminal_id: string
  computer_name: string
  windows_user: string | null
  app_version: string | null
  enrollment_status: 'active' | 'revoked'
  last_seen_at: string
}

type DeploymentApp = {
  app_id: string
  name: string
  version: string
  publisher: string | null
  installer_type: 'msi' | 'exe'
  package_url: string
  sha256: string
  install_args: string
  success_codes: number[]
  notes: string | null
  is_active: boolean
  created_at: string
}

type EndpointGroup = {
  group_id: string
  name: string
  description: string | null
  created_at: string
}

type GroupMember = {
  group_id: string
  terminal_id: string
}

type DeploymentBatch = {
  batch_id: string
  name: string
  requested_at: string
  app_count: number
  terminal_count: number
  status: 'queued' | 'in_progress' | 'completed' | 'partial' | 'failed' | 'cancelled'
}

type DeploymentTask = {
  task_id: string
  batch_id: string
  app_id: string
  terminal_id: string
  sequence_no: number
  command_id: string | null
  status: 'pending' | 'acknowledged' | 'completed' | 'failed' | 'cancelled'
  message: string | null
  requested_at: string
  completed_at: string | null
}

type Tab = 'deploy' | 'applications' | 'groups' | 'history'

const isOnline = (lastSeen: string) => Date.now() - new Date(lastSeen).getTime() < 45_000
const dateTime = (value?: string | null) => value ? new Date(value).toLocaleString() : '—'
const shortHash = (value: string) => value ? `${value.slice(0, 10)}…${value.slice(-6)}` : '—'
const packageHost = (value: string) => {
  try { return new URL(value).hostname }
  catch { return value }
}

export function DeploymentManager() {
  const [tab, setTab] = useState<Tab>('deploy')
  const [terminals, setTerminals] = useState<Terminal[]>([])
  const [apps, setApps] = useState<DeploymentApp[]>([])
  const [groups, setGroups] = useState<EndpointGroup[]>([])
  const [members, setMembers] = useState<GroupMember[]>([])
  const [batches, setBatches] = useState<DeploymentBatch[]>([])
  const [tasks, setTasks] = useState<DeploymentTask[]>([])
  const [selectedApps, setSelectedApps] = useState<Set<string>>(new Set())
  const [selectedTerminals, setSelectedTerminals] = useState<Set<string>>(new Set())
  const [selectedGroups, setSelectedGroups] = useState<Set<string>>(new Set())
  const [batchName, setBatchName] = useState('')
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [busy, setBusy] = useState('')

  const [editingAppId, setEditingAppId] = useState<string | null>(null)
  const [appName, setAppName] = useState('')
  const [appVersion, setAppVersion] = useState('')
  const [appPublisher, setAppPublisher] = useState('')
  const [installerType, setInstallerType] = useState<'msi' | 'exe'>('msi')
  const [packageUrl, setPackageUrl] = useState('')
  const [sha256, setSha256] = useState('')
  const [installArgs, setInstallArgs] = useState('')
  const [successCodes, setSuccessCodes] = useState('0,1641,3010')
  const [appNotes, setAppNotes] = useState('')

  const [editingGroupId, setEditingGroupId] = useState<string | null>(null)
  const [groupName, setGroupName] = useState('')
  const [groupDescription, setGroupDescription] = useState('')
  const [groupTerminals, setGroupTerminals] = useState<Set<string>>(new Set())

  const load = async () => {
    if (!supabase) return
    const results = await Promise.all([
      supabase.from('terminals').select('terminal_id,computer_name,windows_user,app_version,enrollment_status,last_seen_at').order('computer_name'),
      supabase.from('deployment_apps').select('*').eq('is_active', true).order('name').order('version'),
      supabase.from('endpoint_groups').select('*').order('name'),
      supabase.from('endpoint_group_members').select('*'),
      supabase.from('deployment_batches').select('*').order('requested_at', { ascending: false }).limit(60),
      supabase.from('deployment_tasks').select('*').order('requested_at', { ascending: false }).limit(2500),
    ])
    const firstError = results.find(result => result.error)?.error
    setError(firstError?.message || '')
    setTerminals((results[0].data ?? []) as Terminal[])
    setApps((results[1].data ?? []) as DeploymentApp[])
    setGroups((results[2].data ?? []) as EndpointGroup[])
    setMembers((results[3].data ?? []) as GroupMember[])
    setBatches((results[4].data ?? []) as DeploymentBatch[])
    setTasks((results[5].data ?? []) as DeploymentTask[])
  }

  useEffect(() => {
    load()
    const timer = window.setInterval(load, 15_000)
    return () => window.clearInterval(timer)
  }, [])

  const terminalMap = useMemo(() => new Map(terminals.map(item => [item.terminal_id, item])), [terminals])
  const appMap = useMemo(() => new Map(apps.map(item => [item.app_id, item])), [apps])

  const resolvedTargets = useMemo(() => {
    const ids = new Set(selectedTerminals)
    for (const member of members) {
      if (selectedGroups.has(member.group_id)) ids.add(member.terminal_id)
    }
    return [...ids].filter(id => terminalMap.get(id)?.enrollment_status === 'active')
  }, [selectedTerminals, selectedGroups, members, terminalMap])

  const invokeAdmin = async (body: Record<string, unknown>) => {
    if (!supabase) return { data: null, error: 'Supabase is unavailable' }
    const { data, error: invokeError } = await supabase.functions.invoke('terminal-admin', { body })
    return { data, error: data?.error || invokeError?.message || '' }
  }

  const queueDeployment = async () => {
    if (selectedApps.size === 0 || resolvedTargets.length === 0) return
    const selectedAppNames = [...selectedApps].map(id => appMap.get(id)?.name).filter(Boolean).join(', ')
    if (!window.confirm(`Deploy ${selectedApps.size} application(s) to ${resolvedTargets.length} managed PC(s)?\n\n${selectedAppNames}`)) return

    setBusy('deploy'); setError(''); setNotice('')
    const { data, error: invokeError } = await invokeAdmin({
      action: 'create_app_deployment',
      batchName: batchName.trim(),
      appIds: [...selectedApps],
      terminalIds: [...selectedTerminals],
      groupIds: [...selectedGroups],
    })
    if (invokeError) {
      setError(invokeError)
    } else {
      setNotice(`Deployment queued: ${data.taskCount} task(s) across ${data.terminalCount} PC(s).`)
      setSelectedApps(new Set())
      setSelectedTerminals(new Set())
      setSelectedGroups(new Set())
      setBatchName('')
      setTab('history')
      await load()
    }
    setBusy('')
  }

  const resetAppForm = () => {
    setEditingAppId(null); setAppName(''); setAppVersion(''); setAppPublisher('')
    setInstallerType('msi'); setPackageUrl(''); setSha256(''); setInstallArgs('')
    setSuccessCodes('0,1641,3010'); setAppNotes('')
  }

  const saveApp = async () => {
    const parsedCodes = successCodes.split(',').map(value => Number.parseInt(value.trim(), 10)).filter(Number.isInteger)
    setBusy('app'); setError(''); setNotice('')
    const { error: invokeError } = await invokeAdmin({
      action: 'save_deployment_app',
      appId: editingAppId || undefined,
      name: appName,
      version: appVersion,
      publisher: appPublisher,
      installerType,
      packageUrl,
      sha256,
      installArgs,
      successCodes: parsedCodes,
      notes: appNotes,
    })
    if (invokeError) setError(invokeError)
    else {
      setNotice(editingAppId ? 'Application updated.' : 'Application added to the deployment catalog.')
      resetAppForm()
      await load()
    }
    setBusy('')
  }

  const editApp = (app: DeploymentApp) => {
    setEditingAppId(app.app_id); setAppName(app.name); setAppVersion(app.version)
    setAppPublisher(app.publisher || ''); setInstallerType(app.installer_type)
    setPackageUrl(app.package_url); setSha256(app.sha256); setInstallArgs(app.install_args || '')
    setSuccessCodes((app.success_codes || [0, 1641, 3010]).join(',')); setAppNotes(app.notes || '')
    setTab('applications')
  }

  const resetGroupForm = () => {
    setEditingGroupId(null); setGroupName(''); setGroupDescription(''); setGroupTerminals(new Set())
  }

  const saveGroup = async () => {
    setBusy('group'); setError(''); setNotice('')
    const { error: invokeError } = await invokeAdmin({
      action: 'save_endpoint_group',
      groupId: editingGroupId || undefined,
      name: groupName,
      description: groupDescription,
      terminalIds: [...groupTerminals],
    })
    if (invokeError) setError(invokeError)
    else {
      setNotice(editingGroupId ? 'Endpoint group updated.' : 'Endpoint group created.')
      resetGroupForm()
      await load()
    }
    setBusy('')
  }

  const editGroup = (group: EndpointGroup) => {
    setEditingGroupId(group.group_id); setGroupName(group.name)
    setGroupDescription(group.description || '')
    setGroupTerminals(new Set(members.filter(item => item.group_id === group.group_id).map(item => item.terminal_id)))
    setTab('groups')
  }

  const batchStats = (batchId: string) => {
    const rows = tasks.filter(task => task.batch_id === batchId)
    return {
      total: rows.length,
      completed: rows.filter(task => task.status === 'completed').length,
      failed: rows.filter(task => task.status === 'failed').length,
      active: rows.filter(task => ['pending', 'acknowledged'].includes(task.status)).length,
    }
  }

  return <section className="deploymentSection">
    {error && <div className="errorBanner">{error}</div>}
    {notice && <div className="deploymentNotice">{notice}</div>}

    <div className="deploymentTabs">
      <button className={tab === 'deploy' ? 'active' : ''} onClick={() => setTab('deploy')}>Deploy</button>
      <button className={tab === 'applications' ? 'active' : ''} onClick={() => setTab('applications')}>Applications</button>
      <button className={tab === 'groups' ? 'active' : ''} onClick={() => setTab('groups')}>Endpoint Groups</button>
      <button className={tab === 'history' ? 'active' : ''} onClick={() => setTab('history')}>Deployment History</button>
    </div>

    {tab === 'deploy' && <>
      <div className="cards deploymentCards">
        <Metric label="Deployment apps" value={apps.length.toString()} detail="Approved catalog entries" />
        <Metric label="Managed PCs" value={terminals.filter(t => t.enrollment_status === 'active').length.toString()} detail={`${terminals.filter(t => isOnline(t.last_seen_at)).length} currently online`} />
        <Metric label="Endpoint groups" value={groups.length.toString()} detail="Reusable IT targeting" />
        <Metric label="Active deployments" value={batches.filter(b => ['queued', 'in_progress'].includes(b.status)).length.toString()} detail="Queued or installing" />
      </div>

      <div className="deploymentGrid">
        <div className="deploymentPanel">
          <div className="deploymentPanelHead"><div><span>Step 1</span><strong>Select applications</strong></div><em>{selectedApps.size} selected</em></div>
          <div className="deploymentChoiceList">
            {apps.length === 0 ? <p className="deploymentEmpty">Add an application to the catalog first.</p> : apps.map(app => <label className="deploymentChoice" key={app.app_id}>
              <input type="checkbox" checked={selectedApps.has(app.app_id)} onChange={event => {
                const next = new Set(selectedApps)
                if (event.target.checked) next.add(app.app_id); else next.delete(app.app_id)
                setSelectedApps(next)
              }} />
              <span className="deploymentCheck" />
              <div><strong>{app.name}</strong><small>{app.version} · {app.publisher || 'Publisher not specified'}</small></div>
              <b>{app.installer_type.toUpperCase()}</b>
            </label>)}
          </div>
        </div>

        <div className="deploymentPanel">
          <div className="deploymentPanelHead"><div><span>Step 2</span><strong>Choose endpoint groups</strong></div><em>{selectedGroups.size} selected</em></div>
          <div className="groupTargetGrid">
            {groups.length === 0 ? <p className="deploymentEmpty">No saved endpoint groups yet.</p> : groups.map(group => {
              const count = members.filter(item => item.group_id === group.group_id).length
              return <label className={selectedGroups.has(group.group_id) ? 'groupTarget selected' : 'groupTarget'} key={group.group_id}>
                <input type="checkbox" checked={selectedGroups.has(group.group_id)} onChange={event => {
                  const next = new Set(selectedGroups)
                  if (event.target.checked) next.add(group.group_id); else next.delete(group.group_id)
                  setSelectedGroups(next)
                }} />
                <strong>{group.name}</strong><small>{count} PC{count === 1 ? '' : 's'}</small>
              </label>
            })}
          </div>
        </div>

        <div className="deploymentPanel deploymentEndpoints">
          <div className="deploymentPanelHead">
            <div><span>Step 3</span><strong>Add individual PCs</strong></div>
            <button className="textButton" onClick={() => {
              const activeIds = terminals.filter(t => t.enrollment_status === 'active').map(t => t.terminal_id)
              setSelectedTerminals(selectedTerminals.size === activeIds.length ? new Set() : new Set(activeIds))
            }}>{selectedTerminals.size === terminals.filter(t => t.enrollment_status === 'active').length ? 'Clear all' : 'Select all'}</button>
          </div>
          <div className="endpointTargetList">
            {terminals.filter(t => t.enrollment_status === 'active').map(terminal => <label className="endpointTarget" key={terminal.terminal_id}>
              <input type="checkbox" checked={selectedTerminals.has(terminal.terminal_id)} onChange={event => {
                const next = new Set(selectedTerminals)
                if (event.target.checked) next.add(terminal.terminal_id); else next.delete(terminal.terminal_id)
                setSelectedTerminals(next)
              }} />
              <span className="deploymentCheck" />
              <div><strong>{terminal.computer_name}</strong><small>{terminal.windows_user || terminal.terminal_id}</small></div>
              <span className={isOnline(terminal.last_seen_at) ? 'deploymentOnline' : 'deploymentOffline'}>{isOnline(terminal.last_seen_at) ? 'Online' : 'Offline'}</span>
              <code>{terminal.app_version || '—'}</code>
            </label>)}
          </div>
        </div>
      </div>

      <div className="deploymentLaunchBar">
        <div><span>Deployment scope</span><strong>{selectedApps.size} app{selectedApps.size === 1 ? '' : 's'} → {resolvedTargets.length} PC{resolvedTargets.length === 1 ? '' : 's'}</strong><small>Group targets and individually selected PCs are automatically de-duplicated.</small></div>
        <input value={batchName} onChange={event => setBatchName(event.target.value)} placeholder="Deployment name (optional)" maxLength={120} />
        <button className="primary" disabled={busy !== '' || selectedApps.size === 0 || resolvedTargets.length === 0} onClick={queueDeployment}>{busy === 'deploy' ? 'Queuing…' : 'Deploy applications'}</button>
      </div>
    </>}

    {tab === 'applications' && <div className="deploymentTwoCol">
      <div className="deploymentPanel">
        <div className="deploymentPanelHead"><div><span>Catalog</span><strong>{editingAppId ? 'Edit application' : 'Add application'}</strong></div>{editingAppId && <button className="textButton" onClick={resetAppForm}>Cancel edit</button>}</div>
        <div className="deploymentForm">
          <label>Application name<input value={appName} onChange={e => setAppName(e.target.value)} placeholder="e.g. Google Chrome" /></label>
          <div className="deploymentFormRow">
            <label>Version<input value={appVersion} onChange={e => setAppVersion(e.target.value)} placeholder="e.g. 142.0" /></label>
            <label>Publisher<input value={appPublisher} onChange={e => setAppPublisher(e.target.value)} placeholder="e.g. Google LLC" /></label>
          </div>
          <div className="deploymentFormRow">
            <label>Installer type<select value={installerType} onChange={e => setInstallerType(e.target.value as 'msi' | 'exe')}><option value="msi">MSI</option><option value="exe">EXE</option></select></label>
            <label>Successful exit codes<input value={successCodes} onChange={e => setSuccessCodes(e.target.value)} placeholder="0,1641,3010" /></label>
          </div>
          <label>HTTPS package URL<input value={packageUrl} onChange={e => setPackageUrl(e.target.value)} placeholder="https://..." /></label>
          <label>SHA-256<input className="mono" value={sha256} onChange={e => setSha256(e.target.value)} placeholder="64-character SHA-256 digest" maxLength={64} /></label>
          <label>Silent install arguments<input value={installArgs} onChange={e => setInstallArgs(e.target.value)} placeholder={installerType === 'msi' ? 'Additional MSI properties only; /qn is added automatically' : 'e.g. /silent /norestart'} /></label>
          <label>IT notes<textarea value={appNotes} onChange={e => setAppNotes(e.target.value)} placeholder="Optional deployment notes" rows={3} /></label>
          <div className="deploymentSecurityNote"><strong>Package verification</strong><span>Every endpoint verifies this SHA-256 before starting the installer. MSI installs also run with /qn /norestart.</span></div>
          <button className="primary" disabled={busy !== '' || !appName || !appVersion || !packageUrl || sha256.length !== 64} onClick={saveApp}>{busy === 'app' ? 'Saving…' : editingAppId ? 'Update application' : 'Add to catalog'}</button>
        </div>
      </div>

      <div className="deploymentPanel">
        <div className="deploymentPanelHead"><div><span>{apps.length} entries</span><strong>Approved application catalog</strong></div></div>
        <div className="catalogList">{apps.length === 0 ? <p className="deploymentEmpty">No deployment applications yet.</p> : apps.map(app => <div className="catalogRow" key={app.app_id}>
          <div className="catalogIcon">{app.name.slice(0, 1).toUpperCase()}</div>
          <div className="catalogIdentity"><strong>{app.name}</strong><span>{app.version} · {app.publisher || 'Publisher not specified'}</span><small>{packageHost(app.package_url)} · SHA-256 {shortHash(app.sha256)}</small></div>
          <span className="installerBadge">{app.installer_type.toUpperCase()}</span>
          <button className="linkButton" onClick={() => editApp(app)}>Edit</button>
        </div>)}</div>
      </div>
    </div>}

    {tab === 'groups' && <div className="deploymentTwoCol">
      <div className="deploymentPanel">
        <div className="deploymentPanelHead"><div><span>Reusable targeting</span><strong>{editingGroupId ? 'Edit endpoint group' : 'Create endpoint group'}</strong></div>{editingGroupId && <button className="textButton" onClick={resetGroupForm}>Cancel edit</button>}</div>
        <div className="deploymentForm">
          <label>Group name<input value={groupName} onChange={e => setGroupName(e.target.value)} placeholder="e.g. Zomba Office PCs" /></label>
          <label>Description<textarea value={groupDescription} onChange={e => setGroupDescription(e.target.value)} placeholder="Optional description" rows={2} /></label>
          <div className="groupMemberSelector">
            <div className="groupMemberSelectorHead"><strong>Select PCs</strong><span>{groupTerminals.size} selected</span></div>
            {terminals.filter(t => t.enrollment_status === 'active').map(terminal => <label key={terminal.terminal_id}>
              <input type="checkbox" checked={groupTerminals.has(terminal.terminal_id)} onChange={event => {
                const next = new Set(groupTerminals)
                if (event.target.checked) next.add(terminal.terminal_id); else next.delete(terminal.terminal_id)
                setGroupTerminals(next)
              }} />
              <span className="deploymentCheck" /><div><strong>{terminal.computer_name}</strong><small>{terminal.windows_user || 'Managed endpoint'}</small></div>
            </label>)}
          </div>
          <button className="primary" disabled={busy !== '' || !groupName} onClick={saveGroup}>{busy === 'group' ? 'Saving…' : editingGroupId ? 'Update group' : 'Create group'}</button>
        </div>
      </div>

      <div className="deploymentPanel">
        <div className="deploymentPanelHead"><div><span>{groups.length} groups</span><strong>Endpoint groups</strong></div></div>
        <div className="groupList">{groups.length === 0 ? <p className="deploymentEmpty">No endpoint groups yet.</p> : groups.map(group => {
          const groupMembers = members.filter(item => item.group_id === group.group_id)
          return <div className="groupRow" key={group.group_id}>
            <div><strong>{group.name}</strong><span>{group.description || 'No description'}</span><small>{groupMembers.length} PC{groupMembers.length === 1 ? '' : 's'}: {groupMembers.map(member => terminalMap.get(member.terminal_id)?.computer_name || member.terminal_id).join(', ') || 'None'}</small></div>
            <button className="linkButton" onClick={() => editGroup(group)}>Edit</button>
          </div>
        })}</div>
      </div>
    </div>}

    {tab === 'history' && <div className="deploymentPanel">
      <div className="deploymentPanelHead"><div><span>Latest 60 batches</span><strong>Application deployment history</strong></div><button className="secondary compactButton" onClick={load}>Refresh</button></div>
      <div className="tableWrap"><table className="deploymentHistory"><thead><tr><th>Requested</th><th>Deployment</th><th>Scope</th><th>Progress</th><th>Status</th></tr></thead><tbody>
        {batches.length === 0 ? <tr><td colSpan={5} className="empty">No application deployments yet.</td></tr> : batches.map(batch => {
          const stats = batchStats(batch.batch_id)
          const rows = tasks.filter(task => task.batch_id === batch.batch_id)
          const failures = rows.filter(task => task.status === 'failed')
          return <tr key={batch.batch_id}>
            <td>{dateTime(batch.requested_at)}</td>
            <td><strong>{batch.name}</strong><small>{batch.app_count} app{batch.app_count === 1 ? '' : 's'} · {stats.total} task{stats.total === 1 ? '' : 's'}</small></td>
            <td>{batch.terminal_count} PC{batch.terminal_count === 1 ? '' : 's'}<small>{[...new Set(rows.map(task => terminalMap.get(task.terminal_id)?.computer_name || task.terminal_id))].slice(0, 4).join(', ')}{batch.terminal_count > 4 ? '…' : ''}</small></td>
            <td><div className="deploymentProgress"><div style={{ width: `${stats.total ? ((stats.completed + stats.failed) / stats.total) * 100 : 0}%` }} /></div><small>{stats.completed} installed · {stats.failed} failed · {stats.active} active</small>{failures.length > 0 && <span className="failureHint">{failures[0].message || 'One or more deployments failed.'}</span>}</td>
            <td><span className={`batchStatus ${batch.status}`}>{batch.status.replace('_', ' ')}</span></td>
          </tr>
        })}</tbody></table></div>
    </div>}
  </section>
}

function Metric({ label, value, detail }: { label: string, value: string, detail: string }) {
  return <div className="metric"><span>{label}</span><strong>{value}</strong><small>{detail}</small></div>
}
