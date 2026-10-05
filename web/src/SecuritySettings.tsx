import { useEffect, useMemo, useState } from 'react'
import type { FormEvent } from 'react'
import { supabase } from './lib/supabase'
import { useAppDialog } from './AppDialogs'
import './security-settings.css'

type ManagedTerminal = {
  terminal_id: string
  computer_name: string
  app_version: string | null
  enrollment_status: 'active' | 'revoked'
  last_seen_at: string
}

type SettingsCommand = {
  command_id: string
  terminal_id: string
  status: string
  requested_at: string
  completed_at: string | null
  result: Record<string, unknown> | null
}

type PreciseLocation = {
  terminal_id: string
  sharing_enabled: boolean
  status: string
  latitude: number | null
  longitude: number | null
  accuracy_meters: number | null
  source: string | null
  captured_at: string | null
  received_at: string
}

const SETTINGS_AGENT_MIN_VERSION = '1.2.121'
const versionAtLeast = (current: string | null, minimum: string) => {
  const a = (current || '').split('.').map(Number)
  const b = minimum.split('.').map(Number)
  if (a.some(value => !Number.isFinite(value)) || a.length < 3) return false
  for (let i = 0; i < 3; i++) {
    if ((a[i] || 0) !== (b[i] || 0)) return (a[i] || 0) > (b[i] || 0)
  }
  return true
}
const dateTime = (value?: string | null) => value ? new Date(value).toLocaleString() : '—'

export function SecuritySettings({ terminals }: { terminals: ManagedTerminal[] }) {
  const { confirm, notify } = useAppDialog()
  const [selectedTerminalId, setSelectedTerminalId] = useState('')
  const [password, setPassword] = useState('')
  const [confirmation, setConfirmation] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [showConfirmation, setShowConfirmation] = useState(false)
  const [preciseLocation, setPreciseLocation] = useState<PreciseLocation | null>(null)
  const [locationViewed, setLocationViewed] = useState(false)
  const [locationBusy, setLocationBusy] = useState(false)
  const [locationMessage, setLocationMessage] = useState('')
  const [locationMapVisible, setLocationMapVisible] = useState(false)
  const [busy, setBusy] = useState(false)
  const [loadingHistory, setLoadingHistory] = useState(true)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [commands, setCommands] = useState<SettingsCommand[]>([])

  const activeTerminals = useMemo(
    () => terminals.filter(terminal => terminal.enrollment_status === 'active')
      .sort((a, b) => a.computer_name.localeCompare(b.computer_name)),
    [terminals],
  )
  useEffect(() => {
    if (!activeTerminals.some(item => item.terminal_id === selectedTerminalId)) {
      setSelectedTerminalId(activeTerminals[0]?.terminal_id ?? '')
    }
  }, [activeTerminals, selectedTerminalId])

  useEffect(() => {
    setPreciseLocation(null)
    setLocationViewed(false)
    setLocationMessage('')
    setLocationMapVisible(false)
  }, [selectedTerminalId])

  const refreshHistory = async () => {
    if (!supabase) return
    setLoadingHistory(true)
    const { data, error: queryError } = await supabase.from('endpoint_commands')
      .select('command_id,terminal_id,status,requested_at,completed_at,result')
      .eq('command_type', 'set_connection_password')
      .order('requested_at', { ascending: false }).limit(100)
    if (queryError) setError(queryError.message)
    else setCommands((data ?? []) as SettingsCommand[])
    setLoadingHistory(false)
  }
  useEffect(() => { void refreshHistory() }, [])

  const selected = activeTerminals.find(item => item.terminal_id === selectedTerminalId)
  const compatible = !!selected && versionAtLeast(selected.app_version, SETTINGS_AGENT_MIN_VERSION)
  const latest = commands.find(item => item.terminal_id === selectedTerminalId)

  const savePassword = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (!supabase || !selected || busy) return
    setNotice(''); setError('')
    if (!compatible) {
      setError(`Update this endpoint to Smart Console ${SETTINGS_AGENT_MIN_VERSION} or later before assigning its connection password.`)
      return
    }
    if (password.trim().length < 12 || password.length > 128) {
      setError('Use a settings password between 12 and 128 characters.')
      return
    }
    if (password !== confirmation) {
      setError('The passwords do not match.')
      return
    }

    const accepted = await confirm({
      title: 'Update endpoint settings password?',
      message: `Queue a new protected Connection settings password for ${selected.computer_name}? The change becomes active after the endpoint checks in.`,
      confirmLabel: 'Update password',
      tone: 'warning',
    })
    if (!accepted) return

    setBusy(true)
    try {
      const { data, error: invokeError } = await supabase.functions.invoke('terminal-admin', {
        body: {
          action: 'set_connection_password',
          terminalId: selected.terminal_id,
          connectionPassword: password,
        },
      })
      if (invokeError || data?.error) {
        const message = data?.error || invokeError?.message || 'The password policy could not be queued.'
        setError(message)
        await notify({ title: 'Password update failed', message, tone: 'danger' })
      } else {
        const message = `A connection-settings password update was queued for ${selected.computer_name}. It will become active after its agent checks in.`
        setNotice(message)
        await refreshHistory()
        await notify({ title: 'Password update queued', message, tone: 'success' })
      }
    } catch {
      const message = 'The administrative service could not be reached.'
      setError(message)
      await notify({ title: 'Password update failed', message, tone: 'danger' })
    } finally {
      setPassword(''); setConfirmation('')
      setBusy(false)
    }
  }

  const viewLocation = async () => {
    if (!supabase || !selectedTerminalId || locationBusy) return
    setLocationBusy(true)
    setLocationMessage('')
    setLocationMapVisible(false)
    const { data, error: rpcError } = await supabase.rpc('get_endpoint_location', {
      p_terminal_id: selectedTerminalId,
    })
    if (rpcError) {
      setLocationMessage(rpcError.message)
      setPreciseLocation(null)
    } else {
      setPreciseLocation((Array.isArray(data) ? data[0] : data) as PreciseLocation | null)
      setLocationViewed(true)
    }
    setLocationBusy(false)
  }

  const requestNewLocation = async () => {
    if (!supabase || !selected || locationBusy) return
    const accepted = await confirm({
      title: 'Request updated device location?',
      message: `Request a new authorized location reading from ${selected.computer_name}? Windows permission and the endpoint user's location-sharing choice still control whether a reading can be returned.`,
      confirmLabel: 'Request location',
      tone: 'info',
    })
    if (!accepted) return

    setLocationBusy(true)
    const { error: rpcError } = await supabase.rpc('request_endpoint_location', {
      p_terminal_id: selected.terminal_id,
    })
    const message = rpcError
      ? rpcError.message
      : 'Location refresh queued. The endpoint must be online with Windows location permission enabled.'
    setLocationMessage(message)
    setLocationBusy(false)
    await notify({
      title: rpcError ? 'Location request failed' : 'Location refresh queued',
      message,
      tone: rpcError ? 'danger' : 'success',
    })
  }

  return <section className="securitySettings">
    <div className="settingsIntro">
      <h2>Endpoint security settings</h2>
      <p>Manage protected connection settings, administrator passwords, and consented device-location controls for CRECCOM endpoints.</p>
    </div>

    <div className="panel settingsProtectionPanel">
      <div className="panelTitle">Administrator-managed settings password</div>
      <div className="settingsProtectionBody">
        <div className="settingsSecurityNotice">
          Only authorized administrators can create or rotate a password. The secure console sends a salted verifier to the selected endpoint; the plaintext password is not stored in the endpoint command.
        </div>
        <form className="settingsProtectionForm" onSubmit={savePassword}>
          <label className="settingsField">
            <span>Managed endpoint</span>
            <select required value={selectedTerminalId} onChange={event => {
              setSelectedTerminalId(event.target.value); setPassword(''); setConfirmation('')
              setShowPassword(false); setShowConfirmation(false)
              setError(''); setNotice('')
            }}>
              {activeTerminals.length === 0 && <option value="">No active endpoints</option>}
              {activeTerminals.map(item => <option key={item.terminal_id} value={item.terminal_id}>
                {item.computer_name} · Agent {item.app_version || 'unknown'}
              </option>)}
            </select>
          </label>
          {selected && <div className={compatible ? 'settingsAgentCompatibility ready' : 'settingsAgentCompatibility'}>
            {compatible ? 'Compatible agent version detected.' :
              `This endpoint must first update to version ${SETTINGS_AGENT_MIN_VERSION} or newer.`}
          </div>}
          <div className="settingsPasswordInputs">
            <label className="settingsField"><span>New administrator password</span>
              <span className="settingsPasswordControl">
                <input type={showPassword ? 'text' : 'password'} autoComplete="new-password" required minLength={12} maxLength={128}
                  value={password} onChange={event => setPassword(event.target.value)}
                  placeholder="Minimum 12 characters" />
                <button type="button" className="settingsPasswordToggle"
                  aria-label={showPassword ? 'Hide administrator password' : 'Show administrator password'}
                  title={showPassword ? 'Hide password' : 'Show password'}
                  onClick={() => setShowPassword(value => !value)}>
                  <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M2.8 12s3.3-5.5 9.2-5.5 9.2 5.5 9.2 5.5-3.3 5.5-9.2 5.5S2.8 12 2.8 12Z"/><circle cx="12" cy="12" r="2.5"/></svg>
                </button>
              </span>
            </label>
            <label className="settingsField"><span>Confirm password</span>
              <span className="settingsPasswordControl">
                <input type={showConfirmation ? 'text' : 'password'} autoComplete="new-password" required minLength={12} maxLength={128}
                  value={confirmation} onChange={event => setConfirmation(event.target.value)}
                  placeholder="Re-enter the password" />
                <button type="button" className="settingsPasswordToggle"
                  aria-label={showConfirmation ? 'Hide password confirmation' : 'Show password confirmation'}
                  title={showConfirmation ? 'Hide password' : 'Show password'}
                  onClick={() => setShowConfirmation(value => !value)}>
                  <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M2.8 12s3.3-5.5 9.2-5.5 9.2 5.5 9.2 5.5-3.3 5.5-9.2 5.5S2.8 12 2.8 12Z"/><circle cx="12" cy="12" r="2.5"/></svg>
                </button>
              </span>
            </label>
          </div>
          {error && <div className="errorBanner" role="alert">{error}</div>}
          {notice && <div className="settingsSuccess" role="status">{notice}</div>}
          <div className="settingsProtectionActions">
            <button type="submit" className="primary" disabled={busy || !compatible || !password || !confirmation}>
              {busy ? 'Saving policy…' : 'Set / rotate password'}
            </button>
            <button type="button" className="secondary" disabled={busy} onClick={() => {
              setPassword(''); setConfirmation(''); setShowPassword(false); setShowConfirmation(false); setError(''); setNotice('')
            }}>Clear</button>
          </div>
        </form>
        <div className="settingsPolicyStatus">
          <strong>Latest delivery status</strong>
          {!selected ? <span>No managed endpoint selected.</span> : !latest
            ? <span>No settings-password policy has been queued for this endpoint yet.</span>
            : <span><b>{latest.status.replaceAll('_', ' ')}</b> · requested {dateTime(latest.requested_at)}
              {latest.completed_at ? ` · completed ${dateTime(latest.completed_at)}` : ''}
              {latest.status === 'failed' && latest.result?.message ? ` · ${String(latest.result.message)}` : ''}
            </span>}
          <button type="button" className="secondary compactButton" disabled={loadingHistory}
            onClick={() => void refreshHistory()}>{loadingHistory ? 'Refreshing…' : 'Refresh delivery status'}</button>
        </div>
      </div>
    </div>

    <div className="panel settingsProtectionPanel settingsLocationPanel">
      <div className="panelTitle">Device location &amp; asset security</div>
      <div className="settingsProtectionBody">
        <div className="settingsSecurityNotice">
          Exact device location is available only after location sharing is enabled on the Windows Smart Console. Each administrator view is audited, and only the latest permitted reading is retained.
        </div>
        <div className="settingsLocationToolbar">
          <div>
            <strong>{selected?.computer_name || 'No managed endpoint selected'}</strong>
            <span>{selected ? `Agent ${selected.app_version || 'unknown'} · last seen ${dateTime(selected.last_seen_at)}` : 'Select an active endpoint above.'}</span>
          </div>
          <div>
            <button type="button" className="secondary compactButton" disabled={!selected || locationBusy}
              onClick={() => void viewLocation()}>{locationBusy ? 'Checking…' : 'View location (audited)'}</button>
            <button type="button" className="secondary compactButton" disabled={!selected || locationBusy}
              onClick={() => void requestNewLocation()}>Request updated reading</button>
          </div>
        </div>
        {locationMessage && <div className="settingsLocationMessage" role="status">{locationMessage}</div>}
        {locationViewed && (preciseLocation ? <div className="settingsLocationFacts">
          <div><span>Permission</span><strong>{preciseLocation.sharing_enabled ? 'Enabled on endpoint' : 'Disabled on endpoint'}</strong></div>
          <div><span>Collection status</span><strong>{preciseLocation.status.replaceAll('_', ' ')}</strong></div>
          <div><span>Last reading</span><strong>{dateTime(preciseLocation.captured_at)}</strong></div>
          <div><span>Reported accuracy</span><strong>{preciseLocation.accuracy_meters != null ? Number(preciseLocation.accuracy_meters).toLocaleString() + ' m' : '—'}</strong></div>
          <div><span>Latitude / Longitude</span><strong className="mono">{preciseLocation.latitude != null && preciseLocation.longitude != null ? preciseLocation.latitude + ', ' + preciseLocation.longitude : 'No permitted coordinates available'}</strong></div>
          <div><span>Positioning source</span><strong>{preciseLocation.source === 'windows_geolocator' ? 'Windows Location (GPS/Wi-Fi/network as available)' : '—'}</strong></div>
          {preciseLocation.latitude != null && preciseLocation.longitude != null && <div className="settingsLocationMapAction">
            <button type="button" className="secondary compactButton" onClick={() => setLocationMapVisible(value => !value)}>
              {locationMapVisible ? 'Hide map' : 'Show map (shares coordinates with OpenStreetMap)'}
            </button>
          </div>}
          {locationMapVisible && preciseLocation.latitude != null && preciseLocation.longitude != null && <iframe
            title="Last consented endpoint location" loading="lazy" referrerPolicy="no-referrer"
            className="settingsLocationMap"
            src={`https://www.openstreetmap.org/export/embed.html?bbox=${Number(preciseLocation.longitude)-0.004}%2C${Number(preciseLocation.latitude)-0.004}%2C${Number(preciseLocation.longitude)+0.004}%2C${Number(preciseLocation.latitude)+0.004}&marker=${preciseLocation.latitude}%2C${preciseLocation.longitude}`} />}
        </div> : <div className="settingsLocationEmpty">No approved Windows location has been reported for this endpoint.</div>)}
      </div>
    </div>

    <div className="panel settingsProtectionPanel">
      <div className="panelTitle">How access protection works</div>
      <div className="settingsProtectionBody settingsExplainer">
        <p>The password becomes active once the endpoint receives and acknowledges the settings policy. Until then, the local Connection settings section stays locked, including on installations without a provisioned password.</p>
        <p>Access automatically locks when the section is closed, after five minutes or when IT changes its password. Five incorrect attempts introduce a temporary retry delay. A fully sleeping PC cannot keep a live cloud connection; queued policies and events resume synchronization after wake.</p>
      </div>
    </div>
  </section>
}
