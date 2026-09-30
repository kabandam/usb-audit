import { useEffect, useMemo, useState } from 'react'
import { supabase } from './lib/supabase'
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
  const [selectedTerminalId, setSelectedTerminalId] = useState('')
  const [password, setPassword] = useState('')
  const [confirmation, setConfirmation] = useState('')
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

  const savePassword = async (event: React.FormEvent<HTMLFormElement>) => {
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
        setError(data?.error || invokeError?.message || 'The password policy could not be queued.')
      } else {
        setNotice(`A connection-settings password update was queued for ${selected.computer_name}. It will become active after its agent checks in. Confirm delivery below.`)
        await refreshHistory()
      }
    } catch {
      setError('The administrative service could not be reached.')
    } finally {
      setPassword(''); setConfirmation('')
      setBusy(false)
    }
  }

  return <section className="securitySettings">
    <div className="settingsIntro">
      <h2>Endpoint connection protection</h2>
      <p>Manage access to the sensitive Connection settings section of the installed Windows Smart Console. Endpoint users can still refresh activity and request cloud synchronization without this password.</p>
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
              <input type="password" autoComplete="new-password" required minLength={12} maxLength={128}
                value={password} onChange={event => setPassword(event.target.value)}
                placeholder="Minimum 12 characters" />
            </label>
            <label className="settingsField"><span>Confirm password</span>
              <input type="password" autoComplete="new-password" required minLength={12} maxLength={128}
                value={confirmation} onChange={event => setConfirmation(event.target.value)}
                placeholder="Re-enter the password" />
            </label>
          </div>
          {error && <div className="errorBanner" role="alert">{error}</div>}
          {notice && <div className="settingsSuccess" role="status">{notice}</div>}
          <div className="settingsProtectionActions">
            <button type="submit" className="primary" disabled={busy || !compatible || !password || !confirmation}>
              {busy ? 'Saving policy…' : 'Set / rotate password'}
            </button>
            <button type="button" className="secondary" disabled={busy} onClick={() => {
              setPassword(''); setConfirmation(''); setError(''); setNotice('')
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

    <div className="panel settingsProtectionPanel">
      <div className="panelTitle">How access protection works</div>
      <div className="settingsProtectionBody settingsExplainer">
        <p>The password becomes active once the endpoint receives and acknowledges the settings policy. Until then, the local Connection settings section stays locked, including on installations without a provisioned password.</p>
        <p>Access automatically locks when the section is closed, after five minutes or when IT changes its password. Five incorrect attempts introduce a temporary retry delay. A fully sleeping PC cannot keep a live cloud connection; queued policies and events resume synchronization after wake.</p>
      </div>
    </div>
  </section>
}
