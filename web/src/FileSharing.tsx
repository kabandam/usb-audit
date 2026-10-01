import { useCallback, useEffect, useMemo, useState } from 'react'
import type { Session } from '@supabase/supabase-js'
import { supabase } from './lib/supabase'
import './file-sharing.css'

const GRAPH_TOKEN_KEY = 'smart-console:graph-provider-token'
const GRAPH_TOKEN_EXPIRES_KEY = 'smart-console:graph-provider-token-expires'
const DATA_CENTRE_DRIVE_ID = 'b!l4Wat0zMtkGXeibrIQS1DJ9lhL-UKuhPvT-7il85MzyA3mCd8GVwTZ1O0u25u4_s'
const DATA_CENTRE_PARENT_FOLDER_ID = '01AIJXTSLSPMBUPZP2OFDKZ7FJXJSCOA6U'
const FILE_SHARE_FOLDER = 'Shared Files'
const MAX_SIMPLE_UPLOAD_BYTES = 250 * 1024 * 1024
const PRODUCTION_SUPABASE_URL = 'https://pgbipustotixwahmotvu.supabase.co'

type ShareScope = 'public' | 'organization' | 'specific'
type ExpiryPreset = 'never' | '1d' | '7d' | '30d' | 'custom'

type ShareRow = {
  share_id: string
  share_token: string
  file_name: string
  file_size_bytes: number
  mime_type: string | null
  drive_id: string | null
  drive_item_id: string
  drive_web_url: string | null
  share_url: string
  share_permission_ids: string[]
  access_scope: ShareScope
  allowed_emails: string[]
  expires_at: string | null
  max_downloads: number | null
  download_count: number
  last_downloaded_at: string | null
  is_active: boolean
  uploaded_by_email: string
  created_at: string
}

const formatBytes = (value?: number | null) => {
  if (!value) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  let size = value
  let unit = 0
  while (size >= 1024 && unit < units.length - 1) { size /= 1024; unit += 1 }
  return `${size >= 100 || unit === 0 ? Math.round(size) : size.toFixed(1)} ${units[unit]}`
}

const dateTime = (value?: string | null) => value ? new Date(value).toLocaleString() : 'Never'
const cleanFileName = (name: string) => name.replace(/[\\/:*?"<>|#%]/g, '_').replace(/\s+/g, ' ').trim() || 'file'
const shareLink = (token: string) => `${window.location.origin}/share/${token}`

const providerToken = (session: Session) => {
  const token = session.provider_token || sessionStorage.getItem(GRAPH_TOKEN_KEY) || ''
  const expires = Number(sessionStorage.getItem(GRAPH_TOKEN_EXPIRES_KEY) || '0')
  if (expires && Date.now() >= expires - 60_000) return ''
  return token
}

const graphRequest = async (token: string, path: string, init: RequestInit = {}) => {
  const response = await fetch(`https://graph.microsoft.com/v1.0${path}`, {
    ...init,
    headers: {
      authorization: `Bearer ${token}`,
      ...(init.body && !(init.body instanceof File) ? { 'content-type': 'application/json' } : {}),
      ...(init.headers || {}),
    },
  })

  if (!response.ok) {
    const raw = await response.text()
    let message = `Microsoft Graph returned ${response.status}`
    try {
      const parsed = JSON.parse(raw)
      message = parsed?.error?.message || message
    } catch {
      if (raw) message = raw.slice(0, 240)
    }
    throw new Error(message)
  }

  if (response.status === 204) return null
  return response.json()
}

const getExpiry = (preset: ExpiryPreset, custom: string) => {
  if (preset === 'never') return null
  if (preset === 'custom') {
    if (!custom) throw new Error('Choose the custom expiry date and time.')
    const date = new Date(custom)
    if (date.getTime() <= Date.now()) throw new Error('Expiry must be in the future.')
    return date.toISOString()
  }
  const days = preset === '1d' ? 1 : preset === '7d' ? 7 : 30
  return new Date(Date.now() + days * 86_400_000).toISOString()
}

const parseEmails = (value: string) => Array.from(new Set(
  value.split(/[\n,;]+/).map(item => item.trim().toLowerCase()).filter(Boolean),
))

const ensureShareFolder = async (token: string) => {
  const driveId = encodeURIComponent(DATA_CENTRE_DRIVE_ID)
  const parentId = encodeURIComponent(DATA_CENTRE_PARENT_FOLDER_ID)
  const encoded = encodeURIComponent(FILE_SHARE_FOLDER)
  const existing = await fetch(
    `https://graph.microsoft.com/v1.0/drives/${driveId}/items/${parentId}:/${encoded}`,
    { headers: { authorization: `Bearer ${token}` } },
  )

  if (existing.ok) return existing.json()
  if (existing.status !== 404) {
    const raw = await existing.text()
    throw new Error(raw || `Could not open the Data Centre OneDrive share folder (${existing.status}).`)
  }

  return graphRequest(token, `/drives/${driveId}/items/${parentId}/children`, {
    method: 'POST',
    body: JSON.stringify({
      name: FILE_SHARE_FOLDER,
      folder: {},
      '@microsoft.graph.conflictBehavior': 'fail',
    }),
  })
}

const shareStatus = (item: ShareRow) => {
  if (!item.is_active) return { label: 'Disabled', tone: 'disabled' }
  if (item.expires_at && new Date(item.expires_at).getTime() <= Date.now()) return { label: 'Expired', tone: 'expired' }
  if (item.max_downloads && item.download_count >= item.max_downloads) return { label: 'Limit reached', tone: 'expired' }
  return { label: 'Active', tone: 'active' }
}

export function PublicShareRedirect({ token }: { token: string }) {
  useEffect(() => {
    const base = (import.meta.env.VITE_SUPABASE_URL as string | undefined) || PRODUCTION_SUPABASE_URL
    window.location.replace(`${base}/functions/v1/file-share-download?token=${encodeURIComponent(token)}`)
  }, [token])

  return <div className="shareRedirectPage">
    <div className="shareRedirectCard">
      <img src="/creccom-round-logo.png" alt="CRECCOM" />
      <h1>Preparing your file…</h1>
      <p>The secure share link is being checked before opening the OneDrive download.</p>
    </div>
  </div>
}

export function FileSharing({ session }: { session: Session }) {
  const [shares, setShares] = useState<ShareRow[]>([])
  const [file, setFile] = useState<File | null>(null)
  const [scope, setScope] = useState<ShareScope>('organization')
  const [emails, setEmails] = useState('')
  const [expiryPreset, setExpiryPreset] = useState<ExpiryPreset>('7d')
  const [customExpiry, setCustomExpiry] = useState('')
  const [maxDownloads, setMaxDownloads] = useState('')
  const [search, setSearch] = useState('')
  const [busy, setBusy] = useState(false)
  const [loading, setLoading] = useState(true)
  const [message, setMessage] = useState('')
  const [error, setError] = useState('')

  const loadShares = useCallback(async () => {
    if (!supabase) return
    setLoading(true)
    setError('')
    const { data, error: queryError } = await supabase
      .from('file_shares')
      .select('share_id,share_token,file_name,file_size_bytes,mime_type,drive_id,drive_item_id,drive_web_url,share_url,share_permission_ids,access_scope,allowed_emails,expires_at,max_downloads,download_count,last_downloaded_at,is_active,uploaded_by_email,created_at')
      .order('created_at', { ascending: false })

    if (queryError) setError(queryError.message)
    setShares((data || []) as ShareRow[])
    setLoading(false)
  }, [])

  useEffect(() => { void loadShares() }, [loadShares])

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase()
    if (!q) return shares
    return shares.filter(item =>
      item.file_name.toLowerCase().includes(q) ||
      item.uploaded_by_email.toLowerCase().includes(q) ||
      item.allowed_emails.some(email => email.includes(q)),
    )
  }, [shares, search])

  const metrics = useMemo(() => {
    const active = shares.filter(item => shareStatus(item).tone === 'active').length
    const downloads = shares.reduce((sum, item) => sum + Number(item.download_count || 0), 0)
    const expiring = shares.filter(item => item.is_active && item.expires_at && new Date(item.expires_at).getTime() > Date.now() && new Date(item.expires_at).getTime() < Date.now() + 7 * 86_400_000).length
    return { total: shares.length, active, downloads, expiring }
  }, [shares])

  const upload = async () => {
    if (!supabase || !file || busy) return
    setBusy(true)
    setError('')
    setMessage('')

    try {
      if (file.size > MAX_SIMPLE_UPLOAD_BYTES) {
        throw new Error('This first version supports files up to 250 MB per upload.')
      }

      const token = providerToken(session)
      if (!token) throw new Error('Your Microsoft file-access session has expired. Sign out, then sign in again to continue.')

      const allowedEmails = parseEmails(emails)
      if (scope === 'specific' && allowedEmails.length === 0) {
        throw new Error('Enter at least one email address for a restricted share.')
      }

      const expiresAt = getExpiry(expiryPreset, customExpiry)
      const max = maxDownloads.trim() ? Number(maxDownloads) : null
      if (max !== null && (!Number.isInteger(max) || max < 1)) {
        throw new Error('Download limit must be a whole number greater than zero.')
      }

      setMessage('Uploading file to Data Centre OneDrive → Smart Console App Packages → Shared Files…')
      const folder = await ensureShareFolder(token)
      const safeName = cleanFileName(file.name)
      const stamp = new Date().toISOString().replace(/[-:]/g, '').replace('T', '-').slice(0, 15)
      const storageName = `${stamp}__${safeName}`
      const uploaded = await graphRequest(token, `/drives/${encodeURIComponent(DATA_CENTRE_DRIVE_ID)}/items/${encodeURIComponent(folder.id)}:/${encodeURIComponent(storageName)}:/content`, {
        method: 'PUT',
        body: file,
        headers: { 'content-type': file.type || 'application/octet-stream' },
      })

      let targetUrl = uploaded.webUrl as string
      let permissionIds: string[] = []

      setMessage('Creating the controlled OneDrive sharing permission…')
      if (scope === 'specific') {
        const invitation = await graphRequest(token, `/drives/${encodeURIComponent(DATA_CENTRE_DRIVE_ID)}/items/${encodeURIComponent(uploaded.id)}/invite`, {
          method: 'POST',
          body: JSON.stringify({
            recipients: allowedEmails.map(email => ({ email })),
            requireSignIn: true,
            sendInvitation: false,
            roles: ['read'],
          }),
        })
        permissionIds = (invitation?.value || []).map((item: { id?: string }) => item.id).filter(Boolean)
      } else {
        const permission = await graphRequest(token, `/drives/${encodeURIComponent(DATA_CENTRE_DRIVE_ID)}/items/${encodeURIComponent(uploaded.id)}/createLink`, {
          method: 'POST',
          body: JSON.stringify({
            type: 'view',
            scope: scope === 'public' ? 'anonymous' : 'organization',
            ...(expiresAt ? { expirationDateTime: expiresAt } : {}),
          }),
        })
        targetUrl = permission?.link?.webUrl || targetUrl
        permissionIds = permission?.id ? [permission.id] : []
      }

      const driveInfo = uploaded.parentReference?.driveId || DATA_CENTRE_DRIVE_ID
      const { error: insertError } = await supabase.from('file_shares').insert({
        file_name: file.name,
        file_size_bytes: file.size,
        mime_type: file.type || null,
        drive_id: driveInfo,
        drive_item_id: uploaded.id,
        drive_web_url: uploaded.webUrl || null,
        share_url: targetUrl,
        share_permission_ids: permissionIds,
        access_scope: scope,
        allowed_emails: allowedEmails,
        expires_at: expiresAt,
        max_downloads: max,
        uploaded_by: session.user.id,
        uploaded_by_email: session.user.email || '',
      })

      if (insertError) throw insertError

      setFile(null)
      setEmails('')
      setMaxDownloads('')
      setMessage('File uploaded and share link created.')
      const input = document.getElementById('fileShareInput') as HTMLInputElement | null
      if (input) input.value = ''
      await loadShares()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not create the file share.')
      setMessage('')
    } finally {
      setBusy(false)
    }
  }

  const copyLink = async (token: string) => {
    await navigator.clipboard.writeText(shareLink(token))
    setMessage('Share link copied.')
  }

  const toggleShare = async (item: ShareRow) => {
    if (!supabase) return
    setError('')
    const { error: updateError } = await supabase
      .from('file_shares')
      .update({ is_active: !item.is_active, updated_at: new Date().toISOString() })
      .eq('share_id', item.share_id)
    if (updateError) setError(updateError.message)
    else await loadShares()
  }

  const deleteShare = async (item: ShareRow) => {
    if (!supabase || !window.confirm(`Delete "${item.file_name}" from OneDrive and remove its share record?`)) return
    setBusy(true)
    setError('')
    try {
      const token = providerToken(session)
      if (!token) throw new Error('Your Microsoft file-access session has expired. Sign out and sign in again before deleting OneDrive files.')
      await graphRequest(token, `/drives/${encodeURIComponent(item.drive_id || DATA_CENTRE_DRIVE_ID)}/items/${encodeURIComponent(item.drive_item_id)}`, { method: 'DELETE' })
      const { error: deleteError } = await supabase.from('file_shares').delete().eq('share_id', item.share_id)
      if (deleteError) throw deleteError
      setMessage('File and share record deleted.')
      await loadShares()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not delete the file.')
    } finally {
      setBusy(false)
    }
  }

  return <section className="fileSharingPage">
    <div className="fileShareMetrics">
      <div><span>Total files</span><strong>{metrics.total}</strong></div>
      <div><span>Active links</span><strong>{metrics.active}</strong></div>
      <div><span>Downloads</span><strong>{metrics.downloads}</strong></div>
      <div><span>Expiring in 7 days</span><strong>{metrics.expiring}</strong></div>
    </div>

    <div className="fileShareGrid">
      <div className="fileSharePanel">
        <div className="fileSharePanelTitle">
          <div><strong>Upload & share</strong><span>Data Centre OneDrive → Smart Console App Packages → Shared Files</span></div>
        </div>
        <div className="fileShareForm">
          <label>File</label>
          <input id="fileShareInput" type="file" disabled={busy} onChange={event => setFile(event.target.files?.[0] || null)} />
          {file && <div className="selectedFile"><strong>{file.name}</strong><span>{formatBytes(file.size)}</span></div>}

          <div className="fileShareTwoCol">
            <div>
              <label>Who can access?</label>
              <select value={scope} onChange={event => setScope(event.target.value as ShareScope)} disabled={busy}>
                <option value="organization">CRECCOM users</option>
                <option value="public">Anyone with the link</option>
                <option value="specific">Specific people</option>
              </select>
            </div>
            <div>
              <label>Link expiry</label>
              <select value={expiryPreset} onChange={event => setExpiryPreset(event.target.value as ExpiryPreset)} disabled={busy}>
                <option value="never">Never</option>
                <option value="1d">1 day</option>
                <option value="7d">7 days</option>
                <option value="30d">30 days</option>
                <option value="custom">Custom</option>
              </select>
            </div>
          </div>

          {scope === 'specific' && <>
            <label>Allowed email addresses</label>
            <textarea value={emails} onChange={event => setEmails(event.target.value)} placeholder="name@creccommw.org, partner@example.org" rows={3} disabled={busy} />
          </>}

          {expiryPreset === 'custom' && <>
            <label>Custom expiry</label>
            <input type="datetime-local" value={customExpiry} onChange={event => setCustomExpiry(event.target.value)} disabled={busy} />
          </>}

          <label>Download limit <span className="optionalText">optional</span></label>
          <input type="number" min="1" step="1" value={maxDownloads} onChange={event => setMaxDownloads(event.target.value)} placeholder="Unlimited" disabled={busy} />

          <button className="primary fileShareUploadButton" type="button" onClick={() => void upload()} disabled={!file || busy}>
            {busy ? 'Working…' : 'Upload to OneDrive & create link'}
          </button>
          <small className="fileShareHint">Files stay in Microsoft OneDrive. Supabase keeps only share metadata and the download counter.</small>
        </div>
      </div>

      <div className="fileSharePanel fileShareInfoPanel">
        <div className="fileSharePanelTitle"><div><strong>Sharing controls</strong><span>Web-console only — no endpoint agent update</span></div></div>
        <div className="fileShareInfo">
          <div><strong>Public</strong><p>Anyone with the link can open the file when anonymous sharing is allowed by Microsoft 365 policy.</p></div>
          <div><strong>CRECCOM users</strong><p>Microsoft sign-in is required and the link is limited to your organization.</p></div>
          <div><strong>Specific people</strong><p>Only the email addresses you grant in Microsoft 365 can open the underlying file.</p></div>
          <div><strong>Download counter</strong><p>Counts successful passes through the Security Console share link before redirecting to OneDrive.</p></div>
        </div>
      </div>
    </div>

    {(error || message) && <div className={error ? 'fileShareNotice error' : 'fileShareNotice success'}>{error || message}</div>}

    <div className="fileShareToolbar">
      <input value={search} onChange={event => setSearch(event.target.value)} placeholder="Search files or recipients" />
      <button className="secondary" type="button" onClick={() => void loadShares()} disabled={loading}>Refresh</button>
    </div>

    <div className="fileSharePanel">
      <div className="fileSharePanelTitle"><div><strong>Shared files</strong><span>{filtered.length} records</span></div></div>
      <div className="tableWrap">
        <table className="fileShareTable">
          <thead><tr><th>File</th><th>Access</th><th>Downloads</th><th>Expires</th><th>Status</th><th>Actions</th></tr></thead>
          <tbody>
            {loading && shares.length === 0 ? <tr><td colSpan={6} className="empty">Loading shared files…</td></tr> :
              filtered.length === 0 ? <tr><td colSpan={6} className="empty">No shared files yet.</td></tr> :
              filtered.map(item => {
                const status = shareStatus(item)
                return <tr key={item.share_id}>
                  <td><strong>{item.file_name}</strong><small>{formatBytes(item.file_size_bytes)} · Shared {dateTime(item.created_at)}</small></td>
                  <td><span className="scopeBadge">{item.access_scope === 'public' ? 'Public' : item.access_scope === 'organization' ? 'CRECCOM' : 'Specific users'}</span>{item.allowed_emails.length > 0 && <small>{item.allowed_emails.join(', ')}</small>}</td>
                  <td><strong>{item.download_count}</strong>{item.max_downloads ? <small>of {item.max_downloads}</small> : <small>Unlimited</small>}</td>
                  <td>{dateTime(item.expires_at)}{item.last_downloaded_at && <small>Last: {dateTime(item.last_downloaded_at)}</small>}</td>
                  <td><span className={`shareStatus ${status.tone}`}>{status.label}</span></td>
                  <td><div className="fileShareActions">
                    <button type="button" onClick={() => void copyLink(item.share_token)}>Copy link</button>
                    <button type="button" onClick={() => void toggleShare(item)}>{item.is_active ? 'Disable' : 'Enable'}</button>
                    <button className="danger" type="button" onClick={() => void deleteShare(item)} disabled={busy}>Delete</button>
                  </div></td>
                </tr>
              })}
          </tbody>
        </table>
      </div>
    </div>
  </section>
}
