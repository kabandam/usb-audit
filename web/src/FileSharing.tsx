import { useCallback, useEffect, useMemo, useState } from 'react'
import type { Session } from '@supabase/supabase-js'
import { supabase } from './lib/supabase'
import './file-sharing.css'

const GRAPH_TOKEN_KEY = 'smart-console:graph-provider-token'
const GRAPH_TOKEN_EXPIRES_KEY = 'smart-console:graph-provider-token-expires'
const DATA_CENTRE_DRIVE_ID = 'b!l4Wat0zMtkGXeibrIQS1DJ9lhL-UKuhPvT-7il85MzyA3mCd8GVwTZ1O0u25u4_s'
const DATA_CENTRE_PARENT_FOLDER_ID = '01AIJXTSLSPMBUPZP2OFDKZ7FJXJSCOA6U'
const FILE_SHARE_FOLDER = 'Shared Files'
const GRAPH_UPLOAD_CHUNK_BYTES = 180 * 320 * 1024
const GRAPH_SIMPLE_UPLOAD_BYTES = 4 * 1024 * 1024
const PRODUCTION_SUPABASE_URL = 'https://pgbipustotixwahmotvu.supabase.co'
const ZIP64_END_BYTES = 98

type ShareScope = 'public' | 'organization' | 'specific'
type ExpiryPreset = 'never' | '1d' | '7d' | '30d' | 'custom'
type SourceMode = 'file' | 'folder'

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

type UploadProgress = {
  active: boolean
  phase: string
  percent: number
  uploadedBytes: number
  totalBytes: number
  speedBytesPerSecond: number
  etaSeconds: number | null
}

type ZipEntry = {
  file: File
  name: string
  nameBytes: Uint8Array
  dosTime: number
  dosDate: number
  localOffset: number
  crc32: number
}

type PreparedFolderZip = {
  fileName: string
  totalBytes: number
  sourceBytes: number
  fileCount: number
  stream: ReadableStream<Uint8Array>
}

type UploadResult = {
  id: string
  webUrl?: string
  parentReference?: { driveId?: string }
}

const EMPTY_PROGRESS: UploadProgress = {
  active: false,
  phase: '',
  percent: 0,
  uploadedBytes: 0,
  totalBytes: 0,
  speedBytesPerSecond: 0,
  etaSeconds: null,
}

const formatBytes = (value?: number | null) => {
  if (!value) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  let size = value
  let unit = 0
  while (size >= 1024 && unit < units.length - 1) { size /= 1024; unit += 1 }
  return (size >= 100 || unit === 0 ? Math.round(size) : size.toFixed(1)) + ' ' + units[unit]
}

const formatEta = (seconds?: number | null) => {
  if (seconds === null || seconds === undefined || !Number.isFinite(seconds) || seconds < 0) return 'Calculating…'
  if (seconds < 60) return Math.max(1, Math.ceil(seconds)) + ' sec remaining'
  const minutes = Math.ceil(seconds / 60)
  if (minutes < 60) return minutes + ' min remaining'
  const hours = Math.floor(minutes / 60)
  const rest = minutes % 60
  return hours + ' hr' + (hours === 1 ? '' : 's') + (rest ? ' ' + rest + ' min' : '') + ' remaining'
}

const dateTime = (value?: string | null) => value ? new Date(value).toLocaleString() : 'Never'
const cleanFileName = (name: string) => name.replace(/[\\/:*?"<>|#%]/g, '_').replace(/\s+/g, ' ').trim() || 'file'
const shareLink = (token: string) => window.location.origin + '/share/' + token
const delay = (ms: number) => new Promise(resolve => window.setTimeout(resolve, ms))

const providerToken = (session: Session) => {
  const token = session.provider_token || sessionStorage.getItem(GRAPH_TOKEN_KEY) || ''
  const expires = Number(sessionStorage.getItem(GRAPH_TOKEN_EXPIRES_KEY) || '0')
  if (expires && Date.now() >= expires - 60_000) return ''
  return token
}

const graphRequest = async (token: string, path: string, init: RequestInit = {}) => {
  const response = await fetch('https://graph.microsoft.com/v1.0' + path, {
    ...init,
    headers: {
      authorization: 'Bearer ' + token,
      ...(init.body && !(init.body instanceof Blob) ? { 'content-type': 'application/json' } : {}),
      ...(init.headers || {}),
    },
  })

  if (!response.ok) {
    const raw = await response.text()
    let message = 'Microsoft Graph returned ' + response.status
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
    'https://graph.microsoft.com/v1.0/drives/' + driveId + '/items/' + parentId + ':/' + encoded,
    { headers: { authorization: 'Bearer ' + token } },
  )

  if (existing.ok) return existing.json()
  if (existing.status !== 404) {
    const raw = await existing.text()
    throw new Error(raw || 'Could not open the Data Centre OneDrive share folder (' + existing.status + ').')
  }

  return graphRequest(token, '/drives/' + driveId + '/items/' + parentId + '/children', {
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

const crcTable = (() => {
  const table = new Uint32Array(256)
  for (let n = 0; n < 256; n += 1) {
    let c = n
    for (let k = 0; k < 8; k += 1) c = (c & 1) ? 0xedb88320 ^ (c >>> 1) : c >>> 1
    table[n] = c >>> 0
  }
  return table
})()

const crc32Update = (crc: number, bytes: Uint8Array) => {
  let value = crc >>> 0
  for (let index = 0; index < bytes.length; index += 1) {
    value = crcTable[(value ^ bytes[index]) & 0xff] ^ (value >>> 8)
  }
  return value >>> 0
}

const setU64 = (view: DataView, offset: number, value: number) => {
  view.setBigUint64(offset, BigInt(Math.trunc(value)), true)
}

const dosDateTime = (timestamp: number) => {
  const date = new Date(timestamp || Date.now())
  const year = Math.min(2107, Math.max(1980, date.getFullYear()))
  const dosTime = (date.getHours() << 11) | (date.getMinutes() << 5) | Math.floor(date.getSeconds() / 2)
  const dosDate = ((year - 1980) << 9) | ((date.getMonth() + 1) << 5) | date.getDate()
  return { dosTime, dosDate }
}

const safeZipPath = (file: File) => {
  const relative = ((file as File & { webkitRelativePath?: string }).webkitRelativePath || file.name)
    .replace(/\\/g, '/')
    .replace(/^\/+/, '')
  const parts = relative.split('/').filter(part => part && part !== '.' && part !== '..')
  return parts.join('/') || cleanFileName(file.name)
}

const localHeader = (entry: ZipEntry) => {
  const bytes = new Uint8Array(50 + entry.nameBytes.length)
  const view = new DataView(bytes.buffer)
  view.setUint32(0, 0x04034b50, true)
  view.setUint16(4, 45, true)
  view.setUint16(6, 0x0808, true)
  view.setUint16(8, 0, true)
  view.setUint16(10, entry.dosTime, true)
  view.setUint16(12, entry.dosDate, true)
  view.setUint32(14, 0, true)
  view.setUint32(18, 0xffffffff, true)
  view.setUint32(22, 0xffffffff, true)
  view.setUint16(26, entry.nameBytes.length, true)
  view.setUint16(28, 20, true)
  bytes.set(entry.nameBytes, 30)
  const extra = 30 + entry.nameBytes.length
  view.setUint16(extra, 0x0001, true)
  view.setUint16(extra + 2, 16, true)
  setU64(view, extra + 4, entry.file.size)
  setU64(view, extra + 12, entry.file.size)
  return bytes
}

const dataDescriptor = (entry: ZipEntry) => {
  const bytes = new Uint8Array(24)
  const view = new DataView(bytes.buffer)
  view.setUint32(0, 0x08074b50, true)
  view.setUint32(4, entry.crc32 >>> 0, true)
  setU64(view, 8, entry.file.size)
  setU64(view, 16, entry.file.size)
  return bytes
}

const centralHeader = (entry: ZipEntry) => {
  const bytes = new Uint8Array(74 + entry.nameBytes.length)
  const view = new DataView(bytes.buffer)
  view.setUint32(0, 0x02014b50, true)
  view.setUint16(4, 45, true)
  view.setUint16(6, 45, true)
  view.setUint16(8, 0x0808, true)
  view.setUint16(10, 0, true)
  view.setUint16(12, entry.dosTime, true)
  view.setUint16(14, entry.dosDate, true)
  view.setUint32(16, entry.crc32 >>> 0, true)
  view.setUint32(20, 0xffffffff, true)
  view.setUint32(24, 0xffffffff, true)
  view.setUint16(28, entry.nameBytes.length, true)
  view.setUint16(30, 28, true)
  view.setUint16(32, 0, true)
  view.setUint16(34, 0, true)
  view.setUint16(36, 0, true)
  view.setUint32(38, 0, true)
  view.setUint32(42, 0xffffffff, true)
  bytes.set(entry.nameBytes, 46)
  const extra = 46 + entry.nameBytes.length
  view.setUint16(extra, 0x0001, true)
  view.setUint16(extra + 2, 24, true)
  setU64(view, extra + 4, entry.file.size)
  setU64(view, extra + 12, entry.file.size)
  setU64(view, extra + 20, entry.localOffset)
  return bytes
}

const zip64Tail = (entries: ZipEntry[], centralOffset: number, centralSize: number) => {
  const bytes = new Uint8Array(ZIP64_END_BYTES)
  const view = new DataView(bytes.buffer)
  const zip64EocdOffset = centralOffset + centralSize
  view.setUint32(0, 0x06064b50, true)
  setU64(view, 4, 44)
  view.setUint16(12, 45, true)
  view.setUint16(14, 45, true)
  view.setUint32(16, 0, true)
  view.setUint32(20, 0, true)
  setU64(view, 24, entries.length)
  setU64(view, 32, entries.length)
  setU64(view, 40, centralSize)
  setU64(view, 48, centralOffset)

  view.setUint32(56, 0x07064b50, true)
  view.setUint32(60, 0, true)
  setU64(view, 64, zip64EocdOffset)
  view.setUint32(72, 1, true)

  view.setUint32(76, 0x06054b50, true)
  view.setUint16(80, 0, true)
  view.setUint16(82, 0, true)
  view.setUint16(84, Math.min(0xffff, entries.length), true)
  view.setUint16(86, Math.min(0xffff, entries.length), true)
  view.setUint32(88, centralSize <= 0xffffffff ? centralSize : 0xffffffff, true)
  view.setUint32(92, centralOffset <= 0xffffffff ? centralOffset : 0xffffffff, true)
  view.setUint16(96, 0, true)
  return bytes
}

const prepareFolderZip = (files: File[]): PreparedFolderZip => {
  if (files.length === 0) throw new Error('Choose a folder first.')
  const encoder = new TextEncoder()
  let localOffset = 0
  let sourceBytes = 0
  const entries: ZipEntry[] = files.map(file => {
    const name = safeZipPath(file)
    const nameBytes = encoder.encode(name)
    if (nameBytes.length > 65535) throw new Error('A folder path is too long to package into ZIP.')
    const date = dosDateTime(file.lastModified)
    const entry: ZipEntry = {
      file,
      name,
      nameBytes,
      dosTime: date.dosTime,
      dosDate: date.dosDate,
      localOffset,
      crc32: 0,
    }
    localOffset += 74 + nameBytes.length + file.size
    sourceBytes += file.size
    return entry
  })

  const centralOffset = localOffset
  const centralSize = entries.reduce((sum, entry) => sum + 74 + entry.nameBytes.length, 0)
  const totalBytes = centralOffset + centralSize + ZIP64_END_BYTES
  const firstPath = safeZipPath(files[0])
  const rootName = firstPath.includes('/') ? firstPath.split('/')[0] : 'Folder'
  const fileName = cleanFileName(rootName || 'Folder') + '.zip'

  async function* generateZip() {
    for (const entry of entries) {
      yield localHeader(entry)
      let crc = 0xffffffff
      const reader = entry.file.stream().getReader()
      try {
        while (true) {
          const result = await reader.read()
          if (result.done) break
          if (!result.value?.length) continue
          crc = crc32Update(crc, result.value)
          yield result.value
        }
      } finally {
        reader.releaseLock()
      }
      entry.crc32 = (crc ^ 0xffffffff) >>> 0
      yield dataDescriptor(entry)
    }

    for (const entry of entries) yield centralHeader(entry)
    yield zip64Tail(entries, centralOffset, centralSize)
  }

  const iterator = generateZip()[Symbol.asyncIterator]()
  const stream = new ReadableStream<Uint8Array>({
    async pull(controller) {
      const next = await iterator.next()
      if (next.done) controller.close()
      else controller.enqueue(next.value)
    },
    async cancel() {
      if (iterator.return) await iterator.return()
    },
  })

  return { fileName, totalBytes, sourceBytes, fileCount: files.length, stream }
}

const parseXhrPayload = (xhr: XMLHttpRequest) => {
  if (!xhr.responseText) return null
  try { return JSON.parse(xhr.responseText) }
  catch { return null }
}

const xhrPut = (
  url: string,
  body: Blob | ArrayBuffer,
  headers: Record<string, string>,
  onProgress: (loaded: number) => void,
) => new Promise<{ status: number, payload: any }>((resolve, reject) => {
  const xhr = new XMLHttpRequest()
  xhr.open('PUT', url, true)
  Object.entries(headers).forEach(([key, value]) => xhr.setRequestHeader(key, value))
  xhr.upload.onprogress = event => onProgress(event.loaded)
  xhr.onerror = () => reject(new Error('Network connection interrupted during upload.'))
  xhr.onabort = () => reject(new Error('Upload was cancelled.'))
  xhr.onload = () => {
    const payload = parseXhrPayload(xhr)
    if ([200, 201, 202].includes(xhr.status)) {
      resolve({ status: xhr.status, payload })
      return
    }
    const graphMessage = payload?.error?.message
    reject(new Error(graphMessage || 'Microsoft 365 upload failed (HTTP ' + xhr.status + ').'))
  }
  xhr.send(body)
})

const uploadChunkWithRetry = async (
  uploadUrl: string,
  body: Blob | ArrayBuffer,
  start: number,
  endExclusive: number,
  totalBytes: number,
  onProgress: (uploadedBytes: number) => void,
) => {
  let lastError: unknown
  for (let attempt = 1; attempt <= 3; attempt += 1) {
    try {
      return await xhrPut(uploadUrl, body, {
        'content-range': 'bytes ' + start + '-' + (endExclusive - 1) + '/' + totalBytes,
      }, loaded => onProgress(start + loaded))
    } catch (error) {
      lastError = error
      onProgress(start)
      if (attempt < 3) await delay(attempt * 900)
    }
  }
  throw lastError instanceof Error ? lastError : new Error('Upload failed after several retry attempts.')
}

const createUploadSession = async (token: string, folderId: string, storageName: string) => {
  const driveId = encodeURIComponent(DATA_CENTRE_DRIVE_ID)
  const itemId = encodeURIComponent(folderId)
  const encodedName = encodeURIComponent(storageName)
  const session = await graphRequest(
    token,
    '/drives/' + driveId + '/items/' + itemId + ':/' + encodedName + ':/createUploadSession',
    {
      method: 'POST',
      body: JSON.stringify({
        item: {
          '@microsoft.graph.conflictBehavior': 'rename',
          name: storageName,
        },
      }),
    },
  )
  if (!session?.uploadUrl) throw new Error('Microsoft 365 returned no resumable upload session.')
  return session.uploadUrl as string
}

const uploadLargeFile = async (
  token: string,
  folderId: string,
  storageName: string,
  file: File,
  onProgress: (uploadedBytes: number, totalBytes: number) => void,
): Promise<UploadResult> => {
  const uploadUrl = await createUploadSession(token, folderId, storageName)
  let finalItem: UploadResult | null = null

  for (let start = 0; start < file.size; start += GRAPH_UPLOAD_CHUNK_BYTES) {
    const endExclusive = Math.min(start + GRAPH_UPLOAD_CHUNK_BYTES, file.size)
    const part = file.slice(start, endExclusive)
    const response = await uploadChunkWithRetry(
      uploadUrl,
      part,
      start,
      endExclusive,
      file.size,
      uploaded => onProgress(uploaded, file.size),
    )
    if (response.status !== 202 && response.payload?.id) finalItem = response.payload as UploadResult
    onProgress(endExclusive, file.size)
  }

  if (!finalItem?.id) throw new Error('Microsoft 365 upload completed without returning the uploaded file.')
  return finalItem
}

const uploadSmallFile = async (
  token: string,
  folderId: string,
  storageName: string,
  file: File,
  onProgress: (uploadedBytes: number, totalBytes: number) => void,
): Promise<UploadResult> => {
  const driveId = encodeURIComponent(DATA_CENTRE_DRIVE_ID)
  const itemId = encodeURIComponent(folderId)
  const encodedName = encodeURIComponent(storageName)
  const url = 'https://graph.microsoft.com/v1.0/drives/' + driveId + '/items/' + itemId + ':/' + encodedName + ':/content'
  const response = await xhrPut(url, file, {
    authorization: 'Bearer ' + token,
    'content-type': file.type || 'application/octet-stream',
  }, loaded => onProgress(loaded, file.size))
  if (!response.payload?.id) throw new Error('Microsoft 365 upload completed without returning the uploaded file.')
  onProgress(file.size, file.size)
  return response.payload as UploadResult
}

const uploadZipStream = async (
  token: string,
  folderId: string,
  storageName: string,
  source: ReadableStream<Uint8Array>,
  totalBytes: number,
  onProgress: (uploadedBytes: number, totalBytes: number) => void,
): Promise<UploadResult> => {
  const uploadUrl = await createUploadSession(token, folderId, storageName)
  const reader = source.getReader()
  let sourceDone = false
  let carry: Uint8Array | null = null
  let carryOffset = 0
  let offset = 0
  const finalItem = { value: null as UploadResult | null }

  // Build the next ZIP chunk while the current chunk is being uploaded.
  // This overlaps disk reads / ZIP metadata work with network transfer and
  // avoids the old stop-start pattern on large folders.
  const readNextChunk = async (): Promise<Uint8Array | null> => {
    if (sourceDone && !carry) return null
    const buffer = new Uint8Array(GRAPH_UPLOAD_CHUNK_BYTES)
    let buffered = 0

    while (buffered < buffer.length) {
      if (carry) {
        const writable = Math.min(buffer.length - buffered, carry.length - carryOffset)
        buffer.set(carry.subarray(carryOffset, carryOffset + writable), buffered)
        buffered += writable
        carryOffset += writable

        if (carryOffset >= carry.length) {
          carry = null
          carryOffset = 0
        }

        if (buffered === buffer.length) break
        continue
      }

      if (sourceDone) break

      const result = await reader.read()
      if (result.done) {
        sourceDone = true
        break
      }

      carry = result.value
      carryOffset = 0
    }

    if (buffered === 0) return null
    return buffered === buffer.length ? buffer : buffer.slice(0, buffered)
  }

  try {
    let currentChunk = await readNextChunk()

    while (currentChunk) {
      // Start packaging the next chunk immediately. It can run while the
      // current Graph PUT is in flight, using at most one extra chunk of RAM.
      const nextChunkPromise = readNextChunk()
      const endExclusive = offset + currentChunk.length
      const response = await uploadChunkWithRetry(
        uploadUrl,
        currentChunk.buffer as ArrayBuffer,
        offset,
        endExclusive,
        totalBytes,
        uploaded => onProgress(uploaded, totalBytes),
      )

      if (response.status !== 202 && response.payload?.id) {
        finalItem.value = response.payload as UploadResult
      }

      offset = endExclusive
      onProgress(offset, totalBytes)
      currentChunk = await nextChunkPromise
    }
  } finally {
    reader.releaseLock()
  }

  if (offset !== totalBytes) {
    throw new Error('ZIP stream size did not match the expected archive size. Upload stopped to prevent a corrupt file.')
  }
  const completedItem = finalItem.value
  if (!completedItem || !completedItem.id) throw new Error('Microsoft 365 upload completed without returning the uploaded ZIP.')
  return completedItem
}

export function PublicShareRedirect({ token }: { token: string }) {
  useEffect(() => {
    const base = (import.meta.env.VITE_SUPABASE_URL as string | undefined) || PRODUCTION_SUPABASE_URL
    window.location.replace(base + '/functions/v1/file-share-download?token=' + encodeURIComponent(token))
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
  const [sourceMode, setSourceMode] = useState<SourceMode>('file')
  const [file, setFile] = useState<File | null>(null)
  const [folderFiles, setFolderFiles] = useState<File[]>([])
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
  const [progress, setProgress] = useState<UploadProgress>(EMPTY_PROGRESS)

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

  const selectedFolderBytes = useMemo(
    () => folderFiles.reduce((sum, item) => sum + item.size, 0),
    [folderFiles],
  )

  const selectedFolderName = useMemo(() => {
    if (folderFiles.length === 0) return ''
    const path = safeZipPath(folderFiles[0])
    return path.includes('/') ? path.split('/')[0] : 'Folder'
  }, [folderFiles])

  const reportFactory = (startedAt: number, phase: string) => {
    let samples: Array<{ at: number, bytes: number }> = []
    let previousBytes = 0

    return (uploadedBytes: number, totalBytes: number) => {
      const now = performance.now()

      // A retry can move the visible position back to the last committed
      // fragment. Reset the rolling window so that does not produce a negative
      // or misleading transfer rate.
      if (uploadedBytes < previousBytes) samples = []
      previousBytes = uploadedBytes

      samples.push({ at: now, bytes: uploadedBytes })
      const cutoff = now - 15_000
      samples = samples.filter(sample => sample.at >= cutoff)

      const first = samples[0]
      const rollingSeconds = first ? Math.max(0.25, (now - first.at) / 1000) : 0
      const rollingBytes = first ? Math.max(0, uploadedBytes - first.bytes) : 0
      let speed = rollingSeconds > 0 ? rollingBytes / rollingSeconds : 0

      // During the first few progress events there may not yet be enough
      // rolling-window data. Use the session average only as a short fallback.
      if (speed <= 0 && uploadedBytes > 0) {
        const elapsedSeconds = Math.max(0.25, (now - startedAt) / 1000)
        speed = uploadedBytes / elapsedSeconds
      }

      const remaining = Math.max(0, totalBytes - uploadedBytes)
      const eta = speed > 0 ? remaining / speed : null

      setProgress({
        active: true,
        phase,
        percent: totalBytes > 0 ? Math.min(100, (uploadedBytes / totalBytes) * 100) : 0,
        uploadedBytes,
        totalBytes,
        speedBytesPerSecond: speed,
        etaSeconds: eta,
      })
    }
  }

  const resetSelection = () => {
    setFile(null)
    setFolderFiles([])
    const fileInput = document.getElementById('fileShareInput') as HTMLInputElement | null
    const folderInput = document.getElementById('folderShareInput') as HTMLInputElement | null
    if (fileInput) fileInput.value = ''
    if (folderInput) folderInput.value = ''
  }

  const upload = async () => {
    if (!supabase || busy) return
    if (sourceMode === 'file' && !file) return
    if (sourceMode === 'folder' && folderFiles.length === 0) return

    setBusy(true)
    setError('')
    setMessage('')
    setProgress(EMPTY_PROGRESS)

    try {
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

      setMessage('Preparing Data Centre OneDrive upload…')
      const folder = await ensureShareFolder(token)
      const stamp = new Date().toISOString().replace(/[-:]/g, '').replace('T', '-').slice(0, 15)
      const startedAt = performance.now()

      let uploaded: UploadResult
      let finalName: string
      let finalSize: number
      let finalMime: string

      if (sourceMode === 'folder') {
        setMessage('Packaging the selected folder as a ZIP and uploading it in resumable chunks…')
        const archive = prepareFolderZip(folderFiles)
        finalName = archive.fileName
        finalSize = archive.totalBytes
        finalMime = 'application/zip'
        const storageName = stamp + '__' + cleanFileName(finalName)
        const report = reportFactory(startedAt, 'Packing folder + uploading ZIP')
        report(0, archive.totalBytes)
        uploaded = await uploadZipStream(token, folder.id, storageName, archive.stream, archive.totalBytes, report)
      } else {
        const selectedFile = file as File
        finalName = selectedFile.name
        finalSize = selectedFile.size
        finalMime = selectedFile.type || 'application/octet-stream'
        const storageName = stamp + '__' + cleanFileName(selectedFile.name)
        const report = reportFactory(startedAt, 'Uploading to Data Centre OneDrive')
        report(0, selectedFile.size)
        setMessage('Uploading to Data Centre OneDrive with resumable transfer…')
        uploaded = selectedFile.size <= GRAPH_SIMPLE_UPLOAD_BYTES
          ? await uploadSmallFile(token, folder.id, storageName, selectedFile, report)
          : await uploadLargeFile(token, folder.id, storageName, selectedFile, report)
      }

      setProgress(previous => ({ ...previous, active: true, phase: 'Creating secure sharing link', percent: 100, uploadedBytes: previous.totalBytes }))
      setMessage('Upload complete. Creating the controlled OneDrive sharing permission…')

      let targetUrl = uploaded.webUrl || ''
      let permissionIds: string[] = []

      if (scope === 'specific') {
        const invitation = await graphRequest(token, '/drives/' + encodeURIComponent(DATA_CENTRE_DRIVE_ID) + '/items/' + encodeURIComponent(uploaded.id) + '/invite', {
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
        const permission = await graphRequest(token, '/drives/' + encodeURIComponent(DATA_CENTRE_DRIVE_ID) + '/items/' + encodeURIComponent(uploaded.id) + '/createLink', {
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

      if (!targetUrl) throw new Error('The file uploaded, but Microsoft 365 did not return a usable sharing URL.')

      const driveInfo = uploaded.parentReference?.driveId || DATA_CENTRE_DRIVE_ID
      const { error: insertError } = await supabase.from('file_shares').insert({
        file_name: finalName,
        file_size_bytes: finalSize,
        mime_type: finalMime,
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

      resetSelection()
      setEmails('')
      setMaxDownloads('')
      setProgress(previous => ({ ...previous, active: false, phase: 'Complete', percent: 100 }))
      setMessage(sourceMode === 'folder' ? 'Folder packaged as ZIP, uploaded and shared successfully.' : 'File uploaded and share link created.')
      await loadShares()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not create the file share.')
      setMessage('')
      setProgress(previous => ({ ...previous, active: false, phase: 'Upload stopped' }))
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
    if (!supabase || !window.confirm('Delete "' + item.file_name + '" from OneDrive and remove its share record?')) return
    setBusy(true)
    setError('')
    try {
      const token = providerToken(session)
      if (!token) throw new Error('Your Microsoft file-access session has expired. Sign out and sign in again before deleting OneDrive files.')
      await graphRequest(token, '/drives/' + encodeURIComponent(item.drive_id || DATA_CENTRE_DRIVE_ID) + '/items/' + encodeURIComponent(item.drive_item_id), { method: 'DELETE' })
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
          <div className="sourceModeSwitch" aria-label="Upload type">
            <button type="button" className={sourceMode === 'file' ? 'active' : ''} disabled={busy} onClick={() => setSourceMode('file')}>Single file</button>
            <button type="button" className={sourceMode === 'folder' ? 'active' : ''} disabled={busy} onClick={() => setSourceMode('folder')}>Folder → ZIP</button>
          </div>

          {sourceMode === 'file' ? <>
            <label>File</label>
            <input id="fileShareInput" type="file" disabled={busy} onChange={event => {
              setFile(event.target.files?.[0] || null)
              setFolderFiles([])
              setError('')
            }} />
            {file && <div className="selectedFile"><strong>{file.name}</strong><span>{formatBytes(file.size)}</span></div>}
          </> : <>
            <label>Folder</label>
            <input
              id="folderShareInput"
              type="file"
              multiple
              disabled={busy}
              {...({ webkitdirectory: '', directory: '' } as any)}
              onChange={event => {
                const selected = Array.from(event.target.files || [])
                setFolderFiles(selected)
                setFile(null)
                setError('')
              }}
            />
            {folderFiles.length > 0 && <div className="selectedFile selectedFolder">
              <div><strong>{selectedFolderName}</strong><small>{folderFiles.length} files · packaged as {cleanFileName(selectedFolderName || 'Folder')}.zip</small></div>
              <span>{formatBytes(selectedFolderBytes)}</span>
            </div>}
          </>}

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

          {progress.totalBytes > 0 && <div className="uploadProgressCard">
            <div className="uploadProgressHeader">
              <div><strong>{progress.phase || 'Uploading'}</strong><span>{formatBytes(progress.uploadedBytes)} / {formatBytes(progress.totalBytes)}</span></div>
              <strong>{Math.round(progress.percent)}%</strong>
            </div>
            <div className="uploadProgressTrack"><div style={{ width: Math.max(0, Math.min(100, progress.percent)) + '%' }} /></div>
            <div className="uploadProgressMeta">
              <span>{progress.speedBytesPerSecond > 0 ? formatBytes(progress.speedBytesPerSecond) + '/s' : 'Starting…'}</span>
              <span>{progress.percent >= 100 ? 'Transfer complete' : formatEta(progress.etaSeconds)}</span>
            </div>
          </div>}

          <button className="primary fileShareUploadButton" type="button" onClick={() => void upload()} disabled={busy || (sourceMode === 'file' ? !file : folderFiles.length === 0)}>
            {busy ? 'Uploading…' : sourceMode === 'folder' ? 'Zip folder & upload to OneDrive' : 'Upload to OneDrive & create link'}
          </button>
          <small className="fileShareHint">
            Large files use resumable Microsoft 365 chunks with automatic retry. Folder uploads are packed into a ZIP stream in the browser, so the full ZIP does not need to be held in memory first.
          </small>
        </div>
      </div>

      <div className="fileSharePanel fileShareInfoPanel">
        <div className="fileSharePanelTitle"><div><strong>Sharing controls</strong><span>Web-console only — no endpoint agent update</span></div></div>
        <div className="fileShareInfo">
          <div><strong>Large files</strong><p>Uploads use larger resumable chunks instead of the previous 250 MB single-request limit.</p></div>
          <div><strong>Folder → ZIP</strong><p>Select a normal folder. The console packages its files into a ZIP64 archive while uploading so very large folders are supported.</p></div>
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
                  <td><span className={'shareStatus ' + status.tone}>{status.label}</span></td>
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
