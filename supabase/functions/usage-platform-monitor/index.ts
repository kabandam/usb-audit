import { createClient } from 'npm:@supabase/supabase-js@2.57.4'

const PROJECT_REF = 'pgbipustotixwahmotvu'
const MANAGEMENT_BASE = 'https://api.supabase.com/v1'
const cors = {
  'access-control-allow-origin': 'https://secure.creccommw.org',
  'access-control-allow-headers': 'authorization, x-client-info, apikey, content-type, x-usage-cron-key',
  'access-control-allow-methods': 'POST, OPTIONS',
}
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), {
  status,
  headers: { ...cors, 'content-type': 'application/json; charset=utf-8' },
})

type AdminClient = ReturnType<typeof createClient>

type RequestBody = {
  action?: 'status' | 'connect' | 'disconnect' | 'collect'
  token?: string
  force?: boolean
}

type LogRow = {
  source?: string
  events?: number | string
  observed_bytes?: number | string
}

const asNumber = (value: unknown) => {
  const number = typeof value === 'number' ? value : Number(value)
  return Number.isFinite(number) ? number : 0
}

const extractResultRows = (value: unknown): LogRow[] => {
  if (Array.isArray(value)) return value as LogRow[]
  if (!value || typeof value !== 'object') return []
  const record = value as Record<string, unknown>
  if (Array.isArray(record.result)) return record.result as LogRow[]
  if (Array.isArray(record.data)) return record.data as LogRow[]
  return []
}

const findMetricNumber = (value: unknown, keys: string[]): number | null => {
  if (!value || typeof value !== 'object') return null
  const wanted = new Set(keys.map(key => key.toLowerCase()))
  const queue: unknown[] = [value]
  while (queue.length) {
    const current = queue.shift()
    if (Array.isArray(current)) {
      queue.push(...current)
      continue
    }
    if (!current || typeof current !== 'object') continue
    for (const [key, item] of Object.entries(current as Record<string, unknown>)) {
      if (wanted.has(key.toLowerCase())) {
        const parsed = asNumber(item)
        if (parsed > 0) return parsed
      }
      if (item && typeof item === 'object') queue.push(item)
    }
  }
  return null
}

const validateManagementToken = async (token: string) => {
  const response = await fetch(`${MANAGEMENT_BASE}/projects/${PROJECT_REF}`, {
    headers: { authorization: `Bearer ${token}`, accept: 'application/json' },
  })
  const body = await response.text()
  if (!response.ok) {
    return { ok: false, status: response.status, message: body.slice(0, 500) }
  }
  let project: Record<string, unknown> = {}
  try { project = JSON.parse(body) } catch { /* validation succeeded even if response changes shape */ }
  return { ok: true, project }
}

const getToken = async (admin: AdminClient) => {
  const { data, error } = await admin.rpc('get_supabase_management_token')
  if (error) throw new Error('Could not access the encrypted Management API credential.')
  return typeof data === 'string' && data.trim() ? data.trim() : null
}

const isCronRequest = async (req: Request, admin: AdminClient) => {
  const supplied = req.headers.get('x-usage-cron-key') || ''
  if (!supplied) return false
  const { data, error } = await admin.rpc('get_usage_cron_key')
  return !error && typeof data === 'string' && data.length > 20 && supplied === data
}

const requireConsoleAdmin = async (req: Request, url: string, publishableKey: string, admin: AdminClient) => {
  const authorization = req.headers.get('authorization') || ''
  const token = authorization.replace(/^Bearer\s+/i, '')
  if (!token) return { ok: false as const, response: json({ error: 'Authentication required' }, 401) }

  const userClient = createClient(url, publishableKey, {
    global: { headers: { Authorization: authorization } },
    auth: { persistSession: false, autoRefreshToken: false },
  })
  const { data: { user }, error } = await userClient.auth.getUser(token)
  if (error || !user?.email) return { ok: false as const, response: json({ error: 'Authentication required' }, 401) }

  const { data: consoleUser } = await admin.from('console_users')
    .select('email,access_role,is_active')
    .eq('email', user.email.toLowerCase())
    .maybeSingle()

  if (!consoleUser?.is_active || consoleUser.access_role !== 'admin') {
    return { ok: false as const, response: json({ error: 'Administrator access is required' }, 403) }
  }
  return { ok: true as const, user }
}

const collect = async (admin: AdminClient, managementToken: string, force = false) => {
  const now = new Date()
  const cycleStart = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1))

  const { data: latest } = await admin.from('platform_usage_snapshots')
    .select('captured_at,window_end')
    .order('captured_at', { ascending: false })
    .limit(1)
    .maybeSingle()

  if (!force && latest?.captured_at &&
      now.getTime() - new Date(latest.captured_at).getTime() < 15 * 60 * 1000) {
    return { skipped: true, reason: 'A platform usage sample was collected less than 15 minutes ago.' }
  }

  let start = latest?.window_end ? new Date(latest.window_end) : new Date(now.getTime() - 60 * 60 * 1000)
  if (start < cycleStart) start = cycleStart
  let coverageStatus = 'direct_observed'
  if (now.getTime() - start.getTime() > 24 * 60 * 60 * 1000) {
    start = new Date(now.getTime() - 24 * 60 * 60 * 1000)
    coverageStatus = 'gap_last_24h_only'
  }
  if (start >= now) start = new Date(now.getTime() - 5 * 60 * 1000)

  const startIso = start.toISOString()
  const endIso = now.toISOString()
  const logSql = `select source, count(*) as events,
sum(length(coalesce(event_message,'')) + length(toJSONString(log_attributes))) as observed_bytes
from logs
group by source
order by observed_bytes desc`

  const logsUrl = new URL(`${MANAGEMENT_BASE}/projects/${PROJECT_REF}/analytics/endpoints/logs`)
  logsUrl.searchParams.set('sql', logSql)
  logsUrl.searchParams.set('iso_timestamp_start', startIso)
  logsUrl.searchParams.set('iso_timestamp_end', endIso)

  const [logsResponse, apiCountsResponse, apiRequestCountResponse] = await Promise.all([
    fetch(logsUrl, {
      headers: { authorization: `Bearer ${managementToken}`, accept: 'application/json' },
    }),
    fetch(`${MANAGEMENT_BASE}/projects/${PROJECT_REF}/analytics/endpoints/usage.api-counts?interval=1h`, {
      headers: { authorization: `Bearer ${managementToken}`, accept: 'application/json' },
    }),
    fetch(`${MANAGEMENT_BASE}/projects/${PROJECT_REF}/analytics/endpoints/usage.api-requests-count`, {
      headers: { authorization: `Bearer ${managementToken}`, accept: 'application/json' },
    }),
  ])

  const logsText = await logsResponse.text()
  const apiCountsText = await apiCountsResponse.text()
  const apiRequestCountText = await apiRequestCountResponse.text()

  if (logsResponse.status === 401 || logsResponse.status === 403) {
    throw new Error('The saved Supabase Management API token is no longer authorized.')
  }
  if (!logsResponse.ok) {
    throw new Error(`Supabase logs analytics returned ${logsResponse.status}: ${logsText.slice(0, 300)}`)
  }

  let logsJson: unknown = {}
  let apiCountsJson: unknown = {}
  let apiRequestCountJson: unknown = {}
  try { logsJson = JSON.parse(logsText) } catch { /* handled as empty rows */ }
  try { apiCountsJson = JSON.parse(apiCountsText) } catch { /* optional endpoint */ }
  try { apiRequestCountJson = JSON.parse(apiRequestCountText) } catch { /* optional endpoint */ }

  const rows = extractResultRows(logsJson)
  const breakdown: Record<string, { events: number, bytes: number }> = {}
  let logEvents = 0
  let observedLogBytes = 0
  for (const row of rows) {
    const source = String(row.source || 'unknown').slice(0, 80)
    const events = Math.max(0, Math.round(asNumber(row.events)))
    const bytes = Math.max(0, Math.round(asNumber(row.observed_bytes)))
    breakdown[source] = { events, bytes }
    logEvents += events
    observedLogBytes += bytes
  }

  // The Management logs endpoint may expose ClickHouse scan statistics in response
  // metadata. Use them when available; otherwise observed payload bytes are a lower
  // bound for the collector's log-query scan volume.
  const scanBytes = findMetricNumber(logsJson, [
    'bytes_read', 'bytesread', 'read_bytes', 'bytes_scanned', 'scanned_bytes', 'result_bytes'
  ]) ?? observedLogBytes

  // Store request volume for this exact non-overlapping log window. The documented
  // usage.api-requests-count endpoint has no time-window parameter, so its returned
  // value must not be summed as though it were an hourly delta.
  const directApiRequestCount = breakdown.edge_logs?.events ?? 0
  const managementRequestCount = findMetricNumber(
    apiRequestCountJson, ['count', 'request_count', 'requests', 'total'])

  const managementRaw = {
    apiCountsStatus: apiCountsResponse.status,
    apiRequestCountStatus: apiRequestCountResponse.status,
    windowApiRequestCount: directApiRequestCount,
    managementRequestCount,
    apiCountsAvailable: apiCountsResponse.ok,
    requestCountAvailable: apiRequestCountResponse.ok,
    logAnalyticsStatus: logsResponse.status,
    logQueryStatsDetected: scanBytes !== observedLogBytes,
  }

  const { data: inserted, error: insertError } = await admin.from('platform_usage_snapshots')
    .insert({
      window_start: startIso,
      window_end: endIso,
      api_requests: Math.max(0, Math.round(directApiRequestCount)),
      log_events: logEvents,
      observed_log_ingest_bytes: observedLogBytes,
      log_query_scanned_bytes: Math.max(0, Math.round(scanBytes)),
      exact_egress_bytes: null,
      exact_log_ingest_bytes: null,
      exact_log_query_bytes: null,
      source_breakdown: breakdown,
      management_raw: managementRaw,
      coverage_status: coverageStatus,
      error_message: null,
    })
    .select('snapshot_id,captured_at,window_start,window_end,api_requests,log_events,observed_log_ingest_bytes,log_query_scanned_bytes,coverage_status')
    .single()

  if (insertError) throw new Error(`Could not save platform usage snapshot: ${insertError.message}`)

  // Re-evaluate Free-tier protection after every non-overlapping platform sample.
  // This is one tiny RPC per collection window, not per endpoint heartbeat.
  const { data: restriction, error: restrictionError } = await admin.rpc('evaluate_usage_restrictions')
  if (restrictionError) {
    managementRaw.restrictionEvaluationError = restrictionError.message
  }

  return { skipped: false, snapshot: inserted, sourceBreakdown: breakdown, managementRaw, restriction }
}

Deno.serve(async (req: Request) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: cors })
  if (req.method !== 'POST') return json({ error: 'Method not allowed' }, 405)

  const url = Deno.env.get('SUPABASE_URL') || ''
  const publishableKey = Deno.env.get('SUPABASE_ANON_KEY') || ''
  const serviceKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY') || ''
  if (!url || !publishableKey || !serviceKey) return json({ error: 'Server configuration unavailable' }, 500)

  const admin = createClient(url, serviceKey, {
    auth: { persistSession: false, autoRefreshToken: false },
  })
  const body = await req.json().catch(() => ({})) as RequestBody
  const action = body.action || 'status'

  const cron = action === 'collect' ? await isCronRequest(req, admin) : false
  let actor: Awaited<ReturnType<typeof requireConsoleAdmin>> | null = null
  if (!cron) {
    actor = await requireConsoleAdmin(req, url, publishableKey, admin)
    if (!actor.ok) return actor.response
  }

  try {
    if (action === 'status') {
      const token = await getToken(admin)
      const { data: latest } = await admin.from('platform_usage_snapshots')
        .select('captured_at,window_start,window_end,coverage_status,error_message')
        .order('captured_at', { ascending: false })
        .limit(1)
        .maybeSingle()
      return json({ connected: Boolean(token), latest })
    }

    if (action === 'connect') {
      const token = String(body.token || '').trim()
      if (token.length < 20 || token.length > 500) return json({ error: 'Enter a valid Supabase access token.' }, 400)
      const validation = await validateManagementToken(token)
      if (!validation.ok) {
        return json({ error: 'Supabase rejected this access token.', detail: validation.message }, validation.status === 401 ? 401 : 400)
      }
      const { error } = await admin.rpc('set_supabase_management_token', { p_token: token })
      if (error) return json({ error: 'Could not save the encrypted Management API credential.' }, 500)
      const result = await collect(admin, token, true)
      return json({ ok: true, connected: true, collected: result })
    }

    if (action === 'disconnect') {
      const { error } = await admin.rpc('delete_supabase_management_token')
      if (error) return json({ error: 'Could not disconnect the Management API credential.' }, 500)
      return json({ ok: true, connected: false })
    }

    if (action === 'collect') {
      const token = await getToken(admin)
      if (!token) {
        const { data: restriction, error: restrictionError } = await admin.rpc('evaluate_usage_restrictions')
        return json({
          ok: !restrictionError,
          connected: false,
          skipped: true,
          reason: 'Management API is not connected; database, storage and tracked egress protection was still evaluated.',
          restriction,
          restrictionError: restrictionError?.message || null,
        })
      }
      const result = await collect(admin, token, Boolean(body.force && !cron))
      return json({ ok: true, connected: true, ...result })
    }

    return json({ error: 'Unsupported action' }, 400)
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Platform usage collection failed.'
    await admin.from('platform_usage_snapshots').insert({
      window_start: new Date(Date.now() - 5 * 60 * 1000).toISOString(),
      window_end: new Date().toISOString(),
      coverage_status: 'error',
      error_message: message.slice(0, 1000),
      source_breakdown: {},
      management_raw: {},
    }).catch(() => undefined)
    return json({ error: message }, 500)
  }
})
