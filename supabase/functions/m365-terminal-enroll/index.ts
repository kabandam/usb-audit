import { createClient } from 'npm:@supabase/supabase-js@2.57.4'
import { createRemoteJWKSet, jwtVerify } from 'npm:jose@5.9.6'

const TENANT_ID = '4d9d354c-4cb5-48d5-93ba-ea4db8c5206e'
const CLIENT_ID = 'f06469cb-12ab-467c-a2d1-58f2c7750f29'
const ISSUER = 'https://login.microsoftonline.com/' + TENANT_ID + '/v2.0'
const JWKS = createRemoteJWKSet(new URL('https://login.microsoftonline.com/' + TENANT_ID + '/discovery/v2.0/keys'))

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), {
  status,
  headers: { 'content-type': 'application/json; charset=utf-8' },
})

const sha256 = async (value: string) => {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value))
  return Array.from(new Uint8Array(digest)).map(byte => byte.toString(16).padStart(2, '0')).join('')
}

const randomTerminalToken = () => {
  const bytes = crypto.getRandomValues(new Uint8Array(32))
  return 'csc_' + Array.from(bytes).map(byte => byte.toString(16).padStart(2, '0')).join('')
}

Deno.serve(async (req: Request) => {
  if (req.method !== 'POST') return json({ error: 'Method not allowed' }, 405)

  const body = await req.json().catch(() => ({})) as {
    terminalId?: string
    computerName?: string
    windowsUser?: string
    appVersion?: string
    idToken?: string
  }

  const terminalId = (body.terminalId || '').trim().slice(0, 180)
  const idToken = (body.idToken || '').trim()
  if (!terminalId || !idToken) return json({ error: 'Terminal identity and Microsoft identity are required' }, 400)
  if (idToken.length > 20000) return json({ error: 'Microsoft identity token is invalid' }, 400)

  let payload: Record<string, unknown>
  try {
    const verified = await jwtVerify(idToken, JWKS, {
      issuer: ISSUER,
      audience: CLIENT_ID,
    })
    payload = verified.payload as Record<string, unknown>
  } catch {
    return json({ error: 'Microsoft identity could not be verified' }, 401)
  }

  const tid = String(payload.tid || '').toLowerCase()
  const account = String(payload.preferred_username || payload.email || payload.upn || '').trim().toLowerCase()
  if (tid !== TENANT_ID) return json({ error: 'Microsoft account is not from the CRECCOM tenant' }, 403)
  if (!account.endsWith('@creccommw.org')) return json({ error: 'Only CRECCOM Microsoft 365 accounts can enroll endpoints' }, 403)

  const url = Deno.env.get('SUPABASE_URL') || ''
  const serviceKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY') || ''
  if (!url || !serviceKey) return json({ error: 'Server configuration unavailable' }, 500)

  const admin = createClient(url, serviceKey, { auth: { persistSession: false, autoRefreshToken: false } })
  const terminalToken = randomTerminalToken()

  const { data, error } = await admin.rpc('auto_enroll_terminal_m365', {
    p_terminal_id: terminalId,
    p_computer_name: (body.computerName || terminalId).trim().slice(0, 160),
    p_windows_user: (body.windowsUser || '').trim().slice(0, 160),
    p_app_version: (body.appVersion || '').trim().slice(0, 40),
    p_m365_account: account,
    p_m365_tenant_id: TENANT_ID,
    p_token_hash: await sha256(terminalToken),
    p_token_prefix: terminalToken.slice(0, 12),
  })

  if (error || data !== true) return json({ error: 'Automatic endpoint enrollment failed' }, 500)

  return json({
    ok: true,
    terminalToken,
    account,
    ingestUrl: url + '/functions/v1/usb-audit-ingest',
    webConsoleUrl: 'https://secure.creccommw.org',
  })
})
