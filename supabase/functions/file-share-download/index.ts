import { createClient } from 'npm:@supabase/supabase-js@2.57.4'

const getSecretKey = () => {
  const modern = Deno.env.get('SUPABASE_SECRET_KEYS')
  if (modern) {
    try {
      const keys = JSON.parse(modern)
      if (keys?.default) return String(keys.default)
    } catch {
      // Fall back to the legacy key while the project is transitioning.
    }
  }
  return Deno.env.get('SUPABASE_SERVICE_ROLE_KEY') || ''
}

const escapeHtml = (value: string) => value
  .replaceAll('&', '&amp;')
  .replaceAll('<', '&lt;')
  .replaceAll('>', '&gt;')
  .replaceAll('"', '&quot;')
  .replaceAll("'", '&#039;')

const unavailable = (status: string, fileName: string | null, httpStatus = 410) => {
  const title = status === 'not_found'
    ? 'Share link not found'
    : status === 'expired'
      ? 'This share link has expired'
      : status === 'limit_reached'
        ? 'Download limit reached'
        : status === 'disabled'
          ? 'This share link has been disabled'
          : 'This file is not available'

  const detail = fileName ? `The share for <strong>${escapeHtml(fileName)}</strong> is no longer available.` : 'Check the link and try again.'

  return new Response(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>${escapeHtml(title)}</title>
  <style>
    body{margin:0;min-height:100vh;display:grid;place-items:center;background:#f5f7fa;color:#101828;font-family:Inter,system-ui,sans-serif;padding:20px}
    .card{width:min(440px,100%);background:#fff;border:1px solid #eaecf0;border-radius:12px;padding:28px;box-shadow:0 8px 30px rgba(16,24,40,.06)}
    h1{font-size:22px;margin:0 0 10px}p{color:#667085;line-height:1.55;margin:0 0 18px}a{color:#175cd3;text-decoration:none;font-weight:600}
  </style>
</head>
<body><main class="card"><h1>${escapeHtml(title)}</h1><p>${detail}</p><a href="https://secure.creccommw.org">CRECCOM Smart Console</a></main></body>
</html>`, {
    status: httpStatus,
    headers: {
      'content-type': 'text/html; charset=utf-8',
      'cache-control': 'no-store',
      'x-content-type-options': 'nosniff',
      'referrer-policy': 'no-referrer',
    },
  })
}

Deno.serve(async (req: Request) => {
  if (req.method !== 'GET') {
    return new Response('Method not allowed', { status: 405, headers: { allow: 'GET' } })
  }

  const token = new URL(req.url).searchParams.get('token')?.trim().toLowerCase() || ''
  if (!/^[a-f0-9]{36}$/.test(token)) return unavailable('not_found', null, 404)

  const projectUrl = Deno.env.get('SUPABASE_URL') || ''
  const secretKey = getSecretKey()
  if (!projectUrl || !secretKey) return unavailable('unavailable', null, 503)

  const admin = createClient(projectUrl, secretKey, {
    auth: { persistSession: false, autoRefreshToken: false },
  })

  const { data, error } = await admin.rpc('consume_file_share', { p_share_token: token }).maybeSingle()

  if (error) {
    console.error('file-share-download:', error.message)
    return unavailable('unavailable', null, 503)
  }

  if (!data || data.status !== 'ok' || !data.redirect_url) {
    return unavailable(data?.status || 'not_found', data?.resolved_file_name || null, data?.status === 'not_found' ? 404 : 410)
  }

  return new Response(null, {
    status: 302,
    headers: {
      location: data.redirect_url,
      'cache-control': 'no-store',
      'referrer-policy': 'no-referrer',
      'x-content-type-options': 'nosniff',
    },
  })
})
