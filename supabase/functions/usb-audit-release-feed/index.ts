const REPO = 'kabandam/usb-audit'
const PROJECT_URL = 'https://pgbipustotixwahmotvu.supabase.co'

Deno.serve(async (req: Request) => {
  if (req.method !== 'GET') return new Response('Method not allowed', { status: 405 })

  try {
    const response = await fetch('https://api.github.com/repos/' + REPO + '/releases/latest', {
      headers: {
        accept: 'application/vnd.github+json',
        'user-agent': 'CRECCOM-UsbAudit-ReleaseFeed',
      },
    })
    if (!response.ok) {
      return Response.json({ error: 'Release source unavailable' }, { status: 503 })
    }

    const release = await response.json()
    const tag = String(release.tag_name || '')
    const asset = (release.assets || []).find((item: any) => item.name === 'UsbAudit-win-x64.zip')
    const sha256 = String(asset?.digest || '').replace(/^sha256:/i, '').trim().toLowerCase()

    if (!/^v\d+\.\d+\.\d+$/.test(tag) || !asset?.size || !/^[0-9a-f]{64}$/.test(sha256)) {
      return Response.json({ error: 'Latest managed release is incomplete' }, { status: 503 })
    }

    return Response.json({
      version: tag.slice(1),
      tag,
      packageUrl: PROJECT_URL + '/functions/v1/usb-audit-release-proxy?tag=' + encodeURIComponent(tag),
      size: Number(asset.size),
      sha256,
      releaseUrl: String(release.html_url || ''),
      publishedAt: String(release.published_at || ''),
      source: 'CRECCOM managed update feed',
    }, {
      headers: { 'cache-control': 'public, max-age=60' },
    })
  } catch {
    return Response.json({ error: 'Managed release feed unavailable' }, { status: 503 })
  }
})
