const REPO = 'kabandam/usb-audit'
const ASSET = 'UsbAudit-win-x64.zip'

Deno.serve(async (req: Request) => {
  if (req.method !== 'GET') return new Response('Method not allowed', { status: 405 })

  const url = new URL(req.url)
  const tag = (url.searchParams.get('tag') || '').trim()
  if (!/^v\d+\.\d+\.\d+$/.test(tag)) {
    return Response.json({ error: 'Invalid release tag' }, { status: 400 })
  }

  const range = req.headers.get('range')
  if (!range || !/^bytes=\d+-\d+$/.test(range)) {
    return Response.json({ error: 'A bounded byte range is required' }, {
      status: 416,
      headers: { 'accept-ranges': 'bytes' },
    })
  }

  const source = 'https://github.com/' + REPO + '/releases/download/' + tag + '/' + ASSET
  const upstream = await fetch(source, {
    headers: {
      range,
      'user-agent': 'CRECCOM-UsbAudit-UpdateProxy',
    },
    redirect: 'follow',
  })

  if (upstream.status !== 206 || !upstream.body) {
    return Response.json({
      error: 'Release chunk is unavailable',
      upstreamStatus: upstream.status,
    }, { status: 502 })
  }

  const headers = new Headers()
  headers.set('content-type', 'application/zip')
  headers.set('accept-ranges', 'bytes')
  headers.set('cache-control', 'public, max-age=3600, immutable')
  const contentLength = upstream.headers.get('content-length')
  const contentRange = upstream.headers.get('content-range')
  if (contentLength) headers.set('content-length', contentLength)
  if (contentRange) headers.set('content-range', contentRange)

  return new Response(upstream.body, { status: 206, headers })
})
