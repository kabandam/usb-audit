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

  // Buffer each bounded chunk before returning it. The Windows updater requests
  // 8 MiB ranges; buffering decouples slow endpoint connections from GitHub's
  // upstream stream so a mobile/Wi-Fi stall does not leave the updater hanging
  // on an open proxied response indefinitely.
  const body = new Uint8Array(await upstream.arrayBuffer())
  if (body.byteLength === 0) {
    return Response.json({ error: 'Release chunk was empty' }, { status: 502 })
  }

  const headers = new Headers()
  headers.set('content-type', 'application/zip')
  headers.set('accept-ranges', 'bytes')
  headers.set('cache-control', 'public, max-age=3600, immutable')
  const contentRange = upstream.headers.get('content-range')
  headers.set('content-length', String(body.byteLength))
  if (contentRange) headers.set('content-range', contentRange)

  return new Response(body, { status: 206, headers })
})
