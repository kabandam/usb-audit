const PROJECT_URL = 'https://pgbipustotixwahmotvu.supabase.co'
const METADATA_URL = PROJECT_URL + '/storage/v1/object/public/usb-audit-releases/latest.json'

Deno.serve(async (req: Request) => {
  if (req.method !== 'GET') return new Response('Method not allowed', { status: 405 })

  const response = await fetch(METADATA_URL, { cache: 'no-store' })
  if (!response.ok) {
    return Response.json({ error: 'Managed release metadata is not available yet.' }, {
      status: 503,
      headers: { 'cache-control': 'no-store' },
    })
  }

  const body = await response.text()
  return new Response(body, {
    status: 200,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store, max-age=0',
    },
  })
})
