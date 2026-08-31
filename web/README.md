# USB Audit Web Console

Responsive Inter-branded central console for USB Audit client terminals.

## Local development

1. Copy `.env.example` to `.env` and set the Supabase URL and publishable key.
2. Run `npm install`.
3. Run `npm run dev`.

The web console reads terminal status, connected USB devices, and audit events from Supabase. Installed Windows terminals send metadata through the authenticated `usb-audit-ingest` Edge Function; the browser never receives terminal enrollment tokens or service-role credentials.
