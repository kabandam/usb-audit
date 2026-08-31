# CRECCOM Security Console

Responsive Inter-branded central console for USB Audit client terminals.

## Local development

1. Copy `.env.example` to `.env` and set the Supabase URL and publishable key.
2. Run `npm install`.
3. Run `npm run dev`.

The web console reads terminal status, connected USB devices, and audit events from the dedicated `creccom-security` Supabase project. Installed Windows terminals send metadata through the token-authenticated `usb-audit-ingest` Edge Function; the browser never receives terminal bearer tokens or service-role credentials.

Authorized `@creccommw.org` users can create a one-time, 15-minute enrollment code in the console. The Windows client exchanges that code on its first successful heartbeat and stores the returned terminal token locally. Supabase stores hashes only.
