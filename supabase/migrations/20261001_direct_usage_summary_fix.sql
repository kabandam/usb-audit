create or replace function public.get_direct_usage_summary()
returns jsonb
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  caller_email text := lower(coalesce((select auth.jwt())->>'email',''));
  cycle_start timestamptz := date_trunc('month', now());
  latest public.platform_usage_snapshots%rowtype;
  observed_ingest bigint := 0;
  estimated_query bigint := 0;
  direct_egress bigint := 0;
  client_egress bigint := 0;
  api_requests bigint := 0;
  log_events bigint := 0;
begin
  if auth.role() <> 'authenticated' or caller_email = '' or not exists (
    select 1 from public.console_users cu
    where lower(cu.email) = caller_email and cu.is_active = true
  ) then
    raise exception 'Smart Console authorization required' using errcode = '42501';
  end if;

  select * into latest
  from public.platform_usage_snapshots
  order by captured_at desc
  limit 1;

  select
    coalesce(sum(s.observed_log_ingest_bytes),0),
    coalesce(sum(s.log_query_scanned_bytes),0),
    coalesce(max(s.exact_egress_bytes),0),
    coalesce(sum(s.api_requests),0),
    coalesce(sum(s.log_events),0)
  into observed_ingest, estimated_query, direct_egress, api_requests, log_events
  from public.platform_usage_snapshots s
  where s.window_end >= cycle_start;

  select coalesce(sum(d.egress_bytes),0)
  into client_egress
  from public.usage_client_egress_daily d
  where d.usage_day >= (cycle_start at time zone 'utc')::date;

  return jsonb_build_object(
    'connected', exists (
      select 1 from vault.decrypted_secrets
      where name = 'smart_console_supabase_management_token'
        and decrypted_secret is not null
    ),
    'lastCapturedAt', latest.captured_at,
    'windowStart', latest.window_start,
    'windowEnd', latest.window_end,
    'coverageStatus', latest.coverage_status,
    'error', latest.error_message,
    'apiRequestsThisCycle', api_requests,
    'logEventsThisCycle', log_events,
    'observedLogIngestBytesThisCycle', observed_ingest,
    'trackedLogQueryBytesThisCycle', estimated_query,
    'exactEgressBytesThisCycle', nullif(direct_egress,0),
    'measuredSmartConsoleEgressBytesThisCycle', client_egress,
    'sourceBreakdown', coalesce(latest.source_breakdown,'{}'::jsonb),
    'managementAvailable', latest.snapshot_id is not null,
    'note', 'Unified billing egress/log meters are used when Supabase exposes them through supported APIs. Otherwise the monitor shows direct API/log observations and measured Smart Console payload egress.'
  );
end;
$$;

revoke all on function public.get_direct_usage_summary() from public, anon;
grant execute on function public.get_direct_usage_summary() to authenticated;