-- Daily billing-cycle usage history for the Usage Monitor.
create or replace function public.get_daily_usage_history()
returns jsonb
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  caller_email text := lower(coalesce((select auth.jwt())->>'email',''));
  cycle_start date := date_trunc('month', now() at time zone 'utc')::date;
  cycle_end date := (date_trunc('month', now() at time zone 'utc') + interval '1 month')::date;
  today_utc date := (now() at time zone 'utc')::date;
  result jsonb;
begin
  if auth.role() <> 'authenticated' or caller_email = '' or not exists (
    select 1
    from public.console_users cu
    where lower(cu.email) = caller_email
      and cu.is_active = true
  ) then
    raise exception 'Smart Console authorization required' using errcode = '42501';
  end if;

  with days as (
    select generate_series(
      cycle_start::timestamp,
      least(today_utc, cycle_end - 1)::timestamp,
      interval '1 day'
    )::date as usage_day
  ),
  egress as (
    select
      d.usage_day,
      coalesce(sum(d.egress_bytes), 0)::bigint as egress_bytes,
      coalesce(sum(d.egress_bytes) filter (where d.client_type = 'web'), 0)::bigint as web_egress_bytes,
      coalesce(sum(d.egress_bytes) filter (where d.client_type = 'agent'), 0)::bigint as agent_egress_bytes,
      coalesce(sum(d.reports), 0)::bigint as egress_reports
    from public.usage_client_egress_daily d
    where d.usage_day >= cycle_start
      and d.usage_day < cycle_end
    group by d.usage_day
  ),
  platform as (
    select
      (s.window_end at time zone 'utc')::date as usage_day,
      coalesce(sum(s.observed_log_ingest_bytes), 0)::bigint as log_ingest_bytes,
      coalesce(sum(s.log_query_scanned_bytes), 0)::bigint as log_query_bytes,
      coalesce(sum(s.api_requests), 0)::bigint as api_requests,
      coalesce(sum(s.log_events), 0)::bigint as log_events,
      count(*)::bigint as samples,
      bool_or(s.coverage_status in ('direct_observed','connector_bootstrap')) as has_direct_coverage
    from public.platform_usage_snapshots s
    where s.window_end >= cycle_start::timestamptz
      and s.window_end < cycle_end::timestamptz
    group by (s.window_end at time zone 'utc')::date
  ),
  combined as (
    select
      days.usage_day,
      coalesce(e.egress_bytes, 0)::bigint as egress_bytes,
      coalesce(e.web_egress_bytes, 0)::bigint as web_egress_bytes,
      coalesce(e.agent_egress_bytes, 0)::bigint as agent_egress_bytes,
      coalesce(e.egress_reports, 0)::bigint as egress_reports,
      coalesce(p.log_ingest_bytes, 0)::bigint as log_ingest_bytes,
      coalesce(p.log_query_bytes, 0)::bigint as log_query_bytes,
      coalesce(p.api_requests, 0)::bigint as api_requests,
      coalesce(p.log_events, 0)::bigint as log_events,
      coalesce(p.samples, 0)::bigint as samples,
      coalesce(p.has_direct_coverage, false) as has_direct_coverage
    from days
    left join egress e on e.usage_day = days.usage_day
    left join platform p on p.usage_day = days.usage_day
    order by days.usage_day
  ),
  cumulative as (
    select
      c.*,
      sum(c.egress_bytes) over (order by c.usage_day)::bigint as cumulative_egress_bytes,
      sum(c.log_ingest_bytes) over (order by c.usage_day)::bigint as cumulative_log_ingest_bytes,
      sum(c.log_query_bytes) over (order by c.usage_day)::bigint as cumulative_log_query_bytes
    from combined c
  )
  select jsonb_build_object(
    'cycleStart', cycle_start,
    'cycleEnd', cycle_end,
    'generatedAt', now(),
    'limits', jsonb_build_object(
      'egressBytes', 5::bigint * 1024 * 1024 * 1024,
      'logIngestionBytes', 1::bigint * 1024 * 1024 * 1024,
      'logQueryBytes', 100::bigint * 1024 * 1024 * 1024
    ),
    'days', coalesce(jsonb_agg(
      jsonb_build_object(
        'day', to_char(c.usage_day, 'YYYY-MM-DD'),
        'egressBytes', c.egress_bytes,
        'webEgressBytes', c.web_egress_bytes,
        'agentEgressBytes', c.agent_egress_bytes,
        'egressReports', c.egress_reports,
        'logIngestBytes', c.log_ingest_bytes,
        'logQueryBytes', c.log_query_bytes,
        'apiRequests', c.api_requests,
        'logEvents', c.log_events,
        'samples', c.samples,
        'hasDirectCoverage', c.has_direct_coverage,
        'cumulativeEgressBytes', c.cumulative_egress_bytes,
        'cumulativeLogIngestBytes', c.cumulative_log_ingest_bytes,
        'cumulativeLogQueryBytes', c.cumulative_log_query_bytes
      )
      order by c.usage_day
    ), '[]'::jsonb)
  )
  into result
  from cumulative c;

  return coalesce(result, jsonb_build_object(
    'cycleStart', cycle_start,
    'cycleEnd', cycle_end,
    'generatedAt', now(),
    'limits', jsonb_build_object(
      'egressBytes', 5::bigint * 1024 * 1024 * 1024,
      'logIngestionBytes', 1::bigint * 1024 * 1024 * 1024,
      'logQueryBytes', 100::bigint * 1024 * 1024 * 1024
    ),
    'days', '[]'::jsonb
  ));
end;
$$;

revoke all on function public.get_daily_usage_history() from public, anon;
grant execute on function public.get_daily_usage_history() to authenticated;
