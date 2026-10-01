-- Free-tier resource guard and monitor
create table if not exists public.resource_guard_config (
  id smallint primary key default 1 check (id = 1),
  mode text not null default 'balanced' check (mode in ('balanced','conserve','critical')),
  network_enabled boolean not null default true,
  location_enabled boolean not null default true,
  heartbeat_seconds integer not null default 120 check (heartbeat_seconds between 60 and 300),
  inventory_probe_minutes integer not null default 15 check (inventory_probe_minutes between 5 and 1440),
  inventory_resend_hours integer not null default 12 check (inventory_resend_hours between 1 and 72),
  network_probe_minutes integer not null default 15 check (network_probe_minutes between 5 and 1440),
  network_resend_minutes integer not null default 120 check (network_resend_minutes between 15 and 1440),
  device_resend_minutes integer not null default 120 check (device_resend_minutes between 15 and 1440),
  location_resend_minutes integer not null default 120 check (location_resend_minutes between 15 and 1440),
  update_status_resend_minutes integer not null default 120 check (update_status_resend_minutes between 15 and 1440),
  updated_at timestamptz not null default now(),
  updated_by uuid null
);

insert into public.resource_guard_config (id)
values (1)
on conflict (id) do nothing;

alter table public.resource_guard_config enable row level security;

drop policy if exists resource_guard_read_console on public.resource_guard_config;
create policy resource_guard_read_console
on public.resource_guard_config
for select
to authenticated
using (
  exists (
    select 1
    from public.console_users cu
    where lower(cu.email) = lower(coalesce(auth.jwt()->>'email',''))
      and cu.is_active = true
  )
);

revoke all on public.resource_guard_config from anon;
grant select on public.resource_guard_config to authenticated;

create or replace function public.get_free_tier_monitor()
returns jsonb
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  caller_email text := lower(coalesce(auth.jwt()->>'email',''));
  cycle_start timestamptz := date_trunc('month', now());
  cycle_end timestamptz := date_trunc('month', now()) + interval '1 month';
  cfg public.resource_guard_config%rowtype;
  database_bytes bigint := 0;
  storage_bytes bigint := 0;
  monthly_active_users bigint := 0;
  active_terminals bigint := 0;
  online_terminals bigint := 0;
  audit_events_cycle bigint := 0;
  commands_cycle bigint := 0;
  network_changes_cycle bigint := 0;
  software_rows bigint := 0;
  top_tables jsonb := '[]'::jsonb;
  heartbeat_projection bigint := 0;
  network_projection bigint := 0;
begin
  if caller_email = '' or not exists (
    select 1 from public.console_users cu
    where lower(cu.email) = caller_email and cu.is_active = true
  ) then
    raise exception 'Smart Console authorization required' using errcode = '42501';
  end if;

  select * into cfg
  from public.resource_guard_config
  where id = 1;

  select pg_database_size(current_database())::bigint
    into database_bytes;

  select coalesce(sum(coalesce(nullif(o.metadata->>'size','')::bigint, 0)), 0)::bigint
    into storage_bytes
  from storage.objects o;

  select count(*)::bigint
    into monthly_active_users
  from auth.users u
  where u.last_sign_in_at >= cycle_start
    and u.last_sign_in_at < cycle_end;

  select count(*)::bigint
    into active_terminals
  from public.terminals t
  where t.enrollment_status = 'active';

  select count(*)::bigint
    into online_terminals
  from public.terminals t
  where t.enrollment_status = 'active'
    and t.last_seen_at >= now() - interval '10 minutes';

  select count(*)::bigint
    into audit_events_cycle
  from public.audit_events e
  where e.timestamp >= cycle_start and e.timestamp < cycle_end;

  select count(*)::bigint
    into commands_cycle
  from public.endpoint_commands c
  where c.requested_at >= cycle_start and c.requested_at < cycle_end;

  select count(*)::bigint
    into network_changes_cycle
  from public.endpoint_network_history h
  where h.observed_at >= cycle_start and h.observed_at < cycle_end;

  select count(*)::bigint
    into software_rows
  from public.installed_software;

  select coalesce(jsonb_agg(item order by (item->>'bytes')::bigint desc), '[]'::jsonb)
    into top_tables
  from (
    select jsonb_build_object(
      'table', c.relname,
      'bytes', pg_total_relation_size(c.oid)::bigint,
      'estimatedRows', greatest(c.reltuples::bigint, 0)
    ) as item
    from pg_class c
    join pg_namespace n on n.oid = c.relnamespace
    where n.nspname = 'public' and c.relkind = 'r'
    order by pg_total_relation_size(c.oid) desc
    limit 8
  ) sized;

  heartbeat_projection :=
    active_terminals * ceil((30::numeric * 86400) / greatest(cfg.heartbeat_seconds, 1))::bigint;

  network_projection :=
    case when cfg.network_enabled
      then active_terminals * ceil((30::numeric * 24 * 60) / greatest(cfg.network_resend_minutes, 1))::bigint
      else 0
    end;

  return jsonb_build_object(
    'generatedAt', now(),
    'cycleStart', cycle_start,
    'cycleEnd', cycle_end,
    'limits', jsonb_build_object(
      'egressBytes', 5::bigint * 1024 * 1024 * 1024,
      'databaseBytes', 500::bigint * 1024 * 1024,
      'monthlyActiveUsers', 50000,
      'fileStorageBytes', 1::bigint * 1024 * 1024 * 1024,
      'logIngestionBytes', 1::bigint * 1024 * 1024 * 1024,
      'logQueryBytes', 100::bigint * 1024 * 1024 * 1024
    ),
    'measured', jsonb_build_object(
      'databaseBytes', database_bytes,
      'fileStorageBytes', storage_bytes,
      'monthlyActiveUsers', monthly_active_users
    ),
    'traffic', jsonb_build_object(
      'activeTerminals', active_terminals,
      'onlineTerminals', online_terminals,
      'auditEventsThisCycle', audit_events_cycle,
      'commandsThisCycle', commands_cycle,
      'networkChangesThisCycle', network_changes_cycle,
      'softwareRows', software_rows,
      'projectedHeartbeatRequests30d', heartbeat_projection,
      'projectedNetworkReports30d', network_projection
    ),
    'guard', to_jsonb(cfg),
    'topTables', top_tables,
    'platformMetered', jsonb_build_object(
      'egressExactInConsole', false,
      'logIngestionExactInConsole', false,
      'logQueryExactInConsole', false,
      'note', 'Exact egress and log metering remain on the Supabase billing meter; Smart Console controls and projects the traffic that drives them.'
    )
  );
end;
$$;

revoke all on function public.get_free_tier_monitor() from public;
grant execute on function public.get_free_tier_monitor() to authenticated;
