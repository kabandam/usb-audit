-- Fleet-scale heartbeat consolidation and automatic Free-tier usage restrictions.

-- Allow Resource Guard to stretch heartbeat cadence from minutes to once per day.
alter table public.resource_guard_config
  drop constraint if exists resource_guard_config_heartbeat_seconds_check;
alter table public.resource_guard_config
  add constraint resource_guard_config_heartbeat_seconds_check
  check (heartbeat_seconds between 60 and 86400);

create table if not exists public.usage_restriction_config (
  id smallint primary key default 1 check (id = 1),
  auto_enabled boolean not null default true,
  threshold_restricted numeric(5,2) not null default 50.00 check (threshold_restricted between 10 and 95),
  threshold_severe numeric(5,2) not null default 65.00 check (threshold_severe between 20 and 97),
  threshold_critical numeric(5,2) not null default 80.00 check (threshold_critical between 30 and 99),
  threshold_survival numeric(5,2) not null default 90.00 check (threshold_survival between 40 and 99.9),
  manual_stage text null check (manual_stage is null or manual_stage in ('normal','restricted','severe','critical','survival')),
  current_stage text not null default 'normal' check (current_stage in ('normal','restricted','severe','critical','survival')),
  trigger_metric text,
  trigger_percent numeric(8,3) not null default 0,
  cycle_start date not null default date_trunc('month', now() at time zone 'utc')::date,
  audit_event_upload_enabled boolean not null default true,
  deployment_delivery_enabled boolean not null default true,
  remote_support_delivery_enabled boolean not null default true,
  location_delivery_enabled boolean not null default true,
  last_evaluated_at timestamptz,
  last_stage_change_at timestamptz,
  updated_at timestamptz not null default now(),
  updated_by uuid
);

insert into public.usage_restriction_config(id)
values (1)
on conflict (id) do nothing;

alter table public.usage_restriction_config enable row level security;
drop policy if exists usage_restriction_read_console on public.usage_restriction_config;
create policy usage_restriction_read_console
on public.usage_restriction_config
for select to authenticated
using (
  exists (
    select 1 from public.console_users cu
    where lower(cu.email) = lower(coalesce((select auth.jwt())->>'email',''))
      and cu.is_active = true
  )
);
revoke all on public.usage_restriction_config from anon;
grant select on public.usage_restriction_config to authenticated;

create or replace function public.evaluate_usage_restrictions()
returns jsonb
language plpgsql
security definer
set search_path = public, security, storage, auth, pg_temp
as $$
declare
  cfg public.usage_restriction_config%rowtype;
  cycle_start_utc timestamptz := date_trunc('month', now());
  cycle_date date := date_trunc('month', now() at time zone 'utc')::date;
  egress_bytes bigint := 0;
  log_ingest_bytes bigint := 0;
  log_query_bytes bigint := 0;
  database_bytes bigint := 0;
  storage_bytes bigint := 0;
  mau bigint := 0;
  egress_pct numeric := 0;
  log_ingest_pct numeric := 0;
  log_query_pct numeric := 0;
  database_pct numeric := 0;
  storage_pct numeric := 0;
  mau_pct numeric := 0;
  peak_pct numeric := 0;
  peak_metric text := 'none';
  next_stage text := 'normal';
  previous_stage text;
  stage_changed boolean := false;
begin
  if auth.role() <> 'service_role' then
    raise exception 'Service role required' using errcode = '42501';
  end if;

  select * into cfg from public.usage_restriction_config where id = 1 for update;
  previous_stage := cfg.current_stage;

  select coalesce(sum(d.egress_bytes),0)::bigint into egress_bytes
  from public.usage_client_egress_daily d
  where d.usage_day >= cycle_date;

  select
    coalesce(sum(s.observed_log_ingest_bytes),0)::bigint,
    coalesce(sum(s.log_query_scanned_bytes),0)::bigint
  into log_ingest_bytes, log_query_bytes
  from public.platform_usage_snapshots s
  where s.window_end >= cycle_start_utc;

  select pg_database_size(current_database())::bigint into database_bytes;

  select coalesce(sum(coalesce(nullif(o.metadata->>'size','')::bigint,0)),0)::bigint
  into storage_bytes
  from storage.objects o;

  select count(*)::bigint into mau
  from auth.users u
  where u.last_sign_in_at >= cycle_start_utc
    and u.last_sign_in_at < cycle_start_utc + interval '1 month';

  egress_pct := egress_bytes::numeric / (5::numeric * 1024 * 1024 * 1024) * 100;
  log_ingest_pct := log_ingest_bytes::numeric / (1::numeric * 1024 * 1024 * 1024) * 100;
  log_query_pct := log_query_bytes::numeric / (100::numeric * 1024 * 1024 * 1024) * 100;
  database_pct := database_bytes::numeric / (500::numeric * 1024 * 1024) * 100;
  storage_pct := storage_bytes::numeric / (1::numeric * 1024 * 1024 * 1024) * 100;
  mau_pct := mau::numeric / 50000::numeric * 100;

  peak_pct := greatest(egress_pct, log_ingest_pct, log_query_pct, database_pct, storage_pct, mau_pct);
  peak_metric := case peak_pct
    when egress_pct then 'egress'
    when log_ingest_pct then 'log_ingestion'
    when log_query_pct then 'log_query'
    when database_pct then 'database'
    when storage_pct then 'file_storage'
    else 'monthly_active_users'
  end;

  if cfg.manual_stage is not null then
    next_stage := cfg.manual_stage;
  elsif not cfg.auto_enabled then
    next_stage := cfg.current_stage;
  elsif peak_pct >= cfg.threshold_survival then
    next_stage := 'survival';
  elsif peak_pct >= cfg.threshold_critical then
    next_stage := 'critical';
  elsif peak_pct >= cfg.threshold_severe then
    next_stage := 'severe';
  elsif peak_pct >= cfg.threshold_restricted then
    next_stage := 'restricted';
  else
    next_stage := 'normal';
  end if;

  stage_changed := next_stage is distinct from previous_stage
                   or cfg.cycle_start is distinct from cycle_date;

  update public.usage_restriction_config
  set
    current_stage = next_stage,
    trigger_metric = peak_metric,
    trigger_percent = round(peak_pct,3),
    cycle_start = cycle_date,
    audit_event_upload_enabled = next_stage <> 'survival',
    deployment_delivery_enabled = next_stage in ('normal','restricted'),
    remote_support_delivery_enabled = next_stage in ('normal','restricted','severe'),
    location_delivery_enabled = next_stage = 'normal',
    last_evaluated_at = now(),
    last_stage_change_at = case when stage_changed then now() else last_stage_change_at end,
    updated_at = now()
  where id = 1;

  if cfg.auto_enabled or cfg.manual_stage is not null then
    update public.resource_guard_config
    set
      mode = case
        when next_stage = 'normal' then 'balanced'
        when next_stage = 'restricted' then 'conserve'
        else 'critical'
      end,
      heartbeat_seconds = case next_stage
        when 'normal' then 600
        when 'restricted' then 900
        when 'severe' then 1800
        when 'critical' then 21600
        else 86400
      end,
      inventory_probe_minutes = case next_stage
        when 'normal' then 15
        when 'restricted' then 30
        when 'severe' then 120
        else 1440
      end,
      inventory_resend_hours = 24,
      network_enabled = next_stage in ('normal','restricted'),
      network_probe_minutes = case next_stage
        when 'normal' then 15
        when 'restricted' then 60
        else 1440
      end,
      network_resend_minutes = 1440,
      location_enabled = next_stage = 'normal',
      device_resend_minutes = 1440,
      location_resend_minutes = 1440,
      update_status_resend_minutes = 1440,
      updated_at = now()
    where id = 1;
  end if;

  return jsonb_build_object(
    'stage', next_stage,
    'previousStage', previous_stage,
    'stageChanged', stage_changed,
    'triggerMetric', peak_metric,
    'triggerPercent', round(peak_pct,3),
    'autoEnabled', cfg.auto_enabled,
    'manualStage', cfg.manual_stage,
    'usage', jsonb_build_object(
      'egressPercent', round(egress_pct,3),
      'logIngestionPercent', round(log_ingest_pct,3),
      'logQueryPercent', round(log_query_pct,3),
      'databasePercent', round(database_pct,3),
      'fileStoragePercent', round(storage_pct,3),
      'monthlyActiveUsersPercent', round(mau_pct,3)
    )
  );
end;
$$;

revoke all on function public.evaluate_usage_restrictions() from public, anon, authenticated;
grant execute on function public.evaluate_usage_restrictions() to service_role;

create or replace function public.get_usage_restriction_status()
returns jsonb
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  caller_email text := lower(coalesce((select auth.jwt())->>'email',''));
  cfg public.usage_restriction_config%rowtype;
  guard public.resource_guard_config%rowtype;
  cycle_start_utc timestamptz := date_trunc('month', now());
  cycle_date date := date_trunc('month', now() at time zone 'utc')::date;
  egress_bytes bigint := 0;
  log_ingest_bytes bigint := 0;
  log_query_bytes bigint := 0;
  database_bytes bigint := 0;
  storage_bytes bigint := 0;
  mau bigint := 0;
begin
  if auth.role() <> 'authenticated' or caller_email = '' or not exists (
    select 1 from public.console_users cu
    where lower(cu.email) = caller_email and cu.is_active = true
  ) then
    raise exception 'Smart Console authorization required' using errcode = '42501';
  end if;

  select * into cfg from public.usage_restriction_config where id = 1;
  select * into guard from public.resource_guard_config where id = 1;

  select coalesce(sum(d.egress_bytes),0)::bigint into egress_bytes
  from public.usage_client_egress_daily d where d.usage_day >= cycle_date;
  select coalesce(sum(s.observed_log_ingest_bytes),0)::bigint,
         coalesce(sum(s.log_query_scanned_bytes),0)::bigint
  into log_ingest_bytes, log_query_bytes
  from public.platform_usage_snapshots s where s.window_end >= cycle_start_utc;
  select pg_database_size(current_database())::bigint into database_bytes;
  select coalesce(sum(coalesce(nullif(o.metadata->>'size','')::bigint,0)),0)::bigint
  into storage_bytes from storage.objects o;
  select count(*)::bigint into mau from auth.users u
  where u.last_sign_in_at >= cycle_start_utc
    and u.last_sign_in_at < cycle_start_utc + interval '1 month';

  return jsonb_build_object(
    'autoEnabled', cfg.auto_enabled,
    'manualStage', cfg.manual_stage,
    'currentStage', cfg.current_stage,
    'triggerMetric', cfg.trigger_metric,
    'triggerPercent', cfg.trigger_percent,
    'cycleStart', cfg.cycle_start,
    'lastEvaluatedAt', cfg.last_evaluated_at,
    'lastStageChangeAt', cfg.last_stage_change_at,
    'thresholds', jsonb_build_object(
      'restricted', cfg.threshold_restricted,
      'severe', cfg.threshold_severe,
      'critical', cfg.threshold_critical,
      'survival', cfg.threshold_survival
    ),
    'controls', jsonb_build_object(
      'auditEventUploadEnabled', cfg.audit_event_upload_enabled,
      'deploymentDeliveryEnabled', cfg.deployment_delivery_enabled,
      'remoteSupportDeliveryEnabled', cfg.remote_support_delivery_enabled,
      'locationDeliveryEnabled', cfg.location_delivery_enabled
    ),
    'usage', jsonb_build_object(
      'egressBytes', egress_bytes,
      'egressPercent', round(egress_bytes::numeric/(5::numeric*1024*1024*1024)*100,3),
      'logIngestionBytes', log_ingest_bytes,
      'logIngestionPercent', round(log_ingest_bytes::numeric/(1::numeric*1024*1024*1024)*100,3),
      'logQueryBytes', log_query_bytes,
      'logQueryPercent', round(log_query_bytes::numeric/(100::numeric*1024*1024*1024)*100,3),
      'databaseBytes', database_bytes,
      'databasePercent', round(database_bytes::numeric/(500::numeric*1024*1024)*100,3),
      'fileStorageBytes', storage_bytes,
      'fileStoragePercent', round(storage_bytes::numeric/(1::numeric*1024*1024*1024)*100,3),
      'monthlyActiveUsers', mau,
      'monthlyActiveUsersPercent', round(mau::numeric/50000::numeric*100,3)
    ),
    'guard', to_jsonb(guard),
    'profiles', jsonb_build_array(
      jsonb_build_object('stage','normal','fromPercent',0,'heartbeatSeconds',600,'inventory','daily full reconciliation','network','change-driven + daily fallback','events','enabled','commands','enabled'),
      jsonb_build_object('stage','restricted','fromPercent',cfg.threshold_restricted,'heartbeatSeconds',900,'inventory','daily','network','hourly probe + daily fallback','events','enabled','commands','enabled except location'),
      jsonb_build_object('stage','severe','fromPercent',cfg.threshold_severe,'heartbeatSeconds',1800,'inventory','daily','network','off','events','batched','commands','deployment off'),
      jsonb_build_object('stage','critical','fromPercent',cfg.threshold_critical,'heartbeatSeconds',21600,'inventory','daily','network','off','events','batched every heartbeat','commands','essential only'),
      jsonb_build_object('stage','survival','fromPercent',cfg.threshold_survival,'heartbeatSeconds',86400,'inventory','daily','network','off','events','held locally','commands','essential only')
    )
  );
end;
$$;

revoke all on function public.get_usage_restriction_status() from public, anon;
grant execute on function public.get_usage_restriction_status() to authenticated;

-- One compact heartbeat database RPC: token verification, terminal presence,
-- service policy, Resource Guard, usage restriction and command delivery.
create or replace function public.terminal_sync_v2(
  p_terminal_id text,
  p_token_hash text,
  p_computer_name text,
  p_windows_user text,
  p_app_version text,
  p_last_ip text,
  p_endpoint jsonb default null
)
returns jsonb
language plpgsql
security definer
set search_path = public, security, pg_temp
as $$
declare
  v_token_id uuid;
  t public.terminals%rowtype;
  g public.resource_guard_config%rowtype;
  r public.usage_restriction_config%rowtype;
  command_json jsonb := '[]'::jsonb;
  command_ids uuid[] := '{}';
  now_at timestamptz := now();
begin
  if auth.role() <> 'service_role' then
    raise exception 'Service role required' using errcode = '42501';
  end if;

  select token_id into v_token_id
  from security.terminal_tokens
  where terminal_id = p_terminal_id
    and token_hash = p_token_hash
    and revoked_at is null
    and (expires_at is null or expires_at > now_at)
  limit 1;

  if v_token_id is null then
    return jsonb_build_object('authenticated', false);
  end if;

  update security.terminal_tokens
  set last_used_at = now_at
  where token_id = v_token_id;

  update public.terminals
  set
    computer_name = coalesce(nullif(p_computer_name,''), computer_name),
    windows_user = nullif(p_windows_user,''),
    app_version = nullif(p_app_version,''),
    last_seen_at = now_at,
    last_ip = case when nullif(p_last_ip,'') is null then last_ip else nullif(p_last_ip,'')::inet end,
    last_error = null,
    os_name = case when p_endpoint is null then os_name else p_endpoint->>'osName' end,
    os_version = case when p_endpoint is null then os_version else p_endpoint->>'osVersion' end,
    manufacturer = case when p_endpoint is null then manufacturer else p_endpoint->>'manufacturer' end,
    model = case when p_endpoint is null then model else p_endpoint->>'model' end,
    serial_number = case when p_endpoint is null then serial_number else p_endpoint->>'serialNumber' end,
    total_memory_bytes = case when p_endpoint is null then total_memory_bytes else nullif(p_endpoint->>'totalMemoryBytes','')::bigint end,
    processor_name = case when p_endpoint is null then processor_name else p_endpoint->>'processorName' end,
    defender_status = case when p_endpoint is null then defender_status else p_endpoint->>'defenderStatus' end,
    firewall_enabled = case when p_endpoint is null then firewall_enabled else nullif(p_endpoint->>'firewallEnabled','')::boolean end,
    inventory_at = case when p_endpoint is null then inventory_at else coalesce(nullif(p_endpoint->>'capturedAt','')::timestamptz, now_at) end,
    updated_at = now_at
  where terminal_id = p_terminal_id
    and enrollment_status = 'active'
  returning * into t;

  if t.terminal_id is null then
    return jsonb_build_object('authenticated', false);
  end if;

  select * into g from public.resource_guard_config where id = 1;
  select * into r from public.usage_restriction_config where id = 1;

  with eligible as (
    select c.command_id, c.command_type, c.payload
    from public.endpoint_commands c
    where c.terminal_id = p_terminal_id
      and c.status = 'pending'
      and c.command_type in ('inventory','force_update','cloud_sync','remote_support','sync_policy',
                             'deploy_application','verify_application_package','set_connection_password','request_location')
      and (c.command_type <> 'inventory' or t.inventory_service_enabled)
      and (c.command_type <> 'remote_support' or (t.remote_support_service_enabled and r.remote_support_delivery_enabled))
      and (c.command_type <> 'sync_policy' or t.software_control_service_enabled)
      and (c.command_type not in ('deploy_application','verify_application_package')
           or (t.deployment_service_enabled and r.deployment_delivery_enabled))
      and (c.command_type <> 'request_location'
           or (t.location_service_enabled and r.location_delivery_enabled))
      and (
        r.current_stage not in ('critical','survival')
        or c.command_type in ('force_update','cloud_sync','set_connection_password','inventory','sync_policy')
      )
    order by c.requested_at
    limit 20
  ),
  acked as (
    update public.endpoint_commands c
    set status = 'acknowledged', acknowledged_at = now_at
    where c.command_id in (select command_id from eligible)
    returning c.command_id, c.command_type, c.payload
  )
  select
    coalesce(jsonb_agg(jsonb_build_object(
      'commandId', a.command_id,
      'commandType', a.command_type,
      'payload', a.payload
    )), '[]'::jsonb),
    coalesce(array_agg(a.command_id), '{}')
  into command_json, command_ids
  from acked a;

  if cardinality(command_ids) > 0 then
    update public.deployment_tasks
    set
      status = 'acknowledged',
      progress_percent = 2,
      progress_stage = 'received',
      progress_message = 'Deployment received by the endpoint.',
      last_progress_at = now_at,
      started_at = coalesce(started_at, now_at)
    where command_id = any(command_ids)
      and terminal_id = p_terminal_id
      and status = 'pending';
  end if;

  return jsonb_build_object(
    'authenticated', true,
    'resourcePolicy', jsonb_build_object(
      'mode', g.mode,
      'heartbeatSeconds', g.heartbeat_seconds,
      'networkEnabled', g.network_enabled,
      'locationEnabled', g.location_enabled,
      'inventoryProbeMinutes', g.inventory_probe_minutes,
      'inventoryResendHours', g.inventory_resend_hours,
      'networkProbeMinutes', g.network_probe_minutes,
      'networkResendMinutes', g.network_resend_minutes,
      'deviceResendMinutes', g.device_resend_minutes,
      'locationResendMinutes', g.location_resend_minutes,
      'updateStatusResendMinutes', g.update_status_resend_minutes,
      'updatedAt', g.updated_at
    ),
    'servicePolicy', jsonb_build_object(
      'usbAuditEnabled', t.usb_audit_enabled,
      'networkEnabled', t.network_service_enabled,
      'locationEnabled', t.location_service_enabled,
      'inventoryEnabled', t.inventory_service_enabled,
      'deploymentEnabled', t.deployment_service_enabled,
      'softwareControlEnabled', t.software_control_service_enabled,
      'remoteSupportEnabled', t.remote_support_service_enabled,
      'updatedAt', t.service_policy_updated_at
    ),
    'restrictionPolicy', jsonb_build_object(
      'stage', r.current_stage,
      'active', r.current_stage <> 'normal',
      'auditEventUploadEnabled', r.audit_event_upload_enabled,
      'deploymentDeliveryEnabled', r.deployment_delivery_enabled,
      'remoteSupportDeliveryEnabled', r.remote_support_delivery_enabled,
      'locationDeliveryEnabled', r.location_delivery_enabled,
      'triggerMetric', r.trigger_metric,
      'triggerPercent', r.trigger_percent
    ),
    'commands', command_json
  );
end;
$$;

revoke all on function public.terminal_sync_v2(text,text,text,text,text,text,jsonb) from public, anon, authenticated;
grant execute on function public.terminal_sync_v2(text,text,text,text,text,text,jsonb) to service_role;

-- Start the fleet architecture immediately: 10-minute lightweight heartbeat,
-- change-driven telemetry and one full daily reconciliation.
update public.resource_guard_config
set
  mode = 'balanced',
  heartbeat_seconds = 600,
  inventory_probe_minutes = 15,
  inventory_resend_hours = 24,
  network_enabled = true,
  network_probe_minutes = 15,
  network_resend_minutes = 1440,
  location_enabled = true,
  device_resend_minutes = 1440,
  location_resend_minutes = 1440,
  update_status_resend_minutes = 1440,
  updated_at = now()
where id = 1;
