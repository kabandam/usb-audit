-- Remote endpoint actions, access restriction state, and OneDrive health telemetry.

alter table public.terminals
  add column if not exists access_restricted boolean not null default false,
  add column if not exists access_restricted_at timestamptz,
  add column if not exists access_restricted_user text,
  add column if not exists access_restriction_command_id uuid;

create table if not exists public.endpoint_onedrive_status (
  terminal_id text primary key references public.terminals(terminal_id) on delete cascade,
  is_running boolean,
  account_configured boolean,
  user_email text,
  sync_root text,
  client_version text,
  tenant_id text,
  desktop_protected boolean,
  documents_protected boolean,
  pictures_protected boolean,
  health text,
  last_action text,
  last_error text,
  reported_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

alter table public.endpoint_onedrive_status enable row level security;
drop policy if exists endpoint_onedrive_status_console_read on public.endpoint_onedrive_status;
create policy endpoint_onedrive_status_console_read
on public.endpoint_onedrive_status
for select to authenticated
using (
  exists (
    select 1 from public.console_users cu
    where lower(cu.email) = lower(coalesce((select auth.jwt())->>'email',''))
      and cu.is_active = true
  )
);
revoke all on public.endpoint_onedrive_status from anon;
grant select on public.endpoint_onedrive_status to authenticated;

create index if not exists endpoint_onedrive_status_reported_idx
  on public.endpoint_onedrive_status(reported_at desc);

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
      and c.command_type in (
        'inventory','force_update','cloud_sync','remote_support','sync_policy',
        'deploy_application','verify_application_package','set_connection_password',
        'request_location','device_control','onedrive'
      )
      and (c.command_type <> 'inventory' or t.inventory_service_enabled)
      and (c.command_type not in ('remote_support','device_control','onedrive')
           or t.remote_support_service_enabled)
      and (c.command_type <> 'remote_support' or r.remote_support_delivery_enabled)
      and (c.command_type <> 'sync_policy' or t.software_control_service_enabled)
      and (c.command_type not in ('deploy_application','verify_application_package')
           or (t.deployment_service_enabled and r.deployment_delivery_enabled))
      and (c.command_type <> 'request_location'
           or (t.location_service_enabled and r.location_delivery_enabled))
      and (
        r.current_stage not in ('critical','survival')
        or c.command_type in (
          'force_update','cloud_sync','set_connection_password','inventory',
          'sync_policy','device_control'
        )
      )
      and (
        c.command_type <> 'onedrive'
        or r.current_stage in ('normal','restricted')
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
