create or replace function public.get_security_overview()
returns jsonb
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  caller_email text := lower(coalesce((select auth.jwt())->>'email',''));
  day_start timestamptz := date_trunc('day', now() at time zone 'Africa/Blantyre') at time zone 'Africa/Blantyre';
  total_endpoints bigint := 0;
  online_endpoints bigint := 0;
  offline_24h bigint := 0;
  protected_endpoints bigint := 0;
  firewall_endpoints bigint := 0;
  restricted_endpoints bigint := 0;
  update_current bigint := 0;
  update_issues bigint := 0;
  pending_enrollment bigint := 0;
  connected_usb bigint := 0;
  usb_transfers_today bigint := 0;
  software_pending bigint := 0;
  software_block_rules bigint := 0;
  remote_active bigint := 0;
  remote_failed_today bigint := 0;
  deployment_active bigint := 0;
  deployment_failed bigint := 0;
  onedrive_healthy bigint := 0;
  onedrive_issues bigint := 0;
  networks_reporting bigint := 0;
  locations_available bigint := 0;
  file_total bigint := 0;
  file_active bigint := 0;
  file_downloads bigint := 0;
  file_expiring bigint := 0;
  usage_status jsonb := '{}'::jsonb;
  recent_activity jsonb := '[]'::jsonb;
begin
  if auth.role() <> 'authenticated'
     or caller_email = ''
     or not exists (
       select 1
       from public.console_users cu
       where lower(cu.email) = caller_email
         and cu.is_active = true
     ) then
    raise exception 'Smart Console authorization required' using errcode = '42501';
  end if;

  select
    count(*) filter (where t.enrollment_status = 'active'),
    count(*) filter (where t.enrollment_status = 'active' and t.last_seen_at >= now() - interval '10 minutes'),
    count(*) filter (where t.enrollment_status = 'active' and t.last_seen_at < now() - interval '24 hours'),
    count(*) filter (where t.enrollment_status = 'active' and lower(coalesce(t.defender_status,'')) = 'protected'),
    count(*) filter (where t.enrollment_status = 'active' and t.firewall_enabled is true),
    count(*) filter (where t.enrollment_status = 'active' and t.access_restricted is true)
  into total_endpoints, online_endpoints, offline_24h, protected_endpoints, firewall_endpoints, restricted_endpoints
  from public.terminals t;

  select
    count(*) filter (where lower(coalesce(s.state,'')) = 'up to date'),
    count(*) filter (where lower(coalesce(s.state,'')) <> 'up to date')
  into update_current, update_issues
  from public.endpoint_agent_update_status s;

  select count(*) into pending_enrollment
  from public.machine_enrollment_requests r
  where r.status = 'pending';

  select count(*) into connected_usb
  from public.terminal_devices;

  select count(*) into usb_transfers_today
  from public.audit_events e
  where e.timestamp >= day_start
    and e.kind in ('UsbWrite','UsbRead');

  select count(*) into software_pending
  from public.software_approvals a
  where lower(coalesce(a.status,'')) not in ('approved','denied','rejected');

  select count(*) into software_block_rules
  from public.software_control_rules r
  where r.is_active is true
    and lower(coalesce(r.action,'')) in ('block','blocked','deny');

  select
    count(*) filter (where lower(coalesce(c.status,'')) in ('pending','acknowledged','running','in_progress')),
    count(*) filter (where lower(coalesce(c.status,'')) = 'failed' and c.requested_at >= day_start)
  into remote_active, remote_failed_today
  from public.endpoint_commands c;

  select
    count(*) filter (where lower(coalesce(t.status,'')) in ('pending','queued','acknowledged','downloading','installing','running','in_progress')),
    count(*) filter (where lower(coalesce(t.status,'')) = 'failed')
  into deployment_active, deployment_failed
  from public.deployment_tasks t;

  select
    count(*) filter (
      where s.is_running is true
        and s.account_configured is true
        and coalesce(lower(s.health),'healthy') not in ('error','unhealthy','failed','attention')
        and s.last_error is null
    ),
    count(*) filter (
      where not (
        s.is_running is true
        and s.account_configured is true
        and coalesce(lower(s.health),'healthy') not in ('error','unhealthy','failed','attention')
        and s.last_error is null
      )
    )
  into onedrive_healthy, onedrive_issues
  from public.endpoint_onedrive_status s;

  select count(*) into networks_reporting
  from public.endpoint_network_status;

  select count(*) into locations_available
  from public.endpoint_location_status l
  where l.latitude is not null
    and l.longitude is not null
    and lower(coalesce(l.status,'')) not in ('not_enabled','denied','error');

  select
    count(*),
    count(*) filter (
      where f.is_active is true
        and (f.expires_at is null or f.expires_at > now())
        and (f.max_downloads is null or f.download_count < f.max_downloads)
    ),
    coalesce(sum(f.download_count),0),
    count(*) filter (
      where f.is_active is true
        and f.expires_at > now()
        and f.expires_at <= now() + interval '7 days'
    )
  into file_total, file_active, file_downloads, file_expiring
  from public.file_shares f;

  begin
    usage_status := public.get_usage_restriction_status();
  exception when others then
    usage_status := jsonb_build_object(
      'currentStage','unknown',
      'triggerPercent',0,
      'usage',jsonb_build_object()
    );
  end;

  with activity as (
    select
      e.timestamp as occurred_at,
      'usb'::text as activity_type,
      case
        when e.kind = 'UsbWrite' then 'File copied to USB'
        when e.kind = 'UsbRead' then 'File copied from USB'
        else coalesce(e.kind,'USB activity')
      end as title,
      concat_ws(' · ',
        coalesce(t.computer_name,e.computer_name,e.terminal_id),
        nullif(e.file_name,''),
        nullif(e.device_name,'')
      ) as detail,
      coalesce(e.direction,'') as status
    from public.audit_events e
    left join public.terminals t on t.terminal_id = e.terminal_id
    where e.timestamp >= now() - interval '7 days'

    union all

    select
      c.requested_at as occurred_at,
      'remote'::text as activity_type,
      initcap(replace(coalesce(c.command_type,'Remote command'),'_',' ')) as title,
      coalesce(t.computer_name,c.terminal_id) as detail,
      coalesce(c.status,'') as status
    from public.endpoint_commands c
    left join public.terminals t on t.terminal_id = c.terminal_id
    where c.requested_at >= now() - interval '7 days'

    union all

    select
      d.requested_at as occurred_at,
      'deployment'::text as activity_type,
      'Application deployment'::text as title,
      concat_ws(' · ', coalesce(t.computer_name,d.terminal_id), nullif(d.progress_stage,''), nullif(d.progress_message,'')) as detail,
      coalesce(d.status,'') as status
    from public.deployment_tasks d
    left join public.terminals t on t.terminal_id = d.terminal_id
    where d.requested_at >= now() - interval '7 days'
  ),
  latest as (
    select *
    from activity
    order by occurred_at desc
    limit 24
  )
  select coalesce(jsonb_agg(
    jsonb_build_object(
      'occurredAt', occurred_at,
      'type', activity_type,
      'title', title,
      'detail', detail,
      'status', status
    )
    order by occurred_at desc
  ), '[]'::jsonb)
  into recent_activity
  from latest;

  return jsonb_build_object(
    'generatedAt', now(),
    'endpoints', jsonb_build_object(
      'total', total_endpoints,
      'online', online_endpoints,
      'offline', greatest(total_endpoints - online_endpoints,0),
      'offline24h', offline_24h,
      'protected', protected_endpoints,
      'firewallOn', firewall_endpoints,
      'accessRestricted', restricted_endpoints,
      'agentCurrent', update_current,
      'agentIssues', update_issues,
      'pendingEnrollment', pending_enrollment
    ),
    'security', jsonb_build_object(
      'connectedUsb', connected_usb,
      'usbTransfersToday', usb_transfers_today,
      'softwarePending', software_pending,
      'softwareBlockRules', software_block_rules
    ),
    'operations', jsonb_build_object(
      'remoteActive', remote_active,
      'remoteFailedToday', remote_failed_today,
      'deploymentActive', deployment_active,
      'deploymentFailed', deployment_failed,
      'onedriveHealthy', onedrive_healthy,
      'onedriveIssues', onedrive_issues,
      'networksReporting', networks_reporting,
      'locationsAvailable', locations_available
    ),
    'fileSharing', jsonb_build_object(
      'total', file_total,
      'active', file_active,
      'downloads', file_downloads,
      'expiringSoon', file_expiring
    ),
    'usage', usage_status,
    'recentActivity', recent_activity
  );
end;
$$;

revoke all on function public.get_security_overview() from public, anon;
grant execute on function public.get_security_overview() to authenticated;
