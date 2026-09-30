-- Approved, disclosed device positioning. No location is collected before explicit
-- Windows permission and Smart Console enrollment. Exact coordinates never appear in
-- general network telemetry or CSV exports.
create table if not exists public.endpoint_location_status (
 terminal_id text primary key references public.terminals(terminal_id) on delete cascade,
 sharing_enabled boolean not null default false,
 status text not null default 'not_enabled',
 latitude numeric(9,6) check (latitude is null or latitude between -90 and 90),
 longitude numeric(9,6) check (longitude is null or longitude between -180 and 180),
 accuracy_meters numeric(10,2) check (accuracy_meters is null or accuracy_meters >= 0),
 source text,
 captured_at timestamptz,
 received_at timestamptz not null default now()
);
alter table public.endpoint_location_status enable row level security;
-- Precise positions are accessible ONLY through the auditable administrator RPC.
revoke all on public.endpoint_location_status from public, anon, authenticated;
grant select, insert, update, delete on public.endpoint_location_status to service_role;
comment on table public.endpoint_location_status is
 'Optional Windows location after foreground grant; only administrators may view via an audited function; opt-out deletes stored coordinates.';

create or replace function security.is_creccom_location_admin()
returns boolean language sql stable security definer set search_path = ''
as $$
 select (select auth.uid()) is not null and exists (
   select 1 from public.console_users
   where lower(email) = lower(coalesce((select auth.jwt() ->> 'email'), ''))
     and is_active = true and access_role = 'admin'
 );
$$;
revoke all on function security.is_creccom_location_admin() from public, anon;
grant execute on function security.is_creccom_location_admin() to authenticated;

-- Deliberate user action: do not call from polling code. Each access is audited.
create or replace function public.get_endpoint_location(p_terminal_id text)
returns table (
 terminal_id text, sharing_enabled boolean, status text, latitude numeric,
 longitude numeric, accuracy_meters numeric, source text,
 captured_at timestamptz, received_at timestamptz
)
language plpgsql volatile security definer set search_path = ''
as $$
begin
 if not (select security.is_creccom_location_admin()) then
   raise exception 'Administrator location permission required' using errcode = '42501';
 end if;
 if p_terminal_id is null or length(p_terminal_id) > 200 then
   raise exception 'Invalid endpoint identifier' using errcode = '22023';
 end if;
 insert into public.endpoint_audit_log(actor_user_id,terminal_id,action,details)
 select (select auth.uid()),t.terminal_id,'location_view',jsonb_build_object('purpose','asset_security')
 from public.terminals t where t.terminal_id = p_terminal_id;
 return query
 select l.terminal_id,l.sharing_enabled,l.status,
   case when l.captured_at >= now() - interval '7 days' then l.latitude else null end,
   case when l.captured_at >= now() - interval '7 days' then l.longitude else null end,
   case when l.captured_at >= now() - interval '7 days' then l.accuracy_meters else null end,
   l.source,l.captured_at,l.received_at
 from public.endpoint_location_status l where l.terminal_id = p_terminal_id;
end; $$;
revoke all on function public.get_endpoint_location(text) from public, anon, authenticated;
grant execute on function public.get_endpoint_location(text) to authenticated;

-- Existing management commands remain valid. The new refresh command only writes
-- a flag for the consented foreground Windows application; it cannot bypass permission.
alter table public.endpoint_commands drop constraint if exists endpoint_commands_command_type_check;
alter table public.endpoint_commands add constraint endpoint_commands_command_type_check
 check (command_type in ('inventory','restart','shutdown','install_software',
 'uninstall_software','sync_policy','remote_support','deploy_application',
 'verify_application_package','set_connection_password','request_location'));

create or replace function public.request_endpoint_location(p_terminal_id text)
returns uuid language plpgsql volatile security definer set search_path = ''
as $$
declare v_command uuid;
begin
 if not (select security.is_creccom_location_admin()) then
   raise exception 'Administrator location permission required' using errcode = '42501';
 end if;
 if p_terminal_id is null or length(p_terminal_id) > 200 then
   raise exception 'Invalid endpoint identifier' using errcode = '22023';
 end if;
 if not exists (
   select 1 from public.endpoint_location_status
   where terminal_id=p_terminal_id and sharing_enabled
 ) then
   raise exception 'Device location sharing has not been enabled' using errcode = '22023';
 end if;
 if exists (
   select 1 from public.endpoint_commands where terminal_id=p_terminal_id
     and command_type='request_location' and requested_at > now() - interval '60 seconds'
 ) then
   raise exception 'Please allow at least 60 seconds between location requests' using errcode = '22023';
 end if;
 insert into public.endpoint_commands(terminal_id,command_type,payload,status,requested_by)
 values(p_terminal_id,'request_location','{}'::jsonb,'pending',(select auth.uid()))
 returning command_id into v_command;
 insert into public.endpoint_audit_log(actor_user_id,terminal_id,action,details)
 values((select auth.uid()),p_terminal_id,'location_refresh_request',
        jsonb_build_object('command_id',v_command));
 return v_command;
end; $$;
revoke all on function public.request_endpoint_location(text) from public, anon, authenticated;
grant execute on function public.request_endpoint_location(text) to authenticated;
