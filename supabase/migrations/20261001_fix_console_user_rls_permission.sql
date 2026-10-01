-- Fix authenticated RLS policies that referenced private console_users directly.
-- Keep console_users private; expose only a boolean SECURITY DEFINER membership check.

create or replace function public.is_active_console_user()
returns boolean
language sql
stable
security definer
set search_path = public, auth, pg_temp
as $$
  select exists (
    select 1
    from public.console_users cu
    where lower(cu.email) = lower(coalesce((select auth.jwt())->>'email',''))
      and cu.is_active = true
  );
$$;

revoke all on function public.is_active_console_user() from public, anon;
grant execute on function public.is_active_console_user() to authenticated, service_role;

drop policy if exists resource_guard_read_console on public.resource_guard_config;
create policy resource_guard_read_console
on public.resource_guard_config
for select to authenticated
using (public.is_active_console_user());

drop policy if exists usage_restriction_read_console on public.usage_restriction_config;
create policy usage_restriction_read_console
on public.usage_restriction_config
for select to authenticated
using (public.is_active_console_user());

drop policy if exists endpoint_onedrive_status_console_read on public.endpoint_onedrive_status;
create policy endpoint_onedrive_status_console_read
on public.endpoint_onedrive_status
for select to authenticated
using (public.is_active_console_user());
