drop policy if exists resource_guard_read_console on public.resource_guard_config;
create policy resource_guard_read_console
on public.resource_guard_config
for select
to authenticated
using (
  exists (
    select 1
    from public.console_users cu
    where lower(cu.email) = lower(coalesce((select auth.jwt())->>'email',''))
      and cu.is_active = true
  )
);

revoke execute on function public.get_free_tier_monitor() from anon;
revoke execute on function public.get_free_tier_monitor() from public;
grant execute on function public.get_free_tier_monitor() to authenticated, service_role;
