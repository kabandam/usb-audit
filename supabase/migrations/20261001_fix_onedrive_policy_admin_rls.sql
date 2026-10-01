create or replace function public.is_console_admin()
returns boolean
language sql
stable
security definer
set search_path = public, pg_temp
as $$
  select exists (
    select 1
    from public.console_users cu
    where lower(cu.email) = lower(coalesce((select auth.jwt())->>'email',''))
      and cu.is_active = true
      and cu.access_role = 'admin'
  );
$$;

revoke all on function public.is_console_admin() from public, anon;
grant execute on function public.is_console_admin() to authenticated;

drop policy if exists endpoint_onedrive_account_policy_admin_select on public.endpoint_onedrive_account_policy;
create policy endpoint_onedrive_account_policy_admin_select
on public.endpoint_onedrive_account_policy
for select
to authenticated
using (public.is_console_admin());

drop policy if exists endpoint_onedrive_account_policy_admin_insert on public.endpoint_onedrive_account_policy;
create policy endpoint_onedrive_account_policy_admin_insert
on public.endpoint_onedrive_account_policy
for insert
to authenticated
with check (
  updated_by = (select auth.uid())
  and public.is_console_admin()
);

drop policy if exists endpoint_onedrive_account_policy_admin_update on public.endpoint_onedrive_account_policy;
create policy endpoint_onedrive_account_policy_admin_update
on public.endpoint_onedrive_account_policy
for update
to authenticated
using (public.is_console_admin())
with check (public.is_console_admin());

drop policy if exists endpoint_onedrive_account_policy_admin_delete on public.endpoint_onedrive_account_policy;
create policy endpoint_onedrive_account_policy_admin_delete
on public.endpoint_onedrive_account_policy
for delete
to authenticated
using (public.is_console_admin());
