create table if not exists public.endpoint_onedrive_account_policy (
  terminal_id text primary key references public.terminals(terminal_id) on delete cascade,
  directory_user_id text not null,
  user_principal_name text not null,
  display_name text,
  tenant_id text,
  enforce_match boolean not null default true,
  updated_by uuid references auth.users(id) on delete set null,
  updated_at timestamptz not null default now()
);

alter table public.endpoint_onedrive_account_policy enable row level security;

drop policy if exists endpoint_onedrive_account_policy_admin_select on public.endpoint_onedrive_account_policy;
create policy endpoint_onedrive_account_policy_admin_select
on public.endpoint_onedrive_account_policy
for select
to authenticated
using (
  exists (
    select 1
    from public.console_users cu
    where lower(cu.email) = lower(coalesce((select auth.jwt())->>'email',''))
      and cu.is_active = true
      and cu.access_role = 'admin'
  )
);

drop policy if exists endpoint_onedrive_account_policy_admin_insert on public.endpoint_onedrive_account_policy;
create policy endpoint_onedrive_account_policy_admin_insert
on public.endpoint_onedrive_account_policy
for insert
to authenticated
with check (
  updated_by = (select auth.uid())
  and exists (
    select 1
    from public.console_users cu
    where lower(cu.email) = lower(coalesce((select auth.jwt())->>'email',''))
      and cu.is_active = true
      and cu.access_role = 'admin'
  )
);

drop policy if exists endpoint_onedrive_account_policy_admin_update on public.endpoint_onedrive_account_policy;
create policy endpoint_onedrive_account_policy_admin_update
on public.endpoint_onedrive_account_policy
for update
to authenticated
using (
  exists (
    select 1
    from public.console_users cu
    where lower(cu.email) = lower(coalesce((select auth.jwt())->>'email',''))
      and cu.is_active = true
      and cu.access_role = 'admin'
  )
)
with check (
  exists (
    select 1
    from public.console_users cu
    where lower(cu.email) = lower(coalesce((select auth.jwt())->>'email',''))
      and cu.is_active = true
      and cu.access_role = 'admin'
  )
);

drop policy if exists endpoint_onedrive_account_policy_admin_delete on public.endpoint_onedrive_account_policy;
create policy endpoint_onedrive_account_policy_admin_delete
on public.endpoint_onedrive_account_policy
for delete
to authenticated
using (
  exists (
    select 1
    from public.console_users cu
    where lower(cu.email) = lower(coalesce((select auth.jwt())->>'email',''))
      and cu.is_active = true
      and cu.access_role = 'admin'
  )
);

grant select, insert, update, delete on public.endpoint_onedrive_account_policy to authenticated;
revoke all on public.endpoint_onedrive_account_policy from anon;
