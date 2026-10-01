create table if not exists public.file_shares (
  share_id uuid primary key default gen_random_uuid(),
  share_token text not null unique default encode(gen_random_bytes(18), 'hex'),
  file_name text not null,
  file_size_bytes bigint not null default 0 check (file_size_bytes >= 0),
  mime_type text,
  drive_id text,
  drive_item_id text not null,
  drive_web_url text,
  share_url text not null,
  share_permission_ids text[] not null default '{}'::text[],
  access_scope text not null default 'organization'
    check (access_scope in ('public','organization','specific')),
  allowed_emails text[] not null default '{}'::text[],
  expires_at timestamptz,
  max_downloads integer check (max_downloads is null or max_downloads > 0),
  download_count bigint not null default 0 check (download_count >= 0),
  last_downloaded_at timestamptz,
  is_active boolean not null default true,
  uploaded_by uuid references auth.users(id) on delete set null,
  uploaded_by_email text not null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

comment on table public.file_shares is
  'Console-managed OneDrive file shares. File bytes remain in Microsoft OneDrive/SharePoint; this table stores metadata and the controlled redirect link only.';

create index if not exists file_shares_created_at_idx on public.file_shares(created_at desc);
create index if not exists file_shares_active_expiry_idx on public.file_shares(is_active, expires_at);

alter table public.file_shares enable row level security;

drop policy if exists file_shares_admin_select on public.file_shares;
create policy file_shares_admin_select on public.file_shares for select to authenticated
using (exists (
  select 1 from public.console_users cu
  where lower(cu.email) = lower(coalesce((select auth.jwt())->>'email',''))
    and cu.is_active = true and cu.access_role = 'admin'
));

drop policy if exists file_shares_admin_insert on public.file_shares;
create policy file_shares_admin_insert on public.file_shares for insert to authenticated
with check (
  uploaded_by = (select auth.uid())
  and lower(uploaded_by_email) = lower(coalesce((select auth.jwt())->>'email',''))
  and exists (
    select 1 from public.console_users cu
    where lower(cu.email) = lower(coalesce((select auth.jwt())->>'email',''))
      and cu.is_active = true and cu.access_role = 'admin'
  )
);

drop policy if exists file_shares_admin_update on public.file_shares;
create policy file_shares_admin_update on public.file_shares for update to authenticated
using (exists (
  select 1 from public.console_users cu
  where lower(cu.email) = lower(coalesce((select auth.jwt())->>'email',''))
    and cu.is_active = true and cu.access_role = 'admin'
))
with check (exists (
  select 1 from public.console_users cu
  where lower(cu.email) = lower(coalesce((select auth.jwt())->>'email',''))
    and cu.is_active = true and cu.access_role = 'admin'
));

drop policy if exists file_shares_admin_delete on public.file_shares;
create policy file_shares_admin_delete on public.file_shares for delete to authenticated
using (exists (
  select 1 from public.console_users cu
  where lower(cu.email) = lower(coalesce((select auth.jwt())->>'email',''))
    and cu.is_active = true and cu.access_role = 'admin'
));

revoke all on public.file_shares from anon;
grant select, insert, update, delete on public.file_shares to authenticated;

create or replace function public.consume_file_share(p_share_token text)
returns table (status text, redirect_url text, resolved_file_name text)
language plpgsql
security invoker
set search_path = public, pg_temp
as $$
declare
  v_share public.file_shares%rowtype;
begin
  update public.file_shares
  set download_count = download_count + 1,
      last_downloaded_at = now(),
      updated_at = now()
  where share_token = p_share_token
    and is_active = true
    and (expires_at is null or expires_at > now())
    and (max_downloads is null or download_count < max_downloads)
  returning * into v_share;

  if found then
    return query select 'ok'::text, v_share.share_url, v_share.file_name;
    return;
  end if;

  select * into v_share from public.file_shares where share_token = p_share_token limit 1;

  if v_share.share_id is null then
    return query select 'not_found'::text, null::text, null::text;
  elsif not v_share.is_active then
    return query select 'disabled'::text, null::text, v_share.file_name;
  elsif v_share.expires_at is not null and v_share.expires_at <= now() then
    return query select 'expired'::text, null::text, v_share.file_name;
  elsif v_share.max_downloads is not null and v_share.download_count >= v_share.max_downloads then
    return query select 'limit_reached'::text, null::text, v_share.file_name;
  end if;

  return query select 'unavailable'::text, null::text, v_share.file_name;
end;
$$;

revoke all on function public.consume_file_share(text) from public, anon, authenticated;
grant execute on function public.consume_file_share(text) to service_role;
