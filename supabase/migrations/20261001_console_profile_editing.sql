alter table public.console_users
  add column if not exists avatar_path text;

insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values (
  'console-profile-images',
  'console-profile-images',
  false,
  5242880,
  array['image/jpeg','image/png','image/webp']
)
on conflict (id) do update
set public = false,
    file_size_limit = excluded.file_size_limit,
    allowed_mime_types = excluded.allowed_mime_types;

drop policy if exists "Console profile images read own" on storage.objects;
create policy "Console profile images read own"
on storage.objects
for select
to authenticated
using (
  bucket_id = 'console-profile-images'
  and (storage.foldername(name))[1] = (select auth.uid())::text
);

drop policy if exists "Console profile images insert own" on storage.objects;
create policy "Console profile images insert own"
on storage.objects
for insert
to authenticated
with check (
  bucket_id = 'console-profile-images'
  and (storage.foldername(name))[1] = (select auth.uid())::text
);

drop policy if exists "Console profile images update own" on storage.objects;
create policy "Console profile images update own"
on storage.objects
for update
to authenticated
using (
  bucket_id = 'console-profile-images'
  and (storage.foldername(name))[1] = (select auth.uid())::text
)
with check (
  bucket_id = 'console-profile-images'
  and (storage.foldername(name))[1] = (select auth.uid())::text
);

drop policy if exists "Console profile images delete own" on storage.objects;
create policy "Console profile images delete own"
on storage.objects
for delete
to authenticated
using (
  bucket_id = 'console-profile-images'
  and (storage.foldername(name))[1] = (select auth.uid())::text
);

create or replace function public.get_console_profile()
returns jsonb
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  caller_email text := lower(coalesce((select auth.jwt())->>'email',''));
  profile_row public.console_users%rowtype;
begin
  if auth.role() <> 'authenticated' or caller_email = '' then
    raise exception 'Smart Console authorization required' using errcode = '42501';
  end if;

  select *
  into profile_row
  from public.console_users cu
  where lower(cu.email) = caller_email
    and cu.is_active = true
  limit 1;

  if profile_row.email is null then
    raise exception 'Smart Console authorization required' using errcode = '42501';
  end if;

  return jsonb_build_object(
    'email', profile_row.email,
    'displayName', coalesce(nullif(profile_row.display_name,''), profile_row.email),
    'accessRole', profile_row.access_role,
    'avatarPath', profile_row.avatar_path
  );
end;
$$;

create or replace function public.update_console_profile(
  p_display_name text,
  p_avatar_path text
)
returns jsonb
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  caller_email text := lower(coalesce((select auth.jwt())->>'email',''));
  caller_uid uuid := (select auth.uid());
  clean_name text := nullif(btrim(p_display_name),'');
  updated_row public.console_users%rowtype;
begin
  if auth.role() <> 'authenticated' or caller_email = '' or caller_uid is null then
    raise exception 'Smart Console authorization required' using errcode = '42501';
  end if;

  if clean_name is null or char_length(clean_name) > 100 then
    raise exception 'Display name must be between 1 and 100 characters' using errcode = '22023';
  end if;

  if p_avatar_path is not null
     and split_part(p_avatar_path,'/',1) <> caller_uid::text then
    raise exception 'Invalid profile image path' using errcode = '42501';
  end if;

  update public.console_users
  set display_name = clean_name,
      avatar_path = p_avatar_path
  where lower(email) = caller_email
    and is_active = true
  returning * into updated_row;

  if updated_row.email is null then
    raise exception 'Smart Console authorization required' using errcode = '42501';
  end if;

  return jsonb_build_object(
    'email', updated_row.email,
    'displayName', updated_row.display_name,
    'accessRole', updated_row.access_role,
    'avatarPath', updated_row.avatar_path
  );
end;
$$;

revoke all on function public.get_console_profile() from public, anon;
grant execute on function public.get_console_profile() to authenticated;

revoke all on function public.update_console_profile(text,text) from public, anon;
grant execute on function public.update_console_profile(text,text) to authenticated;
