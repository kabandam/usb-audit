create index if not exists file_shares_uploaded_by_idx
  on public.file_shares(uploaded_by);

create or replace function public.consume_file_share(p_share_token text)
returns table (
  status text,
  redirect_url text,
  resolved_file_name text
)
language plpgsql
security invoker
set search_path = public, pg_temp
as $$
declare
  v_share public.file_shares%rowtype;
begin
  update public.file_shares
  set
    download_count = download_count + 1,
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

  select * into v_share
  from public.file_shares
  where share_token = p_share_token
  limit 1;

  if v_share.share_id is null then
    return query select 'not_found'::text, null::text, null::text;
    return;
  elsif not v_share.is_active then
    return query select 'disabled'::text, null::text, v_share.file_name;
    return;
  elsif v_share.expires_at is not null and v_share.expires_at <= now() then
    return query select 'expired'::text, null::text, v_share.file_name;
    return;
  elsif v_share.max_downloads is not null and v_share.download_count >= v_share.max_downloads then
    return query select 'limit_reached'::text, null::text, v_share.file_name;
    return;
  end if;

  return query select 'unavailable'::text, null::text, v_share.file_name;
end;
$$;

revoke all on function public.consume_file_share(text) from public, anon, authenticated;
grant execute on function public.consume_file_share(text) to service_role;
