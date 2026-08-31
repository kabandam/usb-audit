create or replace function public.verify_terminal_token(p_terminal_id text, p_token_hash text)
returns uuid language plpgsql security definer set search_path = '' as $$
declare v_token_id uuid;
begin
  select token_id into v_token_id from security.terminal_tokens
  where terminal_id = p_terminal_id and token_hash = p_token_hash
    and revoked_at is null and (expires_at is null or expires_at > now());
  if v_token_id is not null then
    update security.terminal_tokens set last_used_at = now() where token_id = v_token_id;
  end if;
  return v_token_id;
end;
$$;

create or replace function public.claim_terminal_enrollment(
  p_code_hash text, p_token_hash text, p_token_prefix text, p_terminal_id text,
  p_computer_name text, p_windows_user text, p_app_version text
)
returns boolean language sql security definer set search_path = '' as $$
  select security.claim_terminal_enrollment(p_code_hash, p_token_hash, p_token_prefix, p_terminal_id,
    p_computer_name, p_windows_user, p_app_version)
$$;

create or replace function public.create_terminal_enrollment(
  p_code_hash text, p_code_prefix text, p_label text, p_created_by uuid, p_expires_at timestamptz
)
returns void language sql security definer set search_path = '' as $$
  insert into security.terminal_enrollment_codes(code_hash, code_prefix, label, created_by, expires_at)
  values (p_code_hash, p_code_prefix, nullif(p_label, ''), p_created_by, p_expires_at)
$$;

create or replace function public.revoke_terminal(p_terminal_id text)
returns void language plpgsql security definer set search_path = '' as $$
begin
  update security.terminal_tokens set revoked_at = now()
  where terminal_id = p_terminal_id and revoked_at is null;
  update public.terminals set enrollment_status = 'revoked', updated_at = now()
  where terminal_id = p_terminal_id;
end;
$$;

revoke all on function public.verify_terminal_token(text,text) from public, anon, authenticated;
revoke all on function public.claim_terminal_enrollment(text,text,text,text,text,text,text) from public, anon, authenticated;
revoke all on function public.create_terminal_enrollment(text,text,text,uuid,timestamptz) from public, anon, authenticated;
revoke all on function public.revoke_terminal(text) from public, anon, authenticated;
grant execute on function public.verify_terminal_token(text,text) to service_role;
grant execute on function public.claim_terminal_enrollment(text,text,text,text,text,text,text) to service_role;
grant execute on function public.create_terminal_enrollment(text,text,text,uuid,timestamptz) to service_role;
grant execute on function public.revoke_terminal(text) to service_role;

grant usage on schema security to authenticated;
grant execute on function security.is_creccom_user() to authenticated;
