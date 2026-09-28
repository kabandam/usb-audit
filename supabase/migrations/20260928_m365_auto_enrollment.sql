-- Microsoft 365 automatic endpoint enrollment
alter table public.terminals
  add column if not exists m365_account text,
  add column if not exists m365_tenant_id uuid,
  add column if not exists auto_enrolled_at timestamptz;

create or replace function public.auto_enroll_terminal_m365(
  p_terminal_id text,
  p_computer_name text,
  p_windows_user text,
  p_app_version text,
  p_m365_account text,
  p_m365_tenant_id uuid,
  p_token_hash text,
  p_token_prefix text
)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
begin
  insert into public.terminals (
    terminal_id, computer_name, windows_user, app_version,
    enrollment_status, last_seen_at, updated_at,
    m365_account, m365_tenant_id, auto_enrolled_at
  )
  values (
    p_terminal_id, p_computer_name, nullif(p_windows_user, ''), nullif(p_app_version, ''),
    'active', now(), now(),
    lower(p_m365_account), p_m365_tenant_id, now()
  )
  on conflict (terminal_id) do update set
    computer_name = excluded.computer_name,
    windows_user = excluded.windows_user,
    app_version = excluded.app_version,
    enrollment_status = 'active',
    last_seen_at = now(),
    updated_at = now(),
    m365_account = excluded.m365_account,
    m365_tenant_id = excluded.m365_tenant_id,
    auto_enrolled_at = coalesce(public.terminals.auto_enrolled_at, now());

  update security.terminal_tokens
  set revoked_at = now()
  where terminal_id = p_terminal_id and revoked_at is null;

  insert into security.terminal_tokens (
    terminal_id, token_hash, token_prefix, label, created_at, last_used_at
  )
  values (
    p_terminal_id, p_token_hash, p_token_prefix,
    'Microsoft 365 automatic enrollment', now(), now()
  );

  insert into public.endpoint_audit_log (
    terminal_id, action, details
  )
  values (
    p_terminal_id,
    'm365_auto_enrolled',
    jsonb_build_object('account', lower(p_m365_account), 'tenant_id', p_m365_tenant_id::text)
  );

  return true;
end;
$$;

revoke all on function public.auto_enroll_terminal_m365(text,text,text,text,text,uuid,text,text) from public, anon, authenticated;
grant execute on function public.auto_enroll_terminal_m365(text,text,text,text,text,uuid,text,text) to service_role;
