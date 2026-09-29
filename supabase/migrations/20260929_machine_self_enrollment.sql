-- Machine-based Smart Console enrollment that does not require an interactive Windows user.

create table if not exists public.machine_enrollment_requests (
  request_id uuid primary key default gen_random_uuid(),
  terminal_id text not null unique,
  computer_name text not null,
  machine_secret_hash text not null,
  app_version text,
  serial_number text,
  manufacturer text,
  model text,
  status text not null default 'pending'
    check (status in ('pending','approved','denied','completed')),
  requested_at timestamptz not null default now(),
  last_seen_at timestamptz not null default now(),
  approved_at timestamptz,
  approved_by uuid references auth.users(id) on delete set null,
  completed_at timestamptz,
  last_ip inet
);

alter table public.machine_enrollment_requests enable row level security;

drop policy if exists "Approved console users can view machine enrollment requests"
  on public.machine_enrollment_requests;
create policy "Approved console users can view machine enrollment requests"
  on public.machine_enrollment_requests
  for select
  to authenticated
  using ((select security.is_creccom_user()));

revoke all on table public.machine_enrollment_requests from anon;
grant select on table public.machine_enrollment_requests to authenticated;

create index if not exists machine_enrollment_requests_status_idx
  on public.machine_enrollment_requests(status, requested_at desc);


create or replace function public.complete_machine_enrollment(
  p_request_id uuid,
  p_terminal_id text,
  p_computer_name text,
  p_app_version text,
  p_serial_number text,
  p_manufacturer text,
  p_model text,
  p_token_hash text,
  p_token_prefix text
)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_status text;
begin
  select status into v_status
  from public.machine_enrollment_requests
  where request_id = p_request_id
    and terminal_id = p_terminal_id
  for update;

  if v_status not in ('approved','completed') then
    return false;
  end if;

  insert into public.terminals (
    terminal_id, computer_name, app_version, enrollment_status,
    last_seen_at, updated_at, serial_number, manufacturer, model
  )
  values (
    p_terminal_id, p_computer_name, nullif(p_app_version,''),
    'active', now(), now(), nullif(p_serial_number,''),
    nullif(p_manufacturer,''), nullif(p_model,'')
  )
  on conflict (terminal_id) do update set
    computer_name = excluded.computer_name,
    app_version = excluded.app_version,
    enrollment_status = 'active',
    last_seen_at = now(),
    updated_at = now(),
    serial_number = coalesce(excluded.serial_number, public.terminals.serial_number),
    manufacturer = coalesce(excluded.manufacturer, public.terminals.manufacturer),
    model = coalesce(excluded.model, public.terminals.model);

  update security.terminal_tokens
  set revoked_at = now()
  where terminal_id = p_terminal_id
    and token_hash <> p_token_hash
    and revoked_at is null;

  insert into security.terminal_tokens (
    terminal_id, token_hash, token_prefix, label, created_at, last_used_at, revoked_at
  )
  values (
    p_terminal_id, p_token_hash, p_token_prefix,
    'Machine self-enrollment', now(), now(), null
  )
  on conflict (token_hash) do update set
    terminal_id = excluded.terminal_id,
    token_prefix = excluded.token_prefix,
    label = excluded.label,
    last_used_at = now(),
    revoked_at = null;

  update public.machine_enrollment_requests
  set status = 'completed',
      completed_at = coalesce(completed_at, now()),
      last_seen_at = now()
  where request_id = p_request_id;

  insert into public.endpoint_audit_log (
    terminal_id, action, details
  )
  values (
    p_terminal_id,
    'machine_self_enrolled',
    jsonb_build_object('request_id', p_request_id)
  );

  return true;
end;
$$;

revoke all on function public.complete_machine_enrollment(uuid,text,text,text,text,text,text,text,text)
  from public, anon, authenticated;
grant execute on function public.complete_machine_enrollment(uuid,text,text,text,text,text,text,text,text)
  to service_role;
