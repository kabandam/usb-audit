create schema if not exists security;

create table if not exists public.terminals (
  terminal_id text primary key,
  computer_name text not null,
  windows_user text,
  app_version text,
  enrollment_status text not null default 'active' check (enrollment_status in ('active', 'revoked')),
  first_seen_at timestamptz not null default now(),
  last_seen_at timestamptz not null default now(),
  last_ip inet,
  last_error text,
  updated_at timestamptz not null default now()
);

create table if not exists security.terminal_tokens (
  token_id uuid primary key default gen_random_uuid(),
  terminal_id text not null references public.terminals(terminal_id) on delete cascade,
  token_hash text not null unique,
  token_prefix text not null,
  label text,
  created_at timestamptz not null default now(),
  last_used_at timestamptz,
  expires_at timestamptz,
  revoked_at timestamptz
);

create table if not exists security.terminal_enrollment_codes (
  enrollment_id uuid primary key default gen_random_uuid(),
  code_hash text not null unique,
  code_prefix text not null,
  label text,
  created_by uuid not null references auth.users(id),
  created_at timestamptz not null default now(),
  expires_at timestamptz not null,
  claimed_at timestamptz,
  claimed_by_terminal text references public.terminals(terminal_id),
  revoked_at timestamptz
);

create table if not exists public.terminal_devices (
  terminal_id text not null references public.terminals(terminal_id) on delete cascade,
  device_key text not null,
  drive_letter text,
  device_name text,
  device_serial text,
  volume_label text,
  file_system text,
  total_size_bytes bigint check (total_size_bytes is null or total_size_bytes >= 0),
  available_free_space_bytes bigint check (available_free_space_bytes is null or available_free_space_bytes >= 0),
  connected_at timestamptz,
  updated_at timestamptz not null default now(),
  primary key (terminal_id, device_key)
);

create table if not exists public.audit_events (
  event_id text primary key,
  terminal_id text not null references public.terminals(terminal_id) on delete cascade,
  timestamp timestamptz not null,
  kind text not null,
  direction text,
  windows_user text,
  computer_name text,
  device_name text,
  device_serial text,
  drive_letter text,
  volume_label text,
  file_name text,
  file_path text,
  source_path text,
  destination_path text,
  file_size_bytes bigint check (file_size_bytes is null or file_size_bytes >= 0),
  sha256 text,
  archive_copy_created boolean not null default false,
  evidence text,
  notes text,
  previous_record_hash text,
  record_hash text,
  received_at timestamptz not null default now()
);

create index if not exists audit_events_timestamp_idx on public.audit_events(timestamp desc);
create index if not exists audit_events_terminal_timestamp_idx on public.audit_events(terminal_id, timestamp desc);
create index if not exists audit_events_direction_idx on public.audit_events(direction, timestamp desc);
create index if not exists audit_events_device_serial_idx on public.audit_events(device_serial) where device_serial is not null;
create index if not exists terminals_last_seen_idx on public.terminals(last_seen_at desc);
create index if not exists terminal_tokens_terminal_idx on security.terminal_tokens(terminal_id) where revoked_at is null;
create index if not exists enrollment_codes_expiry_idx on security.terminal_enrollment_codes(expires_at) where claimed_at is null and revoked_at is null;

create or replace function security.is_creccom_user()
returns boolean language sql stable security invoker set search_path = '' as $$
  select coalesce(lower(auth.jwt() ->> 'email') like '%@creccommw.org', false)
$$;

create or replace function security.claim_terminal_enrollment(
  p_code_hash text, p_token_hash text, p_token_prefix text, p_terminal_id text,
  p_computer_name text, p_windows_user text, p_app_version text
)
returns boolean language plpgsql security definer set search_path = '' as $$
declare v_enrollment_id uuid;
begin
  select enrollment_id into v_enrollment_id from security.terminal_enrollment_codes
  where code_hash = p_code_hash and claimed_at is null and revoked_at is null and expires_at > now()
  for update skip locked;
  if v_enrollment_id is null then return false; end if;

  insert into public.terminals (terminal_id, computer_name, windows_user, app_version)
  values (p_terminal_id, p_computer_name, nullif(p_windows_user, ''), nullif(p_app_version, ''))
  on conflict (terminal_id) do update set computer_name = excluded.computer_name,
    windows_user = excluded.windows_user, app_version = excluded.app_version,
    enrollment_status = 'active', updated_at = now();
  insert into security.terminal_tokens (terminal_id, token_hash, token_prefix, label)
  values (p_terminal_id, p_token_hash, p_token_prefix, 'Initial enrollment');
  update security.terminal_enrollment_codes set claimed_at = now(), claimed_by_terminal = p_terminal_id
  where enrollment_id = v_enrollment_id;
  return true;
end;
$$;

revoke all on schema security from public, anon, authenticated;
grant usage on schema security to service_role;
grant execute on function security.claim_terminal_enrollment(text,text,text,text,text,text,text) to service_role;
revoke all on function security.claim_terminal_enrollment(text,text,text,text,text,text,text) from public, anon, authenticated;

alter table public.terminals enable row level security;
alter table public.terminal_devices enable row level security;
alter table public.audit_events enable row level security;
alter table security.terminal_tokens enable row level security;
alter table security.terminal_enrollment_codes enable row level security;

create policy "CRECCOM users can view terminals" on public.terminals for select to authenticated using ((select security.is_creccom_user()));
create policy "CRECCOM users can view connected devices" on public.terminal_devices for select to authenticated using ((select security.is_creccom_user()));
create policy "CRECCOM users can view audit events" on public.audit_events for select to authenticated using ((select security.is_creccom_user()));

grant select on public.terminals, public.terminal_devices, public.audit_events to authenticated;
revoke all on security.terminal_tokens, security.terminal_enrollment_codes from anon, authenticated;

comment on schema security is 'Private security-console secrets and privileged routines; not exposed through the Data API.';
comment on table security.terminal_tokens is 'Per-terminal bearer tokens stored only as SHA-256 hashes.';
comment on table security.terminal_enrollment_codes is 'Short-lived, one-time terminal enrollment codes stored only as SHA-256 hashes.';
comment on table public.audit_events is 'Central metadata-only USB audit evidence uploaded by installed Windows terminals.';
