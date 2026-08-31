create table if not exists public.terminals (
  terminal_id text primary key,
  computer_name text not null,
  windows_user text,
  app_version text,
  first_seen_at timestamptz not null default now(),
  last_seen_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.terminal_tokens (
  terminal_id text primary key references public.terminals(terminal_id) on delete cascade,
  token_hash text not null unique,
  label text,
  created_at timestamptz not null default now(),
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
  total_size_bytes bigint,
  available_free_space_bytes bigint,
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
  file_size_bytes bigint,
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

alter table public.terminals enable row level security;
alter table public.terminal_devices enable row level security;
alter table public.audit_events enable row level security;
alter table public.terminal_tokens enable row level security;

create policy "Authenticated users can view terminals"
  on public.terminals for select
  to authenticated
  using (true);

create policy "Authenticated users can view connected devices"
  on public.terminal_devices for select
  to authenticated
  using (true);

create policy "Authenticated users can view audit events"
  on public.audit_events for select
  to authenticated
  using (true);

comment on table public.terminal_tokens is 'Per-terminal enrollment tokens stored only as SHA-256 hashes. Access is service-role only.';
comment on table public.audit_events is 'Central metadata-only USB audit evidence uploaded by installed Windows terminals.';
