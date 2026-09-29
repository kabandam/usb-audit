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
