-- CRECCOM Endpoint Manager foundation
-- Adds endpoint inventory, installed software, policy definitions and auditable command queue.

alter table if exists public.terminals
  add column if not exists os_name text,
  add column if not exists os_version text,
  add column if not exists manufacturer text,
  add column if not exists model text,
  add column if not exists serial_number text,
  add column if not exists total_memory_bytes bigint,
  add column if not exists processor_name text,
  add column if not exists defender_status text,
  add column if not exists firewall_enabled boolean,
  add column if not exists inventory_at timestamptz;

create table if not exists public.installed_software (
  terminal_id text not null references public.terminals(terminal_id) on delete cascade,
  software_key text not null,
  name text not null,
  version text,
  publisher text,
  install_location text,
  first_seen_at timestamptz not null default now(),
  last_seen_at timestamptz not null default now(),
  primary key (terminal_id, software_key)
);

create index if not exists installed_software_name_idx on public.installed_software(lower(name));
create index if not exists installed_software_terminal_idx on public.installed_software(terminal_id);

create table if not exists public.endpoint_policies (
  policy_id uuid primary key default gen_random_uuid(),
  name text not null,
  description text,
  mode text not null default 'audit' check (mode in ('audit','enforce')),
  is_default boolean not null default false,
  rules jsonb not null default '{"software":{"allow":[],"block":[]},"usb":{"mode":"monitor"}}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.terminal_policy_assignments (
  terminal_id text primary key references public.terminals(terminal_id) on delete cascade,
  policy_id uuid not null references public.endpoint_policies(policy_id) on delete restrict,
  assigned_at timestamptz not null default now(),
  assigned_by uuid references auth.users(id)
);

create table if not exists public.endpoint_commands (
  command_id uuid primary key default gen_random_uuid(),
  terminal_id text not null references public.terminals(terminal_id) on delete cascade,
  command_type text not null check (command_type in ('inventory','restart','shutdown','install_software','uninstall_software','sync_policy','remote_support')),
  payload jsonb not null default '{}'::jsonb,
  status text not null default 'pending' check (status in ('pending','acknowledged','running','completed','failed','cancelled')),
  requested_by uuid references auth.users(id),
  requested_at timestamptz not null default now(),
  acknowledged_at timestamptz,
  completed_at timestamptz,
  result jsonb
);

create index if not exists endpoint_commands_terminal_status_idx on public.endpoint_commands(terminal_id, status, requested_at desc);

create table if not exists public.endpoint_audit_log (
  audit_id bigint generated always as identity primary key,
  actor_user_id uuid references auth.users(id),
  terminal_id text references public.terminals(terminal_id) on delete set null,
  action text not null,
  details jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

alter table public.installed_software enable row level security;
alter table public.endpoint_policies enable row level security;
alter table public.terminal_policy_assignments enable row level security;
alter table public.endpoint_commands enable row level security;
alter table public.endpoint_audit_log enable row level security;

-- Console users are authenticated through Microsoft. Service-role ingestion bypasses RLS.
do $$ begin
  create policy "authenticated read installed software" on public.installed_software for select to authenticated using (true);
exception when duplicate_object then null; end $$;
do $$ begin
  create policy "authenticated read policies" on public.endpoint_policies for select to authenticated using (true);
exception when duplicate_object then null; end $$;
do $$ begin
  create policy "authenticated read assignments" on public.terminal_policy_assignments for select to authenticated using (true);
exception when duplicate_object then null; end $$;
do $$ begin
  create policy "authenticated read commands" on public.endpoint_commands for select to authenticated using (true);
exception when duplicate_object then null; end $$;
do $$ begin
  create policy "authenticated read endpoint audit" on public.endpoint_audit_log for select to authenticated using (true);
exception when duplicate_object then null; end $$;

insert into public.endpoint_policies(name, description, mode, is_default, rules)
select
  'CRECCOM Standard',
  'Initial endpoint policy. Starts in audit mode so software is inventoried and evaluated before enforcement is enabled.',
  'audit',
  true,
  '{"software":{"allow":[],"block":[]},"usb":{"mode":"monitor"},"security":{"requireDefender":true,"requireFirewall":true}}'::jsonb
where not exists (select 1 from public.endpoint_policies where is_default = true);
