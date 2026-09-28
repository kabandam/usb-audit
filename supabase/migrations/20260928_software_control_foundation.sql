-- CRECCOM Security Console: software control foundation

alter table public.installed_software
  add column if not exists executable_paths jsonb not null default '[]'::jsonb;

create table if not exists public.software_control_rules (
  rule_id uuid primary key default gen_random_uuid(),
  terminal_id text not null references public.terminals(terminal_id) on delete cascade,
  software_key text not null,
  software_name text not null,
  publisher text,
  install_location text,
  executable_paths jsonb not null default '[]'::jsonb,
  action text not null default 'block' check (action in ('block')),
  is_active boolean not null default true,
  created_by uuid references auth.users(id),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (terminal_id, software_key)
);

create index if not exists software_control_rules_terminal_idx
  on public.software_control_rules(terminal_id, is_active);

create index if not exists software_control_rules_software_idx
  on public.software_control_rules(software_key, is_active);

alter table public.software_control_rules enable row level security;

drop policy if exists "Approved console users can view software control rules" on public.software_control_rules;
create policy "Approved console users can view software control rules"
  on public.software_control_rules
  for select
  to authenticated
  using ((select security.is_creccom_user()));

revoke all on public.software_control_rules from anon;
grant select on public.software_control_rules to authenticated;
