-- Smart Console application deployment module

create table if not exists public.endpoint_groups (
  group_id uuid primary key default gen_random_uuid(),
  name text not null unique,
  description text,
  created_by uuid references auth.users(id),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.endpoint_group_members (
  group_id uuid not null references public.endpoint_groups(group_id) on delete cascade,
  terminal_id text not null references public.terminals(terminal_id) on delete cascade,
  created_at timestamptz not null default now(),
  primary key (group_id, terminal_id)
);

create table if not exists public.deployment_apps (
  app_id uuid primary key default gen_random_uuid(),
  name text not null,
  version text not null,
  publisher text,
  installer_type text not null check (installer_type in ('msi','exe')),
  package_url text not null check (package_url ~ '^https://'),
  sha256 text not null check (sha256 ~ '^[0-9A-Fa-f]{64}$'),
  install_args text not null default '',
  success_codes integer[] not null default array[0,1641,3010],
  notes text,
  is_active boolean not null default true,
  created_by uuid references auth.users(id),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (name, version)
);

create table if not exists public.deployment_batches (
  batch_id uuid primary key default gen_random_uuid(),
  name text not null,
  requested_by uuid references auth.users(id),
  requested_at timestamptz not null default now(),
  app_count integer not null default 0,
  terminal_count integer not null default 0,
  status text not null default 'queued'
    check (status in ('queued','in_progress','completed','partial','failed','cancelled'))
);

create table if not exists public.deployment_tasks (
  task_id uuid primary key default gen_random_uuid(),
  batch_id uuid not null references public.deployment_batches(batch_id) on delete cascade,
  app_id uuid not null references public.deployment_apps(app_id),
  terminal_id text not null references public.terminals(terminal_id) on delete cascade,
  sequence_no integer not null default 0,
  command_id uuid references public.endpoint_commands(command_id) on delete set null,
  status text not null default 'pending'
    check (status in ('pending','acknowledged','completed','failed','cancelled')),
  message text,
  requested_at timestamptz not null default now(),
  completed_at timestamptz,
  unique (batch_id, app_id, terminal_id)
);

create index if not exists endpoint_group_members_terminal_idx
  on public.endpoint_group_members(terminal_id);
create index if not exists deployment_tasks_batch_idx
  on public.deployment_tasks(batch_id, status);
create index if not exists deployment_tasks_terminal_idx
  on public.deployment_tasks(terminal_id, status);
create index if not exists deployment_tasks_command_idx
  on public.deployment_tasks(command_id);

alter table public.endpoint_groups enable row level security;
alter table public.endpoint_group_members enable row level security;
alter table public.deployment_apps enable row level security;
alter table public.deployment_batches enable row level security;
alter table public.deployment_tasks enable row level security;

drop policy if exists "Approved console users can view endpoint groups" on public.endpoint_groups;
create policy "Approved console users can view endpoint groups"
  on public.endpoint_groups for select to authenticated
  using ((select security.is_creccom_user()));

drop policy if exists "Approved console users can view endpoint group members" on public.endpoint_group_members;
create policy "Approved console users can view endpoint group members"
  on public.endpoint_group_members for select to authenticated
  using ((select security.is_creccom_user()));

drop policy if exists "Approved console users can view deployment apps" on public.deployment_apps;
create policy "Approved console users can view deployment apps"
  on public.deployment_apps for select to authenticated
  using ((select security.is_creccom_user()));

drop policy if exists "Approved console users can view deployment batches" on public.deployment_batches;
create policy "Approved console users can view deployment batches"
  on public.deployment_batches for select to authenticated
  using ((select security.is_creccom_user()));

drop policy if exists "Approved console users can view deployment tasks" on public.deployment_tasks;
create policy "Approved console users can view deployment tasks"
  on public.deployment_tasks for select to authenticated
  using ((select security.is_creccom_user()));

revoke all on public.endpoint_groups, public.endpoint_group_members, public.deployment_apps,
  public.deployment_batches, public.deployment_tasks from anon, authenticated;
grant select on public.endpoint_groups, public.endpoint_group_members, public.deployment_apps,
  public.deployment_batches, public.deployment_tasks to authenticated;
