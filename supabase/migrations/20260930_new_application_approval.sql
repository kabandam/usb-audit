-- Grandfather already inventoried applications. New distinct software requires approval.
alter table public.software_control_rules add column if not exists source text not null default 'manual';
alter table public.software_control_rules drop constraint if exists software_control_rules_source_check;
alter table public.software_control_rules add constraint software_control_rules_source_check
 check (source in ('manual','approval'));

create table if not exists public.software_approvals (
 terminal_id text not null references public.terminals(terminal_id) on delete cascade,
 software_key text not null,
 name text not null,
 version text,
 publisher text,
 status text not null default 'pending' check (status in ('pending','approved','denied')),
 first_detected_at timestamptz not null default now(),
 decided_at timestamptz,
 decided_by uuid references auth.users(id),
 decision_reason text,
 primary key (terminal_id,software_key)
);
create index if not exists software_approvals_status_idx on public.software_approvals(status,first_detected_at desc);
alter table public.software_approvals enable row level security;
drop policy if exists "Console members read software approvals" on public.software_approvals;
create policy "Console members read software approvals" on public.software_approvals
 for select to authenticated using ((select security.is_creccom_user()));
revoke all on public.software_approvals from anon,authenticated;
grant select on public.software_approvals to authenticated;
insert into public.software_approvals
 (terminal_id,software_key,name,version,publisher,status,first_detected_at,decision_reason)
select terminal_id,software_key,name,version,publisher,'approved',first_seen_at,'Pre-existing application baseline'
from public.installed_software
on conflict (terminal_id,software_key) do nothing;
