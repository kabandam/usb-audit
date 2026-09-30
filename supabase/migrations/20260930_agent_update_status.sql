-- Agent-managed update visibility, separated from heartbeat for old-client compatibility.
create table if not exists public.endpoint_agent_update_status (
 terminal_id text primary key references public.terminals(terminal_id) on delete cascade,
 current_version text,
 latest_version text,
 state text not null default 'Not checked',
 message text,
 last_checked_at timestamptz,
 reported_at timestamptz not null default now()
);
create index if not exists endpoint_agent_update_status_reported_idx on public.endpoint_agent_update_status(reported_at desc);
alter table public.endpoint_agent_update_status enable row level security;
drop policy if exists "Approved console users view agent update health" on public.endpoint_agent_update_status;
create policy "Approved console users view agent update health"
 on public.endpoint_agent_update_status for select to authenticated
 using ((select security.is_creccom_user()));
revoke all on public.endpoint_agent_update_status from anon, authenticated;
grant select on public.endpoint_agent_update_status to authenticated;
comment on table public.endpoint_agent_update_status is 'Approved release check and installation diagnostics uploaded by upgraded agents. Legacy agents report no update status.';
