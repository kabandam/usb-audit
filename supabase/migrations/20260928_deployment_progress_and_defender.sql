-- Add per-endpoint application deployment progress, retries and Defender verification.

alter table public.deployment_tasks
  add column if not exists progress_percent integer not null default 0
    check (progress_percent between 0 and 100),
  add column if not exists progress_stage text not null default 'queued',
  add column if not exists progress_message text,
  add column if not exists attempt_count integer not null default 1
    check (attempt_count >= 1),
  add column if not exists last_progress_at timestamptz not null default now(),
  add column if not exists started_at timestamptz,
  add column if not exists defender_scan_status text;

alter table public.deployment_apps
  add column if not exists last_defender_verified_at timestamptz,
  add column if not exists last_defender_verified_terminal_id text;

do $$
begin
  if not exists (
    select 1 from pg_publication_tables
    where pubname='supabase_realtime'
      and schemaname='public'
      and tablename='deployment_tasks'
  ) then
    alter publication supabase_realtime add table public.deployment_tasks;
  end if;
end $$;
