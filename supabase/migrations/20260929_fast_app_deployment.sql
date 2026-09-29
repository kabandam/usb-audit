-- Faster, safer unattended application deployment.

alter table public.deployment_apps
  add column if not exists install_timeout_minutes integer not null default 15
    check (install_timeout_minutes between 5 and 60);
