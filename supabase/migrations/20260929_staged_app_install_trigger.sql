-- Download-first application deployment with optional local install from Smart Console.

alter table public.deployment_apps
  add column if not exists install_trigger text not null default 'auto'
    check (install_trigger in ('auto','manual'));
