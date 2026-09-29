-- Support silent and visible/user-assisted application installation.

alter table public.deployment_apps
  add column if not exists install_mode text not null default 'silent'
    check (install_mode in ('silent','visible'));
