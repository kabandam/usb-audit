-- Allow uploaded OneDrive packages to appear in the catalog before hash recovery.

alter table public.deployment_apps
  alter column sha256 drop not null;
