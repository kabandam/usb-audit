-- Add Data Centre OneDrive package storage to Smart Console App Deployment

alter table public.deployment_apps
  alter column package_url drop not null;

alter table public.deployment_apps
  add column if not exists storage_provider text not null default 'https'
    check (storage_provider in ('https','onedrive')),
  add column if not exists storage_drive_id text,
  add column if not exists storage_item_id text,
  add column if not exists storage_web_url text,
  add column if not exists storage_file_name text,
  add column if not exists file_size_bytes bigint,
  add column if not exists package_type text not null default 'exe'
    check (package_type in ('msi','exe','zip')),
  add column if not exists installer_entry text,
  add column if not exists metadata_confidence text not null default 'manual'
    check (metadata_confidence in ('detected','confirm','manual'));

alter table public.deployment_apps
  drop constraint if exists deployment_apps_package_source_check;

alter table public.deployment_apps
  add constraint deployment_apps_package_source_check check (
    (storage_provider='https' and package_url is not null and package_url ~ '^https://')
    or
    (storage_provider='onedrive' and storage_drive_id is not null and storage_item_id is not null)
  );
