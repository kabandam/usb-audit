-- Dedicated Smart Console management commands; retain every pre-existing command type.
-- Both commands are restricted to the existing authenticated admin Edge Function.
alter table public.endpoint_commands drop constraint if exists endpoint_commands_command_type_check;
alter table public.endpoint_commands add constraint endpoint_commands_command_type_check check (
  command_type = any (array[
    'inventory'::text, 'restart'::text, 'shutdown'::text,
    'install_software'::text, 'uninstall_software'::text, 'sync_policy'::text,
    'remote_support'::text, 'deploy_application'::text,
    'verify_application_package'::text, 'set_connection_password'::text,
    'request_location'::text, 'force_update'::text, 'cloud_sync'::text
  ])
);
