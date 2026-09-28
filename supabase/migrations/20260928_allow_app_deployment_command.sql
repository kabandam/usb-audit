-- Allow Smart Console application deployment commands.

alter table public.endpoint_commands
  drop constraint if exists endpoint_commands_command_type_check;

alter table public.endpoint_commands
  add constraint endpoint_commands_command_type_check check (
    command_type = any (array[
      'inventory'::text,
      'restart'::text,
      'shutdown'::text,
      'install_software'::text,
      'uninstall_software'::text,
      'sync_policy'::text,
      'remote_support'::text,
      'deploy_application'::text
    ])
  );
