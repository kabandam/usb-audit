-- Add endpoint-side package verification for application deployment.

alter table public.deployment_apps
  add column if not exists verification_status text not null default 'pending'
    check (verification_status in ('pending','queued','verifying','verified','failed')),
  add column if not exists verification_message text,
  add column if not exists last_verification_requested_at timestamptz;

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
      'deploy_application'::text,
      'verify_application_package'::text
    ])
  );
