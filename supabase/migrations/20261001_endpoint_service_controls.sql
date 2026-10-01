-- Endpoint-level service controls for Smart Console.
alter table public.terminals
  add column if not exists usb_audit_enabled boolean not null default true,
  add column if not exists network_service_enabled boolean not null default true,
  add column if not exists location_service_enabled boolean not null default true,
  add column if not exists inventory_service_enabled boolean not null default true,
  add column if not exists deployment_service_enabled boolean not null default true,
  add column if not exists software_control_service_enabled boolean not null default true,
  add column if not exists remote_support_service_enabled boolean not null default true,
  add column if not exists service_policy_updated_at timestamptz,
  add column if not exists service_policy_updated_by uuid;

-- Existing managed endpoints retain their current behaviour. New enrollments start
-- with USB Audit off until IT explicitly designates the endpoint that needs it.
alter table public.terminals alter column usb_audit_enabled set default false;

create index if not exists terminals_usb_audit_enabled_idx
  on public.terminals (usb_audit_enabled)
  where enrollment_status = 'active';

comment on column public.terminals.usb_audit_enabled is
  'Whether the endpoint runs USB removable-media activity monitoring.';
comment on column public.terminals.network_service_enabled is
  'Per-endpoint Network Track service switch; global Resource Guard can still throttle/disable telemetry.';
comment on column public.terminals.location_service_enabled is
  'Per-endpoint precise location telemetry switch.';
comment on column public.terminals.inventory_service_enabled is
  'Per-endpoint hardware/software inventory service switch.';
comment on column public.terminals.deployment_service_enabled is
  'Whether application deployment commands may be delivered to this endpoint.';
comment on column public.terminals.software_control_service_enabled is
  'Whether application allow/block policy enforcement is active on this endpoint.';
comment on column public.terminals.remote_support_service_enabled is
  'Whether remote-support commands may be delivered to this endpoint.';
