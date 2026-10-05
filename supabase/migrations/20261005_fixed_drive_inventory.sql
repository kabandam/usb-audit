-- Internal fixed-drive inventory reported by Smart Console Agent.
alter table public.terminals
  add column if not exists fixed_drives jsonb not null default '[]'::jsonb,
  add column if not exists system_drive_letter text,
  add column if not exists system_drive_total_bytes bigint,
  add column if not exists system_drive_free_bytes bigint;

alter table public.terminals
  drop constraint if exists terminals_system_drive_total_bytes_check,
  add constraint terminals_system_drive_total_bytes_check
    check (system_drive_total_bytes is null or system_drive_total_bytes >= 0),
  drop constraint if exists terminals_system_drive_free_bytes_check,
  add constraint terminals_system_drive_free_bytes_check
    check (system_drive_free_bytes is null or system_drive_free_bytes >= 0),
  drop constraint if exists terminals_system_drive_free_not_gt_total_check,
  add constraint terminals_system_drive_free_not_gt_total_check
    check (
      system_drive_total_bytes is null
      or system_drive_free_bytes is null
      or system_drive_free_bytes <= system_drive_total_bytes
    );

comment on column public.terminals.fixed_drives is
  'Fixed/internal drive inventory reported by the Smart Console Agent.';
comment on column public.terminals.system_drive_letter is
  'Windows system drive, normally C:.';
comment on column public.terminals.system_drive_total_bytes is
  'Total capacity of the Windows system drive.';
comment on column public.terminals.system_drive_free_bytes is
  'Available free space on the Windows system drive.';
