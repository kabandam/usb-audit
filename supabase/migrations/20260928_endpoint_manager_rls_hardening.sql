-- CRECCOM Security Console - Endpoint Manager RLS hardening
-- Ensures the Endpoint Manager tables use the same approved-console-user
-- authorization boundary as USB Audit instead of allowing every authenticated user.

begin;

drop policy if exists "authenticated read installed software" on public.installed_software;
drop policy if exists "authenticated read policies" on public.endpoint_policies;
drop policy if exists "authenticated read assignments" on public.terminal_policy_assignments;
drop policy if exists "authenticated read commands" on public.endpoint_commands;
drop policy if exists "authenticated read endpoint audit" on public.endpoint_audit_log;

create policy "Approved console users can view installed software"
  on public.installed_software
  for select
  to authenticated
  using ((select security.is_creccom_user()));

create policy "Approved console users can view endpoint policies"
  on public.endpoint_policies
  for select
  to authenticated
  using ((select security.is_creccom_user()));

create policy "Approved console users can view policy assignments"
  on public.terminal_policy_assignments
  for select
  to authenticated
  using ((select security.is_creccom_user()));

create policy "Approved console users can view endpoint commands"
  on public.endpoint_commands
  for select
  to authenticated
  using ((select security.is_creccom_user()));

create policy "Approved console users can view endpoint audit log"
  on public.endpoint_audit_log
  for select
  to authenticated
  using ((select security.is_creccom_user()));

revoke all on public.installed_software,
  public.endpoint_policies,
  public.terminal_policy_assignments,
  public.endpoint_commands,
  public.endpoint_audit_log
from anon;

grant select on public.installed_software,
  public.endpoint_policies,
  public.terminal_policy_assignments,
  public.endpoint_commands,
  public.endpoint_audit_log
to authenticated;

commit;
