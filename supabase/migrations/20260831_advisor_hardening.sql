create index if not exists enrollment_codes_created_by_idx on security.terminal_enrollment_codes(created_by);
create index if not exists enrollment_codes_claimed_terminal_idx on security.terminal_enrollment_codes(claimed_by_terminal)
  where claimed_by_terminal is not null;

create policy "No direct token access" on security.terminal_tokens for all to public using (false) with check (false);
create policy "No direct enrollment access" on security.terminal_enrollment_codes for all to public using (false) with check (false);
