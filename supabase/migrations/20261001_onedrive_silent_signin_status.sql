alter table public.endpoint_onedrive_status
  add column if not exists entra_joined boolean,
  add column if not exists windows_user_upn text,
  add column if not exists expected_user_email text,
  add column if not exists account_match boolean,
  add column if not exists silent_signin_enabled boolean;
