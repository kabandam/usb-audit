create or replace function security.is_creccom_user()
returns boolean language sql stable security invoker set search_path = '' as $$
  select coalesce(lower(auth.jwt() ->> 'email') = 'martinkabanda@creccommw.org', false)
$$;
