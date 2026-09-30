-- Network Track: current status and change-only history of enrolled endpoints.
-- IP-derived coordinates are approximate; no precise GPS collection.
create table if not exists public.endpoint_network_status (
 terminal_id text primary key references public.terminals(terminal_id) on delete cascade,
 network_name text, connection_type text, adapter_name text,
 local_ip inet, mac_address text, gateway_ip inet, dns_servers text[] not null default '{}',
 link_speed_mbps numeric(12,2) check (link_speed_mbps is null or link_speed_mbps >= 0),
 public_ip inet, service_provider text,
 geo_city text, geo_region text, geo_country text,
 geo_latitude numeric(9,6), geo_longitude numeric(9,6),
 geo_accuracy text not null default 'not_available' check (geo_accuracy in ('not_available','approximate_ip')),
 observed_at timestamptz not null default now(),
 changed_at timestamptz not null default now()
);
create table if not exists public.endpoint_network_history (
 id bigint generated always as identity primary key,
 terminal_id text not null references public.terminals(terminal_id) on delete cascade,
 network_name text, connection_type text, adapter_name text,
 local_ip inet, mac_address text, gateway_ip inet,
 link_speed_mbps numeric(12,2), public_ip inet,
 service_provider text, geo_city text, geo_region text, geo_country text,
 change_reason text not null default 'network_changed',
 observed_at timestamptz not null default now()
);
create index if not exists endpoint_network_history_terminal_at_idx
 on public.endpoint_network_history(terminal_id, observed_at desc);
create index if not exists endpoint_network_history_at_idx
 on public.endpoint_network_history(observed_at desc);
alter table public.endpoint_network_status enable row level security;
alter table public.endpoint_network_history enable row level security;
drop policy if exists "Approved console users view network status" on public.endpoint_network_status;
create policy "Approved console users view network status" on public.endpoint_network_status
 for select to authenticated using ((select security.is_creccom_user()));
drop policy if exists "Approved console users view network changes" on public.endpoint_network_history;
create policy "Approved console users view network changes" on public.endpoint_network_history
 for select to authenticated using ((select security.is_creccom_user()));
revoke all on public.endpoint_network_status, public.endpoint_network_history from anon, authenticated;
grant select on public.endpoint_network_status, public.endpoint_network_history to authenticated;
comment on table public.endpoint_network_status is 'Endpoint networking, public IP and approximate IP-based location. No silent GPS collection.';
comment on table public.endpoint_network_history is 'Change-only network history; apply organization data-retention policy.';