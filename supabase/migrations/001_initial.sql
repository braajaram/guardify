create extension if not exists pgcrypto;
create table if not exists profiles (id uuid primary key references auth.users(id) on delete cascade, display_name text, created_at timestamptz not null default now());
create table if not exists scans (id uuid primary key default gen_random_uuid(), user_id uuid not null references auth.users(id) on delete cascade, scan_type text not null check (scan_type in ('url','file','email')), verdict text not null check (verdict in ('SAFE','SUSPICIOUS','DANGEROUS','UNKNOWN')), sha256 text not null, created_at timestamptz not null default now());
create index if not exists scans_user_created_idx on scans(user_id, created_at desc);
alter table profiles enable row level security;
alter table scans enable row level security;
create policy profiles_owner on profiles for all using (auth.uid() = id) with check (auth.uid() = id);
create policy scans_owner on scans for all using (auth.uid() = user_id) with check (auth.uid() = user_id);
