-- Baseline: the early-access table already exists in the linked project
-- (created from supabase/early_access_requests.sql). This migration adopts it
-- into version control without changing behaviour: every statement is
-- idempotent, and the insert-only policy is re-asserted, not replaced.
--
-- Rollback: intentionally a no-op. Dropping this table would destroy real
-- submissions; if it ever has to go, do it by hand with a backup.

create extension if not exists "pgcrypto";

create table if not exists public.early_access_requests (
  id uuid primary key default gen_random_uuid(),
  name text not null check (char_length(name) between 2 and 100),
  email text not null check (position('@' in email) > 1),
  build_type text check (build_type is null or char_length(build_type) <= 80),
  project_description text check (
    project_description is null or char_length(project_description) <= 2000
  ),
  source text not null default 'vibecheck-website',
  created_at timestamptz not null default now()
);

create index if not exists early_access_requests_created_at_idx
  on public.early_access_requests (created_at desc);

alter table public.early_access_requests enable row level security;

drop policy if exists "early access: anonymous insert" on public.early_access_requests;
create policy "early access: anonymous insert"
  on public.early_access_requests
  for insert
  to anon, authenticated
  with check (true);

-- No select/update/delete policy on purpose.
