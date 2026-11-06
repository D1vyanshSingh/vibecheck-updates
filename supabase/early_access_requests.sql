-- Early-access requests for vibecheck.dev
-- Run this once in the Supabase SQL editor for your project.
--
-- Design notes:
--   * RLS is enabled with an INSERT-only policy. There is deliberately no
--     SELECT / UPDATE / DELETE policy, so the public key cannot read, change
--     or remove submissions.
--   * Column names match the insert in app/api/early-access/route.ts.

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

-- Makes "newest first" listings cheap in the Supabase table editor.
create index if not exists early_access_requests_created_at_idx
  on public.early_access_requests (created_at desc);

alter table public.early_access_requests enable row level security;

-- Insert-only for the public/anon key used server-side by the form.
drop policy if exists "early access: anonymous insert" on public.early_access_requests;
create policy "early access: anonymous insert"
  on public.early_access_requests
  for insert
  to anon, authenticated
  with check (true);

-- No select/update/delete policies on purpose:
-- reading the list requires the service role or the Supabase dashboard.
