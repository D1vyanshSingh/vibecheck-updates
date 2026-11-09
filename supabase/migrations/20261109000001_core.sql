-- VibeCheck core schema.
--
-- Design rules enforced here:
--   * Every customer-owned table carries workspace_id and has RLS enabled.
--   * Reads are allowed only to workspace members.
--   * Writes are allowed only to roles that can perform them.
--   * The scanner worker uses the service role, which bypasses RLS by design;
--     it is never used by a browser request.
--
-- Rollback: see 20261109000001_core.down.sql

create extension if not exists "pgcrypto";

/* ------------------------------------------------------------------ helpers */

create or replace function public.touch_updated_at()
returns trigger
language plpgsql
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

create or replace function public.is_workspace_member(ws uuid)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1 from public.workspace_members m
    where m.workspace_id = ws and m.user_id = auth.uid()
  );
$$;

create or replace function public.workspace_role(ws uuid)
returns text
language sql
stable
security definer
set search_path = public
as $$
  select m.role from public.workspace_members m
  where m.workspace_id = ws and m.user_id = auth.uid()
  limit 1;
$$;

create or replace function public.has_workspace_role(ws uuid, allowed text[])
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select coalesce(public.workspace_role(ws) = any(allowed), false);
$$;

/* --------------------------------------------------------------- workspaces */

create table if not exists public.workspaces (
  id uuid primary key default gen_random_uuid(),
  name text not null check (char_length(name) between 2 and 80),
  slug text not null check (slug ~ '^[a-z0-9-]{2,48}$'),
  kind text not null default 'personal' check (kind in ('personal', 'agency')),
  created_by uuid not null references auth.users (id) on delete cascade,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (created_by, slug)
);

create table if not exists public.workspace_members (
  id uuid primary key default gen_random_uuid(),
  workspace_id uuid not null references public.workspaces (id) on delete cascade,
  user_id uuid not null references auth.users (id) on delete cascade,
  email text,
  role text not null default 'viewer'
    check (role in ('owner', 'admin', 'analyst', 'developer', 'viewer')),
  created_at timestamptz not null default now(),
  unique (workspace_id, user_id)
);

create index if not exists workspace_members_user_idx
  on public.workspace_members (user_id);

create table if not exists public.workspace_invitations (
  id uuid primary key default gen_random_uuid(),
  workspace_id uuid not null references public.workspaces (id) on delete cascade,
  email text not null,
  role text not null check (role in ('admin', 'analyst', 'developer', 'viewer')),
  token text not null unique,
  invited_by uuid not null references auth.users (id) on delete cascade,
  expires_at timestamptz not null default now() + interval '7 days',
  accepted_at timestamptz,
  accepted_by uuid references auth.users (id) on delete set null,
  created_at timestamptz not null default now()
);

create index if not exists workspace_invitations_token_idx
  on public.workspace_invitations (token);

/* ----------------------------------------------------------------- projects */

create table if not exists public.projects (
  id uuid primary key default gen_random_uuid(),
  workspace_id uuid not null references public.workspaces (id) on delete cascade,
  name text not null check (char_length(name) between 2 and 120),
  description text,
  project_type text not null default 'web_app'
    check (project_type in ('web_app', 'api', 'full_stack', 'static_site', 'mobile_backend')),
  website_url text,
  repository_url text,
  tech_stack jsonb not null default '[]'::jsonb,
  created_by uuid not null references auth.users (id) on delete cascade,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists projects_workspace_idx
  on public.projects (workspace_id, created_at desc);

create table if not exists public.project_sources (
  id uuid primary key default gen_random_uuid(),
  workspace_id uuid not null references public.workspaces (id) on delete cascade,
  project_id uuid not null references public.projects (id) on delete cascade,
  kind text not null check (kind in ('zip', 'github', 'url')),
  label text,
  storage_path text,
  sha256 text,
  size_bytes bigint,
  file_count integer,
  branch text,
  commit_sha text,
  metadata jsonb,
  created_by uuid references auth.users (id) on delete set null,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null default now() + interval '30 days'
);

create index if not exists project_sources_project_idx
  on public.project_sources (project_id, created_at desc);

/* ------------------------------------------------------------ scans / jobs */

create table if not exists public.scans (
  id uuid primary key default gen_random_uuid(),
  workspace_id uuid not null references public.workspaces (id) on delete cascade,
  project_id uuid not null references public.projects (id) on delete cascade,
  source_id uuid references public.project_sources (id) on delete set null,
  user_id uuid references auth.users (id) on delete set null,
  trigger text not null default 'manual'
    check (trigger in ('manual', 'push', 'scheduled', 'verification')),
  status text not null default 'queued'
    check (status in ('queued', 'running', 'completed', 'failed', 'cancelled')),
  findings_total integer not null default 0,
  coverage jsonb,
  scanner_versions jsonb,
  error_message text,
  started_at timestamptz,
  completed_at timestamptz,
  created_at timestamptz not null default now()
);

create index if not exists scans_workspace_idx
  on public.scans (workspace_id, created_at desc);
create index if not exists scans_project_idx
  on public.scans (project_id, created_at desc);

create table if not exists public.scan_jobs (
  id uuid primary key default gen_random_uuid(),
  workspace_id uuid not null references public.workspaces (id) on delete cascade,
  scan_id uuid not null references public.scans (id) on delete cascade,
  kind text not null,
  status text not null default 'queued'
    check (status in ('queued', 'running', 'completed', 'failed', 'cancelled', 'skipped')),
  attempts integer not null default 0,
  locked_by text,
  locked_at timestamptz,
  started_at timestamptz,
  finished_at timestamptz,
  error_message text,
  output_ref text,
  created_at timestamptz not null default now()
);

create index if not exists scan_jobs_scan_idx on public.scan_jobs (scan_id);
create index if not exists scan_jobs_queue_idx
  on public.scan_jobs (status, created_at);

/* ---------------------------------------------------------------- findings */

create table if not exists public.findings (
  id uuid primary key default gen_random_uuid(),
  workspace_id uuid not null references public.workspaces (id) on delete cascade,
  project_id uuid not null references public.projects (id) on delete cascade,
  scan_id uuid references public.scans (id) on delete cascade,
  source_id uuid references public.project_sources (id) on delete set null,
  severity text not null default 'medium'
    check (severity in ('critical', 'high', 'medium', 'low', 'info')),
  status text not null default 'open'
    check (status in (
      'open', 'triaged', 'under_review', 'fix_proposed', 'ready_for_verification',
      'fixed', 'verified', 'still_present', 'unable_to_verify', 'accepted_risk',
      'false_positive'
    )),
  category text not null default 'general',
  title text not null check (char_length(title) between 3 and 200),
  description text,
  file_path text,
  line_start integer,
  line_end integer,
  affected_component text,
  rule_id text,
  fingerprint text not null,
  scanner text not null,
  scanner_version text,
  confidence text not null default 'medium'
    check (confidence in ('low', 'medium', 'high')),
  remediation text,
  redacted_evidence text,
  metadata jsonb,
  first_seen timestamptz not null default now(),
  last_seen timestamptz not null default now(),
  verified_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (project_id, fingerprint)
);

create index if not exists findings_workspace_idx
  on public.findings (workspace_id, created_at desc);
create index if not exists findings_scan_idx on public.findings (scan_id);
create index if not exists findings_severity_idx
  on public.findings (workspace_id, severity);

create table if not exists public.finding_evidence (
  id uuid primary key default gen_random_uuid(),
  workspace_id uuid not null references public.workspaces (id) on delete cascade,
  finding_id uuid not null references public.findings (id) on delete cascade,
  kind text not null default 'scanner_output',
  file_path text,
  line_start integer,
  snippet text,
  metadata jsonb,
  created_at timestamptz not null default now()
);

create index if not exists finding_evidence_finding_idx
  on public.finding_evidence (finding_id);

create table if not exists public.finding_state_history (
  id uuid primary key default gen_random_uuid(),
  workspace_id uuid not null references public.workspaces (id) on delete cascade,
  finding_id uuid not null references public.findings (id) on delete cascade,
  from_status text,
  to_status text not null,
  actor_id uuid references auth.users (id) on delete set null,
  reason text,
  created_at timestamptz not null default now()
);

/* ------------------------------------------------------------ verification */

create table if not exists public.verification_runs (
  id uuid primary key default gen_random_uuid(),
  workspace_id uuid not null references public.workspaces (id) on delete cascade,
  finding_id uuid not null references public.findings (id) on delete cascade,
  scan_id uuid references public.scans (id) on delete set null,
  status text not null default 'pending'
    check (status in ('pending', 'running', 'passed', 'failed', 'error', 'inconclusive')),
  requested_by uuid references auth.users (id) on delete set null,
  notes text,
  started_at timestamptz,
  completed_at timestamptz,
  created_at timestamptz not null default now()
);

create index if not exists verification_runs_finding_idx
  on public.verification_runs (finding_id, created_at desc);

create table if not exists public.verification_evidence (
  id uuid primary key default gen_random_uuid(),
  workspace_id uuid not null references public.workspaces (id) on delete cascade,
  verification_run_id uuid not null references public.verification_runs (id) on delete cascade,
  kind text not null,
  detail text,
  metadata jsonb,
  created_at timestamptz not null default now()
);

/* ---------------------------------------------------------- ai / tooling */

create table if not exists public.ai_sessions (
  id uuid primary key default gen_random_uuid(),
  workspace_id uuid not null references public.workspaces (id) on delete cascade,
  scan_id uuid references public.scans (id) on delete set null,
  provider text,
  model text,
  prompt_version text,
  status text not null default 'pending'
    check (status in ('pending', 'running', 'completed', 'failed', 'unavailable')),
  token_usage jsonb,
  error_message text,
  created_at timestamptz not null default now(),
  completed_at timestamptz
);

create table if not exists public.assessment_plans (
  id uuid primary key default gen_random_uuid(),
  workspace_id uuid not null references public.workspaces (id) on delete cascade,
  scan_id uuid references public.scans (id) on delete set null,
  session_id uuid references public.ai_sessions (id) on delete set null,
  plan jsonb not null,
  validated boolean not null default false,
  validation_notes text,
  created_at timestamptz not null default now()
);

create table if not exists public.tool_executions (
  id uuid primary key default gen_random_uuid(),
  workspace_id uuid not null references public.workspaces (id) on delete cascade,
  scan_id uuid references public.scans (id) on delete set null,
  tool text not null,
  tool_version text,
  argv_sanitized text,
  status text not null check (status in ('ran', 'skipped', 'failed', 'timeout', 'cancelled')),
  exit_code integer,
  duration_ms integer,
  output_ref text,
  error_message text,
  created_at timestamptz not null default now()
);

create table if not exists public.ai_observations (
  id uuid primary key default gen_random_uuid(),
  workspace_id uuid not null references public.workspaces (id) on delete cascade,
  session_id uuid references public.ai_sessions (id) on delete cascade,
  scan_id uuid references public.scans (id) on delete set null,
  kind text not null,
  body text not null,
  finding_ids uuid[] not null default '{}',
  evidence_ids uuid[] not null default '{}',
  created_at timestamptz not null default now()
);

/* ------------------------------------------------------------ app map */

create table if not exists public.application_map_nodes (
  id uuid primary key default gen_random_uuid(),
  workspace_id uuid not null references public.workspaces (id) on delete cascade,
  project_id uuid not null references public.projects (id) on delete cascade,
  kind text not null,
  label text not null,
  evidence_ref text,
  metadata jsonb,
  created_at timestamptz not null default now()
);

create table if not exists public.application_map_edges (
  id uuid primary key default gen_random_uuid(),
  workspace_id uuid not null references public.workspaces (id) on delete cascade,
  project_id uuid not null references public.projects (id) on delete cascade,
  from_node uuid not null references public.application_map_nodes (id) on delete cascade,
  to_node uuid not null references public.application_map_nodes (id) on delete cascade,
  relation text not null,
  evidence_ref text,
  created_at timestamptz not null default now()
);

/* ------------------------------------------------------------- reports */

create table if not exists public.reports (
  id uuid primary key default gen_random_uuid(),
  workspace_id uuid not null references public.workspaces (id) on delete cascade,
  project_id uuid not null references public.projects (id) on delete cascade,
  scan_id uuid references public.scans (id) on delete set null,
  report_type text not null check (report_type in ('client', 'technical')),
  version integer not null default 1,
  status text not null default 'draft'
    check (status in ('draft', 'generating', 'ready', 'failed')),
  summary text,
  generated_by uuid references auth.users (id) on delete set null,
  artifact_ref text,
  created_at timestamptz not null default now(),
  unique (scan_id, report_type, version)
);

create table if not exists public.benchmark_runs (
  id uuid primary key default gen_random_uuid(),
  workspace_id uuid not null references public.workspaces (id) on delete cascade,
  corpus_version text not null,
  scanner text not null,
  true_positives integer not null default 0,
  false_positives integer not null default 0,
  false_negatives integer not null default 0,
  runtime_ms integer,
  meta jsonb,
  created_at timestamptz not null default now()
);

/* --------------------------------------------------------- integrations */

create table if not exists public.integration_configs (
  id uuid primary key default gen_random_uuid(),
  workspace_id uuid not null references public.workspaces (id) on delete cascade,
  provider text not null,
  status text not null default 'configured'
    check (status in ('configured', 'connected', 'revoked', 'error')),
  config jsonb not null default '{}'::jsonb,
  secret_ref text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (workspace_id, provider)
);

create table if not exists public.github_installations (
  id uuid primary key default gen_random_uuid(),
  workspace_id uuid not null references public.workspaces (id) on delete cascade,
  installation_id bigint not null,
  account_login text,
  repository_selection text,
  permissions jsonb,
  revoked_at timestamptz,
  created_at timestamptz not null default now(),
  unique (workspace_id, installation_id)
);

/* --------------------------------------------------------------- audit */

create table if not exists public.audit_events (
  id uuid primary key default gen_random_uuid(),
  workspace_id uuid references public.workspaces (id) on delete cascade,
  actor_id uuid references auth.users (id) on delete set null,
  action text not null,
  entity_type text,
  entity_id text,
  metadata jsonb,
  created_at timestamptz not null default now()
);

create index if not exists audit_events_workspace_idx
  on public.audit_events (workspace_id, created_at desc);

/* ------------------------------------------------------------- triggers */

drop trigger if exists workspaces_touch on public.workspaces;
create trigger workspaces_touch before update on public.workspaces
  for each row execute function public.touch_updated_at();

drop trigger if exists projects_touch on public.projects;
create trigger projects_touch before update on public.projects
  for each row execute function public.touch_updated_at();

drop trigger if exists findings_touch on public.findings;
create trigger findings_touch before update on public.findings
  for each row execute function public.touch_updated_at();

drop trigger if exists integration_configs_touch on public.integration_configs;
create trigger integration_configs_touch before update on public.integration_configs
  for each row execute function public.touch_updated_at();

/* ------------------------------------------------------------- RPC: create */

create or replace function public.create_workspace(
  p_name text,
  p_kind text default 'personal',
  p_slug text default null
)
returns uuid
language plpgsql
security definer
set search_path = public
as $$
declare
  v_id uuid;
  v_slug text;
  v_email text;
begin
  if auth.uid() is null then
    raise exception 'authentication required';
  end if;

  v_slug := coalesce(nullif(p_slug, ''), lower(regexp_replace(p_name, '[^a-zA-Z0-9]+', '-', 'g')));
  v_slug := trim(both '-' from v_slug);
  if char_length(v_slug) < 2 then
    v_slug := 'workspace';
  end if;
  v_slug := left(v_slug, 40) || '-' || substr(replace(gen_random_uuid()::text, '-', ''), 1, 6);

  v_email := nullif(current_setting('request.jwt.claims', true)::jsonb ->> 'email', '');

  insert into public.workspaces (name, slug, kind, created_by)
  values (trim(p_name), v_slug, coalesce(p_kind, 'personal'), auth.uid())
  returning id into v_id;

  insert into public.workspace_members (workspace_id, user_id, email, role)
  values (v_id, auth.uid(), v_email, 'owner');

  insert into public.audit_events (workspace_id, actor_id, action, entity_type, entity_id)
  values (v_id, auth.uid(), 'workspace.created', 'workspace', v_id::text);

  return v_id;
end;
$$;

create or replace function public.create_workspace_invitation(
  p_workspace uuid,
  p_email text,
  p_role text
)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_token text;
  v_id uuid;
begin
  if not public.has_workspace_role(p_workspace, array['owner', 'admin']) then
    raise exception 'not allowed';
  end if;

  v_token := encode(gen_random_bytes(24), 'hex');

  insert into public.workspace_invitations (workspace_id, email, role, token, invited_by)
  values (p_workspace, lower(trim(p_email)), p_role, v_token, auth.uid())
  returning id into v_id;

  insert into public.audit_events (workspace_id, actor_id, action, entity_type, entity_id, metadata)
  values (p_workspace, auth.uid(), 'invitation.created', 'invitation', v_id::text,
          jsonb_build_object('email', p_email, 'role', p_role));

  return jsonb_build_object('id', v_id, 'token', v_token);
end;
$$;

create or replace function public.accept_workspace_invitation(p_token text)
returns uuid
language plpgsql
security definer
set search_path = public
as $$
declare
  v_inv public.workspace_invitations;
  v_email text;
begin
  if auth.uid() is null then
    raise exception 'authentication required';
  end if;

  select * into v_inv from public.workspace_invitations
  where token = p_token for update;

  if v_inv.id is null then
    raise exception 'invitation not found';
  end if;
  if v_inv.accepted_at is not null then
    raise exception 'invitation already used';
  end if;
  if v_inv.expires_at < now() then
    raise exception 'invitation expired';
  end if;

  v_email := lower(coalesce(current_setting('request.jwt.claims', true)::jsonb ->> 'email', ''));

  insert into public.workspace_members (workspace_id, user_id, email, role)
  values (v_inv.workspace_id, auth.uid(), v_email, v_inv.role)
  on conflict (workspace_id, user_id) do update set role = excluded.role;

  update public.workspace_invitations
  set accepted_at = now(), accepted_by = auth.uid()
  where id = v_inv.id;

  insert into public.audit_events (workspace_id, actor_id, action, entity_type, entity_id)
  values (v_inv.workspace_id, auth.uid(), 'invitation.accepted', 'invitation', v_inv.id::text);

  return v_inv.workspace_id;
end;
$$;

/* --------------------------------------------------------- RPC: job queue */

create or replace function public.claim_scan_jobs(p_worker text, p_limit integer default 5)
returns setof public.scan_jobs
language plpgsql
security definer
set search_path = public
as $$
begin
  return query
  with picked as (
    select j.id
    from public.scan_jobs j
    where j.status = 'queued'
      and j.attempts < 3
    order by j.created_at asc
    for update skip locked
    limit greatest(1, least(p_limit, 25))
  )
  update public.scan_jobs j
  set status = 'running',
      locked_by = p_worker,
      locked_at = now(),
      started_at = coalesce(j.started_at, now()),
      attempts = j.attempts + 1
  from picked
  where j.id = picked.id
  returning j.*;
end;
$$;

create or replace function public.requeue_stale_scan_jobs(p_minutes integer default 15)
returns integer
language plpgsql
security definer
set search_path = public
as $$
declare
  v_count integer;
begin
  update public.scan_jobs
  set status = 'queued', locked_by = null, locked_at = null
  where status = 'running'
    and locked_at < now() - make_interval(mins => p_minutes)
    and attempts < 3;

  get diagnostics v_count = row_count;
  return v_count;
end;
$$;

/* ------------------------------------------------------------------- RLS */

alter table public.workspaces enable row level security;
alter table public.workspace_members enable row level security;
alter table public.workspace_invitations enable row level security;
alter table public.projects enable row level security;
alter table public.project_sources enable row level security;
alter table public.scans enable row level security;
alter table public.scan_jobs enable row level security;
alter table public.findings enable row level security;
alter table public.finding_evidence enable row level security;
alter table public.finding_state_history enable row level security;
alter table public.verification_runs enable row level security;
alter table public.verification_evidence enable row level security;
alter table public.ai_sessions enable row level security;
alter table public.assessment_plans enable row level security;
alter table public.tool_executions enable row level security;
alter table public.ai_observations enable row level security;
alter table public.application_map_nodes enable row level security;
alter table public.application_map_edges enable row level security;
alter table public.reports enable row level security;
alter table public.benchmark_runs enable row level security;
alter table public.integration_configs enable row level security;
alter table public.github_installations enable row level security;
alter table public.audit_events enable row level security;

-- workspaces: members read; only owners update.
drop policy if exists workspaces_select on public.workspaces;
create policy workspaces_select on public.workspaces
  for select to authenticated
  using (public.is_workspace_member(id));

drop policy if exists workspaces_update on public.workspaces;
create policy workspaces_update on public.workspaces
  for update to authenticated
  using (public.has_workspace_role(id, array['owner']))
  with check (public.has_workspace_role(id, array['owner']));

-- members: read own workspace rows; managers manage.
drop policy if exists workspace_members_select on public.workspace_members;
create policy workspace_members_select on public.workspace_members
  for select to authenticated
  using (public.is_workspace_member(workspace_id));

drop policy if exists workspace_members_insert on public.workspace_members;
create policy workspace_members_insert on public.workspace_members
  for insert to authenticated
  with check (public.has_workspace_role(workspace_id, array['owner', 'admin']));

drop policy if exists workspace_members_update on public.workspace_members;
create policy workspace_members_update on public.workspace_members
  for update to authenticated
  using (public.has_workspace_role(workspace_id, array['owner', 'admin']))
  with check (public.has_workspace_role(workspace_id, array['owner', 'admin']));

drop policy if exists workspace_members_delete on public.workspace_members;
create policy workspace_members_delete on public.workspace_members
  for delete to authenticated
  using (
    public.has_workspace_role(workspace_id, array['owner', 'admin'])
    and role <> 'owner'
  );

-- invitations: managers only.
drop policy if exists invitations_select on public.workspace_invitations;
create policy invitations_select on public.workspace_invitations
  for select to authenticated
  using (public.has_workspace_role(workspace_id, array['owner', 'admin']));

-- projects.
drop policy if exists projects_select on public.projects;
create policy projects_select on public.projects
  for select to authenticated
  using (public.is_workspace_member(workspace_id));

drop policy if exists projects_insert on public.projects;
create policy projects_insert on public.projects
  for insert to authenticated
  with check (
    public.has_workspace_role(workspace_id, array['owner', 'admin', 'analyst', 'developer'])
    and created_by = auth.uid()
  );

drop policy if exists projects_update on public.projects;
create policy projects_update on public.projects
  for update to authenticated
  using (public.has_workspace_role(workspace_id, array['owner', 'admin', 'analyst', 'developer']))
  with check (public.has_workspace_role(workspace_id, array['owner', 'admin', 'analyst', 'developer']));

drop policy if exists projects_delete on public.projects;
create policy projects_delete on public.projects
  for delete to authenticated
  using (public.has_workspace_role(workspace_id, array['owner', 'admin']));

-- sources: written by the backend (service role); members read.
drop policy if exists project_sources_select on public.project_sources;
create policy project_sources_select on public.project_sources
  for select to authenticated
  using (public.is_workspace_member(workspace_id));

-- scans / jobs: backend writes; members read; analysts may cancel via update.
drop policy if exists scans_select on public.scans;
create policy scans_select on public.scans
  for select to authenticated
  using (public.is_workspace_member(workspace_id));

drop policy if exists scans_update on public.scans;
create policy scans_update on public.scans
  for update to authenticated
  using (public.has_workspace_role(workspace_id, array['owner', 'admin', 'analyst']))
  with check (public.has_workspace_role(workspace_id, array['owner', 'admin', 'analyst']));

drop policy if exists scan_jobs_select on public.scan_jobs;
create policy scan_jobs_select on public.scan_jobs
  for select to authenticated
  using (public.is_workspace_member(workspace_id));

-- findings: members read; analysts may change state.
drop policy if exists findings_select on public.findings;
create policy findings_select on public.findings
  for select to authenticated
  using (public.is_workspace_member(workspace_id));

drop policy if exists findings_update on public.findings;
create policy findings_update on public.findings
  for update to authenticated
  using (public.has_workspace_role(workspace_id, array['owner', 'admin', 'analyst']))
  with check (public.has_workspace_role(workspace_id, array['owner', 'admin', 'analyst']));

drop policy if exists finding_evidence_select on public.finding_evidence;
create policy finding_evidence_select on public.finding_evidence
  for select to authenticated
  using (public.is_workspace_member(workspace_id));

drop policy if exists finding_state_history_select on public.finding_state_history;
create policy finding_state_history_select on public.finding_state_history
  for select to authenticated
  using (public.is_workspace_member(workspace_id));

drop policy if exists verification_runs_select on public.verification_runs;
create policy verification_runs_select on public.verification_runs
  for select to authenticated
  using (public.is_workspace_member(workspace_id));

drop policy if exists verification_evidence_select on public.verification_evidence;
create policy verification_evidence_select on public.verification_evidence
  for select to authenticated
  using (public.is_workspace_member(workspace_id));

-- AI and tooling: read-only to members; the worker writes with the service role.
drop policy if exists ai_sessions_select on public.ai_sessions;
create policy ai_sessions_select on public.ai_sessions
  for select to authenticated using (public.is_workspace_member(workspace_id));

drop policy if exists assessment_plans_select on public.assessment_plans;
create policy assessment_plans_select on public.assessment_plans
  for select to authenticated using (public.is_workspace_member(workspace_id));

drop policy if exists tool_executions_select on public.tool_executions;
create policy tool_executions_select on public.tool_executions
  for select to authenticated using (public.is_workspace_member(workspace_id));

drop policy if exists ai_observations_select on public.ai_observations;
create policy ai_observations_select on public.ai_observations
  for select to authenticated using (public.is_workspace_member(workspace_id));

drop policy if exists map_nodes_select on public.application_map_nodes;
create policy map_nodes_select on public.application_map_nodes
  for select to authenticated using (public.is_workspace_member(workspace_id));

drop policy if exists map_edges_select on public.application_map_edges;
create policy map_edges_select on public.application_map_edges
  for select to authenticated using (public.is_workspace_member(workspace_id));

drop policy if exists reports_select on public.reports;
create policy reports_select on public.reports
  for select to authenticated using (public.is_workspace_member(workspace_id));

drop policy if exists reports_write on public.reports;
create policy reports_write on public.reports
  for insert to authenticated
  with check (public.has_workspace_role(workspace_id, array['owner', 'admin', 'analyst']));

drop policy if exists benchmark_runs_select on public.benchmark_runs;
create policy benchmark_runs_select on public.benchmark_runs
  for select to authenticated using (public.is_workspace_member(workspace_id));

drop policy if exists integration_configs_select on public.integration_configs;
create policy integration_configs_select on public.integration_configs
  for select to authenticated using (public.is_workspace_member(workspace_id));

drop policy if exists integration_configs_write on public.integration_configs;
create policy integration_configs_write on public.integration_configs
  for all to authenticated
  using (public.has_workspace_role(workspace_id, array['owner', 'admin']))
  with check (public.has_workspace_role(workspace_id, array['owner', 'admin']));

drop policy if exists github_installations_select on public.github_installations;
create policy github_installations_select on public.github_installations
  for select to authenticated using (public.is_workspace_member(workspace_id));

-- audit: members read their workspace trail; writes are service-role only.
drop policy if exists audit_events_select on public.audit_events;
create policy audit_events_select on public.audit_events
  for select to authenticated
  using (public.has_workspace_role(workspace_id, array['owner', 'admin']));

/* ---------------------------------------------------------------- grants */

revoke all on function public.claim_scan_jobs(text, integer) from anon, authenticated;
revoke all on function public.requeue_stale_scan_jobs(integer) from anon, authenticated;
grant execute on function public.create_workspace(text, text, text) to authenticated;
grant execute on function public.create_workspace_invitation(uuid, text, text) to authenticated;
grant execute on function public.accept_workspace_invitation(text) to authenticated;
grant execute on function public.is_workspace_member(uuid) to authenticated;
grant execute on function public.workspace_role(uuid) to authenticated;
grant execute on function public.has_workspace_role(uuid, text[]) to authenticated;
