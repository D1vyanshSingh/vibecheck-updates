-- Rollback for 20261109000001_core.sql
--
-- Destructive by definition: it removes every VibeCheck table and the data in
-- it. The early-access table created by the baseline migration is NOT touched.
-- Take a database backup before running this anywhere that matters.

drop function if exists public.requeue_stale_scan_jobs(integer);
drop function if exists public.claim_scan_jobs(text, integer);
drop function if exists public.accept_workspace_invitation(text);
drop function if exists public.create_workspace_invitation(uuid, text, text);
drop function if exists public.create_workspace(text, text, text);
drop function if exists public.has_workspace_role(uuid, text[]);
drop function if exists public.workspace_role(uuid);
drop function if exists public.is_workspace_member(uuid);
drop function if exists public.touch_updated_at();

drop table if exists public.audit_events cascade;
drop table if exists public.github_installations cascade;
drop table if exists public.integration_configs cascade;
drop table if exists public.benchmark_runs cascade;
drop table if exists public.reports cascade;
drop table if exists public.application_map_edges cascade;
drop table if exists public.application_map_nodes cascade;
drop table if exists public.ai_observations cascade;
drop table if exists public.tool_executions cascade;
drop table if exists public.assessment_plans cascade;
drop table if exists public.ai_sessions cascade;
drop table if exists public.verification_evidence cascade;
drop table if exists public.verification_runs cascade;
drop table if exists public.finding_state_history cascade;
drop table if exists public.finding_evidence cascade;
drop table if exists public.findings cascade;
drop table if exists public.scan_jobs cascade;
drop table if exists public.scans cascade;
drop table if exists public.project_sources cascade;
drop table if exists public.projects cascade;
drop table if exists public.workspace_invitations cascade;
drop table if exists public.workspace_members cascade;
drop table if exists public.workspaces cascade;
