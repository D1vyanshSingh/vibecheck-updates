# VibeCheck architecture

Status: the platform runs end to end for ZIP-based source assessment against
the live database. Later modules (GitHub import, OmniRoute-backed planning,
benchmarks) are implemented at the library level or scaffolded with honest
empty states. Every claim below matches code in this repository.

## Surfaces

```
Browser ──▶ Next.js 15 (Vercel)
             app/(site)   marketing site, unchanged copy
             app/(auth)   login / register / reset / invite
             app/(app)    console, cookie session required
             middleware.ts  Supabase session refresh + route guard

Browser ──▶ FastAPI (backend/app)
             bearer JWT verified against Supabase JWKS (ES256/RS256)
             workspace role checked per object
             ZIP validation, scans, findings, verification,
             URL assessment (SSRF-guarded), analysis, reports

Worker (backend/app/worker.py)
             claims scan_jobs with FOR UPDATE SKIP LOCKED
             extracts to a temp dir, runs the allowlisted registry
             persists normalized findings, evidence and coverage
```

## Trust boundaries

| Boundary | Mechanism |
|---|---|
| Browser → database | RLS on all 24 tables; verified live with two accounts |
| Browser → backend | Supabase access token; backend re-reads membership with it |
| Backend → database (privileged) | service-role key, server-only, queue + findings writes |
| Worker → tools | fixed registry, argv built server-side, no shell |
| AI → tools | the model may only name a registry entry; plans are validated |
| Backend → internet (URL assessment) | every hop re-guarded against private/loopback/metadata addresses |

The service-role key has no frontend accessor. `lib/env.ts` exposes only the
public URL, anon key and backend origin. `.env.local` is gitignored.

## Data model

`workspaces → workspace_members`, `workspace_invitations`, `projects →
project_sources → scans → scan_jobs`, `findings → finding_evidence`,
`finding_state_history`, `verification_runs`, `ai_sessions`,
`assessment_plans`, `tool_executions`, `ai_observations`,
`application_map_nodes/edges`, `reports`, `benchmark_runs`,
`integration_configs`, `github_installations`, `audit_events`.

Roles: owner > admin > analyst > developer > viewer, enforced in SQL
(`has_workspace_role`) and in Python (`_role` / `WRITE_ROLES`).

## Engines

**Scanner registry** (`backend/app/scanners/`): `native_secrets`,
`static_checks`, `semgrep` (bundled rules, offline), `gitleaks`
(`--no-git --redact`), `osv`. A tool that does not run is recorded as
`skipped`/`failed` in coverage and repeated in the report's limitations.

**AI orchestration** (`backend/app/ai/`): `OmniRoute` is a thin client for the
gateway; `validate_plan` coerces model output into tool names from the
registry, dropping anything else and recording the rejection. `fallback_plan`
is deterministic and always available, so scanner execution never depends on a
model. `correlate` produces observations strictly from stored findings and
coverage.

**URL assessment** (`backend/app/assessment/`): `guard_url` refuses non-HTTP
schemes, embedded credentials, `.local`/`.internal` hosts, and any hostname
resolving to loopback, private, link-local, multicast, reserved or metadata
addresses. Redirects are not followed automatically; each `Location` is
guarded again, up to three hops. Only headers and transport are evaluated.

**Reports** (`backend/app/reports/`): one document built from stored rows,
rendered as JSON, self-contained HTML (escaped, print CSS) or a dependency-free
PDF. Coverage gaps appear as limitations, and an absent coverage record is
reported as "completeness cannot be claimed".

## Honest-state rules

- Dashboard numbers come from `count: exact`; there are no seeded rows.
- Empty states name what is missing instead of showing zeroes as results.
- `/app/omniroute` probes `/health` and `/v1/capabilities`; with no gateway it
  says so rather than showing a green status.
- A check that did not run is never presented as a clean result.

## Verification

See `docs/VERIFICATION.md`. In short: 96 backend tests, `tsc` clean, production
build clean, 14/14 live end-to-end checks, 10/10 tenant-isolation checks,
8/8 new-endpoint checks against the real database.
