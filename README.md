# VibeCheck — vibecheck.dev

Security verification infrastructure for the AI-powered software development
era. Tagline: **Secure what you build.**

This repository now holds two surfaces:

- **Marketing site** — `app/(site)/`, unchanged copy, design tokens and the
  three signature interactions described below.
- **Console** — `app/(app)/`, an authenticated workspace for projects,
  assessments, findings, verification, reports and OmniRoute status.

## Stack

- Next.js 15 (App Router) + TypeScript, React 19
- Tailwind CSS v4 (`@theme` tokens in `app/globals.css`)
- `@supabase/ssr` cookie sessions, Supabase Auth, Postgres + RLS
- FastAPI + Pydantic backend (`backend/`) with a Postgres-backed job queue
- Scanner adapters: Semgrep, Gitleaks, OSV-Scanner, plus built-in checks
- Framer Motion, GSAP ScrollTrigger, Three.js (marketing site only)

## Commands

```bash
npm install
npm run dev        # http://localhost:3000
npm run build
npm run typecheck

cd backend
pip install -r requirements.txt
python -m pytest -q          # 77 tests
uvicorn app.api:app --reload # http://localhost:8000
python -m app.worker --once  # claim one batch of scan jobs
```

## Routes

Public: `/`, `/platform`, `/how-it-works`, `/integrations`, `/developers`,
`/pricing`, `/about`.

Auth: `/login`, `/register`, `/forgot-password`, `/reset-password`,
`/auth/callback`, `/invite/[token]`.

Console: `/app`, `/app/workspaces`, `/app/projects`, `/app/projects/new`,
`/app/projects/[projectId]`, `/app/scans`, `/app/scans/[scanId]`,
`/app/findings`, `/app/findings/[findingId]`, `/app/verification`,
`/app/remediation`, `/app/ai-intelligence`, `/app/omniroute`,
`/app/application-map`, `/app/benchmarks`, `/app/reports`,
`/app/reports/[reportId]`, `/app/integrations`, `/app/settings`.

## Setup

1. Copy `.env.example` to `.env.local` and fill in the two public Supabase
   values, plus `NEXT_PUBLIC_BACKEND_URL`.
2. Apply the migrations in `supabase/migrations/` to the linked project
   (`wvdcndzdcrqussasscnx` is linked in this checkout via `supabase/.temp`).
   `20261109000000_baseline_early_access.sql` adopts the existing
   `early_access_requests` table idempotently;
   `20261109000001_core.sql` creates everything else.
3. Set the server-only variables (`SUPABASE_URL`, `SUPABASE_ANON_KEY`,
   `SUPABASE_SERVICE_ROLE_KEY`) for the backend and worker.
4. Start the backend and `python -m app.worker`, then sign in.

Rollback for the core schema: `20261109000001_core.down.sql` (destructive; the
early-access table is not touched).

## Security boundaries

- Every customer table has RLS; reads are scoped to workspace membership and
  writes to owner/admin/analyst/developer as appropriate.
- The service-role key is server-only. `lib/env.ts` never exposes it.
- The backend verifies the Supabase JWT (RS256 via JWKS) and re-checks
  workspace membership for every object a request touches.
- ZIP uploads are validated for traversal, symlinks, size, file count and
  archive integrity; uploaded code is never executed.
- Scanner commands are built from a fixed registry. No shell, no
  model-supplied arguments.
- Secrets are redacted before evidence is stored.

## Honesty rules encoded in the site and console

- Capabilities are labelled `In current MVP` / `In development` / `Planned`.
- The console shows only stored rows. Empty states say what is missing.
- `/app/omniroute` shows nothing as online unless the backend reports it.
- No benchmark numbers, adoption figures or findings are invented.
- Sample findings and API output on the marketing site stay labelled
  `illustrative`.

## Design tokens

`#08080D` void · `#11101A` surface · `#171323` elevated · `#702BFF` violet ·
`#974FFF` bright violet · `#C9B5FF` lavender · `#F5F3FF` text ·
`#A5A0B5` muted · `rgba(255,255,255,.10)` hairline.

Space Grotesk (display), Inter (body), JetBrains Mono (labels/code). Change
tokens in the `@theme` block, not per component.

## Interactions (marketing site)

**Tubes hero** — `components/3d/tubes-engine.ts` is a local Three.js
implementation rather than the supplied CDN build: it disposes geometry,
materials, listeners, observer and WebGL context, pauses when the tab is
hidden, and cannot randomise the palette. The canvas is `pointer-events-none`
and listens on `window`, so no CTA is blocked.

**Split wordmark** — GSAP ScrollTrigger scrub pulls `VIBE` / `CHECK` apart and
raises the orbital core; reduced motion renders the static composition.

**Magnification dock** — `components/ui/MagnificationDock.tsx`, real anchors,
Framer spring magnification, keyboard focus support and a touch grid below
`md`.

## Early-access form

Form → `POST /api/early-access` → `public.early_access_requests` with the
insert-only RLS policy. Validation, honeypot, per-IP rate limit, distinct
`503 not_configured` / `502 db_error` states, and success only when Supabase
returns no error.

## Audit documents

- `docs/ARCHITECTURE.md` — implemented architecture and trust boundaries.
- `docs/RECOVERY.md` — what was recovered from the previous build, and what it
  is not.
- `docs/VERIFICATION.md` — every live check that was run, with its result.

## Known environment caveat

WebGL frames cannot be screenshotted when the review tab is hidden
(`document.hidden` pauses `requestAnimationFrame`). The scene initialises and
disposes correctly; verify visually in a focused tab.
