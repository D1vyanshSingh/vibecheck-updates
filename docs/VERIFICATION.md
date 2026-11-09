# Verification record

Everything here was executed on this machine, against the live Supabase
project `wvdcndzdcrqussasscnx` (Tokyo) and a local backend on
`127.0.0.1:8000`. Nothing in this file is projected or estimated. Where a check
did not run, it is listed under "Not verified" rather than implied by silence.

Date: 2026-11-09.

## Gates

| Command | Result |
|---|---|
| `python -m pytest -q` (backend) | 77 passed |
| `npx tsc --noEmit` | exit 0, 0 errors |
| `npm run build` | exit 0, compiled successfully, 34 routes |

## Schema applied to the live database

The core migration was applied in ordered statements. Verified by reading the
catalogue afterwards:

- 24 tables in `public`, every one with `relrowsecurity = true`.
- 35 policies across those 24 tables; `workspaces`, `projects`,
  `workspace_members` and `findings` carry the write policies, read paths use
  `is_workspace_member`.
- Four RPCs granted to `authenticated`: `create_workspace`,
  `create_workspace_invitation`, `accept_workspace_invitation`, plus the
  membership helpers. `claim_scan_jobs` and `requeue_stale_scan_jobs` are
  revoked from `authenticated` and usable only by the service role.
- `early_access_requests` was left untouched (0 rows before and after).

## Live end-to-end (owner account)

`_local/e2e.py` — **14/14 passed**:

1. Password login against Supabase Auth returns a session.
2. Backend refuses a request with no bearer token (401).
3. Backend accepts the real ES256 access token (404 for an absent id, not 401).
4. `create_workspace` RPC returns an id.
5. The creator is inserted as `owner` in `workspace_members`.
6. A project insert through PostgREST succeeds under RLS.
7. An insert naming a foreign workspace id is rejected.
8. ZIP upload (multipart) stores a source record.
9. Scan creation enqueues jobs.
10–11. The worker drains the queue and the scan reaches `completed`.
12. Findings are persisted (2 rows: one critical secret, one high injection sink).
13. No raw `AKIA…` value appears in stored `redacted_evidence`.
14. Coverage is recorded on the scan.

Scanner status recorded by that run: `native_secrets`, `static_checks`,
`semgrep`, `gitleaks`, `osv` all `ran`; semgrep, gitleaks and osv each reported
0 matches on the three-file archive.

## Tenant isolation (second real account)

`_local/isolation.py` — **10/10 passed**:

- The second account sees no workspace, finding, scan or membership row
  belonging to the first (RLS).
- It cannot insert a project into the first workspace.
- It can create its own workspace normally.
- The backend returns 404 for the first workspace's findings and for its scan,
  and 200 for its own empty workspace.

## New endpoints

| Check | Result |
|---|---|
| `POST /v1/workspaces/{id}/url-assessment` with `http://127.0.0.1` | 400, private range refused |
| Same with `http://169.254.169.254/latest/meta-data/` | 400, metadata endpoint refused |
| `GET /v1/scans/{id}/analysis` | 200, observations + plan |
| Plan source with OmniRoute unconfigured | `fallback` (never blocks a scan) |
| `GET /v1/scans/{id}/report?output=json` | 200, summary and limitations |
| `...&output=html` | 200, `text/html` |
| `...&output=pdf` | 200, body starts with `%PDF` |
| Report without a token | 401 |

## URL assessment and reports, end to end

`_local/e2e_url_reports.py` — **41/41 passed** against the live project.

The target was a local HTTP server this session started on
`127.0.0.1:8099` serving one page with no security headers. Reaching it
required `ASSESSMENT_ALLOW_PRIVATE_HOSTS=true`, a **default-off** flag set only
for this run; with the flag unset the same URL is refused with 400 (checked
separately). Link-local and cloud-metadata ranges stay blocked even with the
flag on.

What the run established:

- `POST /v1/workspaces/{id}/url-assessment` returns 201 with the observed
  status, final URL and findings, and **persists a completed scan** with
  `coverage.scanners.web_headers = ran` plus an explicit limitation note.
- Findings are rows in Postgres (`findings` and `finding_evidence`), and the
  scan re-read through the API reports the same coverage.
- `GET /v1/scans/{id}/analysis` counts the stored findings and names the plan
  source (`fallback`, since OmniRoute is unconfigured).
- `POST /v1/scans/{id}/reports` records a `ready` snapshot whose summary states
  the finding count, severity split, scanner status and limitations; the row is
  visible to the owner through RLS.
- Downloads carry the persisted data: JSON names the scan and contains the
  stored finding titles and observations; HTML contains the same finding and
  the limitation text; the client PDF is a real `%PDF` document over 1 KB.
- Isolation: the second account gets 404 for assessment, analysis, report and
  snapshot on the first workspace's objects, and sees no report rows.

Unit coverage pins the same behaviour without a network:
`backend/tests/test_url_assessment_persistence.py` (6 tests) covers viewer
rejection (403), non-member 404, the persisted scan/evidence/audit rows, the
unreachable-target path writing nothing, and report snapshot authorization.

## Console wiring (this iteration)

- `/app/projects/[id]` renders the website-assessment form with the project's
  stored URL prefilled; `/app/scans/[id]` renders the analysis panel and the
  report generate/download controls.
- Verified in the browser on the live scan `02090db8`: the project page listed
  the persisted run as `completed` with 4 findings, and the scan page showed
  coverage `web_headers — HTTP 200; 4 header observations — ran`, the analysis
  button and the three download buttons.
- The analysis click and report download were not re-driven after the browser
  tab was taken over by hand; the underlying calls are covered by the 41-check
  script above.

## Fixed during this pass

- Source archives could land in `backend/backend/sources` when uvicorn was
  started from `backend/`. `storage_root()` now resolves a relative
  `SOURCE_STORAGE_DIR` against the repository root and the default is absolute,
  so archives stay in the gitignored `backend/sources/`.
- `reports` snapshots are upserted on `(scan_id, report_type, version)`, so
  regenerating the same version updates the row instead of failing.

## Browser

- `/login` renders and signs in; the session cookie carries to `/app`.
- `/app` renders live data: 1 project, 1 assessment, 2 open findings
  (1 critical, 1 high), recent assessment list.
- Marketing `/` still renders unchanged after the route-group move.

## Not verified

- **OmniRoute**: not installed, no endpoint or key. The planner path is
  exercised only through its deterministic fallback; the HTTP client is
  implemented but has never spoken to a real gateway.
- **GitHub App**: no credentials, so no repository import was executed. No
  GitHub code exists beyond configuration placeholders.
- **Trivy, ZAP, Checkov, Playwright**: not installed. They are not in the
  registry and no report claims them.
- **OSV depth**: the live run had no lockfile in the archive, so dependency
  coverage was effectively nil; "0 matches" there does not mean "no vulnerable
  dependencies". `run_osv` now refuses to report a clean result when no
  manifest or lockfile exists, and records `skipped` with that reason instead.
  `backend/tests/test_scanner_osv.py` pins that behaviour: no manifest means
  `skipped` and no child process, a lockfile means a real scan, and advisories
  turn into evidence-linked findings.
- **Email delivery**: confirmations were bypassed by setting
  `email_confirmed_at` on the two test accounts; the signup email flow itself
  was never completed.
- **PDF layout**: the file is structurally valid and text-extractable, but its
  visual layout was not opened in a viewer.
