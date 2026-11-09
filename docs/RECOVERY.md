# Recovery manifest

Before any build or cleanup, the following were copied to `_recovery/`
(gitignored, local only):

| Path | Contents | State |
|---|---|---|
| `_recovery/next-build/` | 425 MB copy of the last integrated `.next` build (484 files, 29 routes, BUILD_ID `73MYds9JY2lUkkz27jPZX`) | verified by SHA-256 on `middleware.js.map` and `app-path-routes-manifest.json` |
| `_recovery/bytecode/` | 27 `.pyc` modules from `backend/app` and `backend/tests` | copied, not modified |
| `_recovery/reconstruction-backend/` | the 11 hand-written backend files from the interrupted session | archived, not trusted |

## What the build artifacts contain

- `app-path-routes-manifest.json` — the complete previous route tree,
  including `(site)`, `(auth)`, `(app)`, `/auth/callback`, `/invite/[token]`.
- 19 prerendered `.html` and 19 `.rsc` payloads — the real copy and empty
  states of the lost console pages.
- `.next/server/middleware.js.map` (1.5 MB) — the only surviving copy of the
  original middleware source.
- `types/validator.ts` — authoritative list of route files that existed.

## What they do not contain

- The original TypeScript source of any console page.
- Any backend `.py` source (only Python 3.14 bytecode, which `uncompyle6` and
  `decompyle3` refuse).
- Migrations, dependency manifests, or environment values.

## Current state

The console, auth flow and backend in this repository were **rebuilt**, not
restored. The marketing site was moved into `app/(site)/` unchanged. The
archived reproduction is kept only as a reference for copy and layout.

## Never commit

`_recovery/`, `backend/.tools/`, `backend/sources/`, `supabase/.temp/` and any
`__pycache__` directory. `.gitignore` covers all of them.

## If a later change breaks something

`_recovery/next-build/` is a snapshot of the *old* build and is not a rollback
target for current code. Use Git for that. Its value is historical: it proves
what the previous build rendered.
