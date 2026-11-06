# VibeCheck — vibecheck.dev

Marketing site for VibeCheck: security verification infrastructure for the
AI-powered software development era. Tagline: **Secure what you build.**

Seven routes, art-directed dark/editorial system, and three signature
interactions. No backend beyond one form endpoint.

## Stack

- Next.js 15 (App Router) + TypeScript, React 19
- Tailwind CSS v4 (`@theme` tokens in `app/globals.css`)
- Framer Motion (interface motion, reveal, dock)
- GSAP + ScrollTrigger (hero split-wordmark choreography, lazy-loaded)
- Three.js (hero tubes, dynamically imported, no CDN dependency)
- Supabase (Postgres + insert-only RLS) for early-access requests
- Lucide React (icons)

## Commands

```bash
npm install
npm run dev      # http://localhost:3000
npm run build
npm start
npm run typecheck
```

## Structure

```
app/
  page.tsx                 home (hero + 7 numbered sections)
  platform/                modules, status labels, limits
  how-it-works/            six-step workflow + automation boundary
  integrations/            honest status board + ecosystem map
  developers/              findings, API preview, getting started
  pricing/                 proposed tiers, no published prices
  about/                   why, principles, team placeholder, contact
  api/early-access/        validating form endpoint
  sitemap.ts robots.ts not-found.tsx globals.css layout.tsx
components/
  brand/ navigation/ sections/ animations/ ui/ 3d/
lib/content.ts             single source of product copy + statuses
```

## Design tokens

`#08080D` void · `#11101A` surface · `#171323` elevated · `#702BFF` violet ·
`#974FFF` bright violet · `#C9B5FF` lavender · `#F5F3FF` text ·
`#A5A0B5` muted · `rgba(255,255,255,.10)` hairline.

Space Grotesk (display), Inter (body), JetBrains Mono (labels/code).
All tokens live in the `@theme` block — change them there, not per component.

## Interactions

**Tubes hero** — `components/3d/tubes-engine.ts` is a local Three.js
implementation of the cursor-tubes idea rather than the supplied CDN build.
Trade-off: `threejs-components` ships only as a CDN bundle with no teardown,
no resize handling and click-to-randomise colours (which fought the identity).
The local version is ~10 kB gzip on top of `three`, disposes geometry,
materials, listeners, observer and WebGL context, pauses when the tab is
hidden, and cannot randomise the palette. The canvas is `pointer-events-none`
and listens on `window`, so no CTA is ever blocked.

**Split wordmark** — headline and copy left, `VIBE` / `CHECK` stacked right
with the orbital core in the gap. Scroll progress (GSAP ScrollTrigger, scrub)
pulls the lines apart and raises the core; scrolling back reverses it. Reduced
motion renders the static composition.

**Magnification dock** — `components/ui/MagnificationDock.tsx`, used only as
the platform module explorer. Real anchors (work without JS), Framer spring
magnification, tooltips on hover *and* focus, roving arrow-key support at the
browser level via native tab order, and a touch-friendly grid below `md`.

## Early-access form (Supabase)

Flow: form -> `POST /api/early-access` -> `public.early_access_requests`.

The route validates name (2-100), email format, optional build type (<= 80)
and optional project description (<= 2000), lowercases and trims the email,
rate limits per IP, checks a honeypot, and inserts with the anon key from
**server-only** env vars. Success is returned only when Supabase reports no
error for the insert; the UI then shows
"You're on the list. We'll be in touch." Any database or network failure shows
"We couldn't submit your request. Please try again." with an email fallback.
A missing configuration returns 503 `not_configured` and stores nothing.

Supabase client: `lib/supabase.ts` (server-only — never import it from a
client component). This repo has no `src/` directory, so it follows the
existing top-level `lib/` convention rather than `src/lib/`.

### Setup

1. Create a Supabase project.
2. Run `supabase/early_access_requests.sql` in the SQL editor. It creates the
table, its checks and an **insert-only** RLS policy — there is no SELECT
policy, so the public key cannot read submissions.
3. Copy `.env.example` to `.env.local` and set `SUPABASE_URL` and
`SUPABASE_ANON_KEY` (Project Settings -> API). Keep both non-`NEXT_PUBLIC_`.
4. For Vercel, add the same two keys as environment variables for Production,
Preview and Development, then redeploy.

Never use a service-role key in this app; the anon key plus insert-only RLS is
the intended boundary. The submitted list is not exposed on the website.

## Honesty rules encoded in the site

- Every capability, integration and tier carries `In current MVP` /
  `In development` / `Planned`.
- No customers, testimonials, founders, awards, certifications, statistics or
  partner logos are invented. The team section states why it is empty.
- Sample findings, API responses and CLI output are labelled `illustrative`
  and the CLI text says the commands will fail.
- Pricing publishes no numbers; tiers are explicitly "proposed, not
  purchasable".
- No runtime guarantee, no "complete protection", no auto-fix claims.

## Deployment

Static pages, one serverless route. Deploys as-is to Vercel or any Node host;
no database, no secrets in the client. Set the webhook env var in the host's
dashboard, never in `NEXT_PUBLIC_*`.

## Known environment caveat

WebGL frames cannot be screenshotted when the review tab is hidden
(`document.hidden` pauses `requestAnimationFrame`). The scene still
initialises and disposes correctly; verify visually in a focused tab.
