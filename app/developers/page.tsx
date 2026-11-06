import type { Metadata } from "next";
import Link from "next/link";
import { ArrowRight, BookOpen, Terminal, ShieldQuestion, GitBranch } from "lucide-react";
import { PageHeader } from "@/components/sections/PageHeader";
import { Reveal } from "@/components/animations/Reveal";
import { CodeBlock } from "@/components/ui/CodeBlock";
import { FindingPanel } from "@/components/ui/FindingPanel";
import { StatusChip } from "@/components/ui/StatusChip";
import { EarlyAccessCTA } from "@/components/sections/EarlyAccessCTA";

export const metadata: Metadata = {
  title: "Developers",
  description:
    "The developer-facing view of VibeCheck: example findings, API responses, code samples and the getting-started path. All samples are illustrative — the API is not public yet.",
  alternates: { canonical: "/developers" },
};

const findingJson = `{
  "id": "vbc_1042",
  "status": "open",
  "severity": "high",
  "rule": "db.rls.missing_policy",
  "location": {
    "file": "supabase/policies.sql",
    "line": 42,
    "table": "public.invoices"
  },
  "confidence": 0.86,
  "evidence": {
    "rls_enabled": true,
    "policies_found": 0
  },
  "impact": "Authenticated clients can read rows across tenants.",
  "remediation": {
    "kind": "patch",
    "auto_apply": false,
    "review_required": true
  },
  "verified": false
}`;

const cliSample = `# Illustrative only — no CLI package is published yet.
$ vibecheck auth --read-only
$ vibecheck scan --path .

  analyzing 214 files
  routes 38  handlers 52  tables 9

  4 findings  ·  1 high  ·  2 medium  ·  1 low

$ vibecheck explain vbc_1042
$ vibecheck verify vbc_1042 --after-fix`;

const sdkSample = `// Illustrative usage of the intended API.
const res = await fetch("https://api.vibecheck.dev/v1/findings/vbc_1042", {
  headers: { Authorization: \`Bearer \${process.env.VIBECHECK_TOKEN}\` },
});

if (!res.ok) throw new Error(\`VibeCheck \${res.status}\`);

const finding = await res.json();
console.log(finding.severity, finding.location.file);`;

const endpoints = [
  { method: "GET", path: "/v1/projects", intent: "List connected projects and last analysis time." },
  { method: "POST", path: "/v1/scans", intent: "Request an analysis run for a branch or commit." },
  { method: "GET", path: "/v1/findings/:id", intent: "Fetch a finding with evidence and explanation." },
  { method: "POST", path: "/v1/findings/:id/verify", intent: "Re-test a recorded finding after a fix." },
];

export default function DevelopersPage() {
  return (
    <>
      <PageHeader
        code="05"
        eyebrow="Developers"
        title="Findings you can read at 2am without a translator."
        description="VibeCheck is built for people who ship. That means evidence instead of adjectives, machine-readable output alongside the explanation, and a fix suggestion that shows the diff before it asks for trust."
        meta={[
          { label: "API status", value: "Design preview" },
          { label: "CLI", value: "Not published" },
          { label: "Auth model", value: "Scoped tokens" },
          { label: "Output", value: "JSON + Markdown" },
        ]}
      />

      {/* Philosophy */}
      <section aria-labelledby="philosophy-heading" className="section">
        <div className="shell">
          <div className="grid gap-10 lg:grid-cols-[0.9fr_1fr] lg:gap-16">
            <Reveal>
              <p className="mono text-ash">Philosophy</p>
              <h2 id="philosophy-heading" className="display display-section mt-5 max-w-[16ch] text-fog">
                Security output should survive scrutiny.
              </h2>
              <p className="lede mt-6 max-w-[42ch]">
                A finding that cannot be traced to a line of code is an opinion.
                The interface is designed to make the trace the first thing you
                see, not a disclosure panel three clicks down.
              </p>
            </Reveal>

            <div className="grid gap-px border border-hairline bg-hairline-soft">
              {[
                {
                  icon: <ShieldQuestion />,
                  title: "Show the reasoning",
                  body:
                    "Rule, location, evidence and precondition are part of the finding schema — not a tooltip. If the reasoning is weak, that should be visible immediately.",
                },
                {
                  icon: <Terminal />,
                  title: "Readable by machines",
                  body:
                    "Everything in the UI has a JSON equivalent, so a finding can gate a pipeline without scraping a dashboard.",
                },
                {
                  icon: <GitBranch />,
                  title: "Never act silently",
                  body:
                    "The API can propose a patch. It cannot commit one. Write access is a separate, explicit decision.",
                },
              ].map((item) => (
                <div key={item.title} className="bg-void p-6">
                  <span className="text-lavender [&_svg]:h-4 [&_svg]:w-4">{item.icon}</span>
                  <h3 className="mt-4 font-display text-[16px] tracking-[-0.02em] text-fog">
                    {item.title}
                  </h3>
                  <p className="body-copy mt-2 text-[13px]">{item.body}</p>
                </div>
              ))}
            </div>
          </div>
        </div>
      </section>

      {/* Example findings */}
      <section id="findings" aria-labelledby="findings-heading" className="section hair-t scroll-mt-24 bg-abyss">
        <div className="shell">
          <div className="flex flex-wrap items-end justify-between gap-4">
            <div>
              <p className="mono text-ash">Example findings</p>
              <h2 id="findings-heading" className="display display-section mt-4 max-w-[18ch] text-fog">
                Three shapes of the same problem.
              </h2>
            </div>
            <span className="chip chip-planned">Illustrative data</span>
          </div>

          <div className="mt-12 grid gap-6 lg:grid-cols-3">
            <Reveal>
              <FindingPanel compact />
            </Reveal>

            <Reveal delay={0.06}>
              <div className="panel h-full p-5">
                <div className="flex items-center justify-between">
                  <span className="mono text-ash">Secret exposure</span>
                  <span className="chip chip-dev">Medium</span>
                </div>
                <h3 className="mt-4 font-display text-[17px] leading-snug tracking-[-0.02em] text-fog">
                  Live service key committed in <span className="font-mono text-[15px] text-lavender">.env.example</span>
                </h3>
                <p className="mono-sm mt-2 text-ash">.env.example · line 14 · confidence: high</p>
                <p className="body-copy mt-4 text-[13px]">
                  The file is committed and referenced by the setup guide. The key
                  shape matches a production secret rather than a placeholder, so
                  the recommendation is rotation, not deletion.
                </p>
                <div className="mt-4 border border-hairline-soft bg-[#0a0911] p-3">
                  <pre className="overflow-x-auto font-mono text-[10.5px] leading-relaxed text-[#cfc9e6]">
{`STRIPE_SECRET=sk_live_••••••••••••
# ^ committed, not a placeholder`}
                  </pre>
                </div>
                <p className="mono-sm mt-4 text-ash">
                  Suggested: revoke, rotate, then move to a server-only variable.
                </p>
              </div>
            </Reveal>

            <Reveal delay={0.12}>
              <div className="panel h-full p-5">
                <div className="flex items-center justify-between">
                  <span className="mono text-ash">Dependency</span>
                  <span className="chip chip-planned">Low</span>
                </div>
                <h3 className="mt-4 font-display text-[17px] leading-snug tracking-[-0.02em] text-fog">
                  Transitive package pinned below the patched range
                </h3>
                <p className="mono-sm mt-2 text-ash">package-lock.json · confidence: medium</p>
                <p className="body-copy mt-4 text-[13px]">
                  The advisory applies to a build-time parser that is reachable from
                  the configured pipeline, but not from request handling. Severity is
                  reported with its reachability, not on the advisory alone.
                </p>
                <ul className="mt-4 space-y-2">
                  {[
                    "direct dependency: build tool",
                    "request path: not reachable",
                    "fix: bump range in lockfile",
                  ].map((line) => (
                    <li key={line} className="mono-sm flex gap-2.5 text-muted">
                      <span className="mt-1.5 h-1 w-1 shrink-0 bg-violet-bright" aria-hidden="true" />
                      {line}
                    </li>
                  ))}
                </ul>
                <p className="mono-sm mt-4 text-ash">
                  Reachability context is in development, not shipped.
                </p>
              </div>
            </Reveal>
          </div>
        </div>
      </section>

      {/* API */}
      <section id="api" aria-labelledby="api-heading" className="section hair-t scroll-mt-24">
        <div className="shell">
          <div className="grid gap-10 lg:grid-cols-[0.85fr_1fr] lg:gap-16">
            <Reveal>
              <p className="mono text-ash">API design preview</p>
              <h2 id="api-heading" className="display display-section mt-5 max-w-[16ch] text-fog">
                One finding, one readable object.
              </h2>
              <p className="lede mt-6 max-w-[40ch]">
                The response below is the schema we are building against. It is a
                preview, not a live endpoint — no public API exists yet.
              </p>

              <div className="mt-8 border border-hairline">
                {endpoints.map((endpoint) => (
                  <div
                    key={endpoint.path}
                    className="grid grid-cols-[46px_1fr] gap-x-4 gap-y-1 border-b border-hairline-soft px-4 py-3 last:border-b-0 sm:grid-cols-[46px_170px_1fr]"
                  >
                    <span className="mono-sm text-lavender">{endpoint.method}</span>
                    <span className="font-mono text-[11.5px] text-fog">{endpoint.path}</span>
                    <span className="col-span-2 body-copy text-[12px] sm:col-span-1">
                      {endpoint.intent}
                    </span>
                  </div>
                ))}
              </div>
              <div className="mt-4 flex flex-wrap items-center gap-2">
                <StatusChip status="planned" />
                <span className="mono-sm text-ash">No keys are issued yet.</span>
              </div>
            </Reveal>

            <Reveal delay={0.06} className="space-y-5">
              <CodeBlock
                filename="GET /v1/findings/vbc_1042"
                language="json"
                code={findingJson}
              />
              <div className="grid gap-3 sm:grid-cols-3">
                {[
                  ["anonymous? ", "no"],
                  ["auto-apply", "disabled"],
                  ["review", "required"],
                ].map(([label, value]) => (
                  <div key={label} className="border border-hairline px-3 py-2.5">
                    <p className="mono-sm text-ash">{label}</p>
                    <p className="mt-1 font-mono text-[11px] text-lavender">{value}</p>
                  </div>
                ))}
              </div>
            </Reveal>
          </div>
        </div>
      </section>

      {/* Getting started */}
      <section id="start" aria-labelledby="start-heading" className="section hair-t scroll-mt-24 bg-abyss">
        <div className="shell">
          <div className="flex flex-wrap items-end justify-between gap-4">
            <div>
              <p className="mono text-ash">Getting started</p>
              <h2 id="start-heading" className="display display-section mt-4 max-w-[20ch] text-fog">
                Three commands, when they exist.
              </h2>
            </div>
            <span className="chip chip-planned">Not runnable</span>
          </div>

          <div className="mt-10 grid gap-6 lg:grid-cols-2">
            <Reveal>
              <CodeBlock filename="terminal" language="shell" code={cliSample} />
              <p className="mono-sm mt-3 text-ash">
                Illustrative. The CLI is not published and these commands will fail.
              </p>
            </Reveal>
            <Reveal delay={0.06}>
              <CodeBlock filename="finding.ts" language="typescript" code={sdkSample} />
              <p className="mono-sm mt-3 text-ash">
                Illustrative. api.vibecheck.dev does not serve public requests.
              </p>
            </Reveal>
          </div>

          <div className="mt-12 grid gap-px border border-hairline bg-hairline-soft md:grid-cols-3">
            {[
              {
                step: "01",
                title: "Ask for early access",
                body: "Early access is the only route in while the build is private. Bring a repository you own.",
              },
              {
                step: "02",
                title: "Connect read-only",
                body: "Scope the installation to a single project. Revoke it whenever you want.",
              },
              {
                step: "03",
                title: "Disagree with us",
                body: "False positives are the useful signal early on. Each one becomes a rule discussion.",
              },
            ].map((item) => (
              <div key={item.step} className="bg-void p-6">
                <span className="mono-sm text-violet-bright">{item.step}</span>
                <h3 className="mt-3 font-display text-[16px] tracking-[-0.02em] text-fog">
                  {item.title}
                </h3>
                <p className="body-copy mt-2 text-[13px]">{item.body}</p>
              </div>
            ))}
          </div>

          <Reveal className="mt-10">
            <div className="flex flex-col gap-5 border border-hairline bg-surface/50 p-6 sm:flex-row sm:items-center sm:justify-between">
              <div className="flex items-start gap-3">
                <BookOpen className="mt-0.5 h-4 w-4 shrink-0 text-lavender" aria-hidden="true" />
                <div>
                  <h3 className="font-display text-[16px] tracking-[-0.02em] text-fog">
                    Documentation
                  </h3>
                  <p className="body-copy mt-1 max-w-[52ch] text-[13px]">
                    Reference docs open with the private beta. There is no public
                    documentation site to link to yet, and we are not going to
                    invent one.
                  </p>
                </div>
              </div>
              <Link href="/about#early-access" className="btn btn-outline shrink-0">
                Request access
                <ArrowRight className="h-3.5 w-3.5" aria-hidden="true" />
              </Link>
            </div>
          </Reveal>
        </div>
      </section>

      <EarlyAccessCTA
        index="08"
        title="Build with us, not around us."
        copy="If you are shipping AI-assisted software and want the analysis to understand your stack, early access is how that conversation starts."
      />
    </>
  );
}
