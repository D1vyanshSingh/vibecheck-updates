import Link from "next/link";
import { ArrowRight, ArrowUpRight } from "lucide-react";
import { Hero } from "@/components/sections/Hero";
import { Reveal } from "@/components/animations/Reveal";
import { SectionHead } from "@/components/ui/SectionHead";
import { StatusChip } from "@/components/ui/StatusChip";
import { FindingPanel } from "@/components/ui/FindingPanel";
import { FlowDiagram } from "@/components/sections/FlowDiagram";
import { EarlyAccessCTA } from "@/components/sections/EarlyAccessCTA";
import { capabilities, integrations, workflowSteps } from "@/lib/content";

const surface = [
  {
    id: "01",
    label: "Generated code",
    detail: "Routes, handlers and query builders produced in a single session.",
    value: "UNREVIEWED",
  },
  {
    id: "02",
    label: "Secrets",
    detail: "Keys pasted into env files, then copied into a client bundle.",
    value: "EXPOSED",
  },
  {
    id: "03",
    label: "Dependencies",
    detail: "Packages added on suggestion, pinned to nothing in particular.",
    value: "UNAUDITED",
  },
  {
    id: "04",
    label: "Access rules",
    detail: "Tables created before the policy that scopes them.",
    value: "OPEN",
  },
  {
    id: "05",
    label: "Deployment",
    detail: "Development defaults inherited by the production build.",
    value: "INHERITED",
  },
];

export default function HomePage() {
  return (
    <>
      <Hero />

      {/* 01 — The shift */}
      <section aria-labelledby="shift-heading" className="section hair-t">
        <div className="shell">
          <SectionHead
            index="01"
            eyebrow="The shift"
            title={
              <span id="shift-heading">
                Software now ships faster than security can review it.
              </span>
            }
            description="AI assistants write whole features between meetings. The speed is real, and worth keeping. What it breaks is the assumption that somebody read every line before it reached a database, a bucket or a payment flow."
          />

          <div className="mt-14 grid gap-10 lg:mt-20 lg:grid-cols-[1fr_1fr] lg:gap-20">
            <Reveal className="flex flex-col justify-between">
              <div className="space-y-5">
                <p className="body-copy">
                  For twenty years, application security was built around a
                  reviewable pace: a pull request, a reviewer, a merge. Tooling
                  followed the same assumption — scan after the fact, file a
                  ticket, wait for a sprint.
                </p>
                <p className="body-copy">
                  A generated codebase does not have that rhythm. It is assembled
                  quickly, often by someone who is learning the framework as they
                  go, and it inherits every default the scaffolding shipped with.
                  The result is not obviously broken. It runs, it looks right, and
                  the weakest point is usually a missing condition rather than a
                  syntax error.
                </p>
                <p className="body-copy">
                  VibeCheck is being built for that code: small teams, fast
                  shipping, and no security department to hand the review to.
                </p>
              </div>

              <div className="mt-10 border border-hairline bg-surface/60 p-5">
                <p className="mono-sm text-ash">What we are not claiming</p>
                <p className="body-copy mt-2 text-[12.5px]">
                  We do not publish adoption numbers, detection rates or customer
                  logos. The product is in development, and this site says so
                  everywhere it matters.
                </p>
              </div>
            </Reveal>

            <Reveal delay={0.08}>
              <div className="rule-row">
                {surface.map((row) => (
                  <div key={row.id} className="rule-row grid gap-2 py-4 sm:grid-cols-[auto_1fr_auto] sm:items-baseline sm:gap-5">
                    <span className="mono-sm text-violet-bright">{row.id}</span>
                    <div>
                      <p className="font-display text-[15px] tracking-[-0.015em] text-fog">
                        {row.label}
                      </p>
                      <p className="body-copy mt-1 text-[12.5px]">{row.detail}</p>
                    </div>
                    <span className="mono-sm text-ash sm:text-right">{row.value}</span>
                  </div>
                ))}
              </div>
              <p className="mono-sm mt-4 text-ash">
                The surface VibeCheck is designed to inspect — not a claim of
                complete coverage.
              </p>
            </Reveal>
          </div>
        </div>
      </section>

      {/* 02 — Why appsec must evolve */}
      <section aria-labelledby="evolve-heading" className="section hair-t bg-abyss">
        <div className="shell">
          <SectionHead
            index="02"
            eyebrow="Why security has to change"
            title={
              <span id="evolve-heading">
                Review was built for human authors and human speed.
              </span>
            }
            description="The tools are not wrong — they are pointed at the wrong cadence. Three assumptions no longer hold for AI-built applications."
          />

          <div className="mt-14 grid gap-0 lg:mt-20">
            {[
              {
                label: "Authorship",
                title: "Every line has an author, and it is rarely the person shipping it.",
                body:
                  "When a model proposes the route, the query and the policy, review becomes a formality unless the reviewer actually understands the pattern being generated. Security knowledge has to be attached to the finding, not assumed at the reader.",
              },
              {
                label: "Cadence",
                title: "A weekly scan is a historical document.",
                body:
                  "Applications now change in hours. Verification has to run close to the change, and re-run after the fix, otherwise a green report describes a version of the code that no longer exists.",
              },
              {
                label: "Evidence",
                title: "A badge is not proof, and confidence is not certainty.",
                body:
                  "Static analysis produces hypotheses. Some are correct, some are noise, and a few are correct but unreachable. A credible product shows the evidence, states the precondition, and lets a human disagree.",
              },
            ].map((row, index) => (
              <Reveal key={row.label} delay={index * 0.06}>
                <div className="grid gap-4 border-t border-hairline py-8 md:grid-cols-[140px_1fr_1.1fr] md:gap-10">
                  <span className="mono text-violet-bright">{row.label}</span>
                  <h3 className="display-sub max-w-[26ch] text-fog">{row.title}</h3>
                  <p className="body-copy max-w-[54ch]">{row.body}</p>
                </div>
              </Reveal>
            ))}
            <div className="border-t border-hairline" />
          </div>
        </div>
      </section>

      {/* 03 — How it works */}
      <section aria-labelledby="workflow-heading" className="section hair-t">
        <div className="shell">
          <SectionHead
            index="03"
            eyebrow="How VibeCheck works"
            title={<span id="workflow-heading">Six steps, and the last one proves it.</span>}
            description="A workflow built around verification rather than a score. Each step states what is automated and what stays in human hands."
            aside={
              <Link
                href="/how-it-works"
                className="mono inline-flex items-center gap-2 text-lavender transition-colors hover:text-fog"
              >
                See the full workflow
                <ArrowRight className="h-3.5 w-3.5" aria-hidden="true" />
              </Link>
            }
          />

          <ol className="mt-14 grid gap-px border border-hairline bg-hairline-soft sm:grid-cols-2 lg:grid-cols-3">
            {workflowSteps.map((step, index) => (
              <li key={step.index} className="bg-void">
                <Reveal delay={index * 0.04} className="flex h-full flex-col gap-4 p-6">
                  <div className="flex items-baseline justify-between">
                    <span className="font-display text-[30px] leading-none tracking-[-0.05em] text-[#2a2340]">
                      {step.index}
                    </span>
                    <span className="mono-sm text-ash">{step.automation}</span>
                  </div>
                  <h3 className="display-sub text-fog">{step.title}</h3>
                  <p className="body-copy text-[13px]">{step.summary}</p>
                </Reveal>
              </li>
            ))}
          </ol>

          <p className="mono-sm mt-5 text-ash">
            Automation labels reflect the current design, not a shipped product.
          </p>
        </div>
      </section>

      {/* 04 — Platform capabilities */}
      <section aria-labelledby="capabilities-heading" className="section hair-t bg-abyss">
        <div className="shell">
          <SectionHead
            index="04"
            eyebrow="Platform capabilities"
            title={<span id="capabilities-heading">Eight checks, one readable report.</span>}
            description="Capabilities are grouped by the surface they inspect. Status is stated honestly — the MVP is deliberately narrow."
            aside={
              <Link
                href="/platform"
                className="mono inline-flex items-center gap-2 text-lavender transition-colors hover:text-fog"
              >
                Explore the platform
                <ArrowUpRight className="h-3.5 w-3.5" aria-hidden="true" />
              </Link>
            }
          />

          <div className="mt-14 grid gap-px border border-hairline bg-hairline-soft md:grid-cols-2">
            {capabilities.map((capability, index) => (
              <Reveal key={capability.id} delay={index * 0.03} className="bg-void">
                <Link
                  href={`/platform#${capability.id}`}
                  className="group flex h-full flex-col gap-4 p-6 transition-colors duration-300 hover:bg-surface sm:p-7"
                >
                  <div className="flex items-center justify-between gap-4">
                    <span className="mono-sm text-violet-bright">{capability.index}</span>
                    <StatusChip status={capability.status} />
                  </div>
                  <h3 className="display-sub text-fog">{capability.title}</h3>
                  <p className="body-copy flex-1 text-[13px]">{capability.summary}</p>
                  <span className="mono-sm flex items-center gap-2 text-ash transition-colors group-hover:text-lavender">
                    Read the module
                    <ArrowRight className="h-3 w-3 transition-transform duration-300 group-hover:translate-x-0.5" aria-hidden="true" />
                  </span>
                </Link>
              </Reveal>
            ))}
          </div>
        </div>
      </section>

      {/* 05 — Integrations */}
      <section aria-labelledby="integrations-heading" className="section hair-t">
        <div className="shell">
          <SectionHead
            index="05"
            eyebrow="Integrations"
            title={<span id="integrations-heading">Where your code already lives.</span>}
            description="VibeCheck is designed to meet a project in the tools it was built in. Nothing below is advertised as a working public integration."
          />

          <div className="marquee-mask mt-12 overflow-hidden border-y border-hairline py-6">
            <div className="marquee-track items-center gap-10">
              {[0, 1].map((copy) => (
                <div key={copy} className="flex items-center gap-10" aria-hidden={copy === 1}>
                  {integrations.map((integration) => (
                    <div key={`${copy}-${integration.name}`} className="flex items-center gap-3">
                      <span className="flex h-7 w-7 items-center justify-center border border-hairline font-mono text-[9px] tracking-[0.08em] text-lavender">
                        {integration.glyph}
                      </span>
                      <span className="font-display text-[17px] tracking-[-0.02em] text-fog">
                        {integration.name}
                      </span>
                      <span className="mono-sm text-ash">
                        {integration.status === "development" ? "In dev" : "Planned"}
                      </span>
                      <span className="h-1 w-1 bg-[#2a2340]" aria-hidden="true" />
                    </div>
                  ))}
                </div>
              ))}
            </div>
          </div>

          <div className="mt-8 flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
            <p className="mono-sm max-w-[38rem] text-ash">
              No public integration is live. GitHub is in private development; the
              rest are planned or under research.
            </p>
            <Link
              href="/integrations"
              className="mono inline-flex items-center gap-2 text-lavender transition-colors hover:text-fog"
            >
              Integration status
              <ArrowRight className="h-3.5 w-3.5" aria-hidden="true" />
            </Link>
          </div>
        </div>
      </section>

      {/* 06 — Verification concept */}
      <section aria-labelledby="verification-heading" className="section hair-t bg-abyss">
        <div className="shell">
          <SectionHead
            index="06"
            eyebrow="Verification layer · working name"
            title={<span id="verification-heading">A finding is a claim. Verification is the proof.</span>}
            description="Most scanners stop at the report. VibeCheck is designed around a loop: locate the weakness, explain it, propose a fix, then re-test the exact finding and keep the record."
          />

          <div className="mt-14 grid gap-10 lg:grid-cols-[0.95fr_1fr] lg:gap-16">
            <Reveal>
              <FlowDiagram className="border border-hairline bg-void/60 p-2" />
            </Reveal>

            <div className="flex flex-col justify-center gap-8">
              <div className="rule-row">
                {[
                  {
                    step: "Locate",
                    body: "The rule, the file, the line, and the surrounding context that made it match.",
                  },
                  {
                    step: "Explain",
                    body: "What an attacker gains, what has to be true first, and how confident the analysis is.",
                  },
                  {
                    step: "Fix",
                    body: "A patch direction written for your framework. You review it; nothing is committed for you.",
                  },
                  {
                    step: "Verify",
                    body: "The original finding is re-run. It closes on evidence, not on a checkbox.",
                  },
                ].map((item) => (
                  <div key={item.step} className="rule-row grid gap-1 py-4 sm:grid-cols-[92px_1fr] sm:gap-6">
                    <span className="mono text-lavender">{item.step}</span>
                    <p className="body-copy text-[13px]">{item.body}</p>
                  </div>
                ))}
              </div>

              <div className="panel p-5">
                <div className="flex items-center justify-between gap-4">
                  <p className="mono-sm text-ash">Status of this concept</p>
                  <StatusChip status="planned" />
                </div>
                <p className="body-copy mt-3 text-[12.5px]">
                  Verification records and continuous monitoring are planned. Manual
                  re-runs of individual findings are the near-term design; nothing
                  on this page implies an automated guarantee.
                </p>
              </div>
            </div>
          </div>

          <Reveal className="mt-14">
            <div className="grid gap-6 border-t border-hairline pt-10 lg:grid-cols-[0.9fr_1.1fr] lg:gap-16">
              <div>
                <p className="mono text-ash">What the report looks like</p>
                <h3 className="display-sub mt-4 max-w-[24ch] text-fog">
                  Evidence you can check, written for the person who has to fix it.
                </h3>
                <p className="body-copy mt-4 max-w-[46ch] text-[13.5px]">
                  This panel is a static demonstration of the intended finding
                  format. It is sample content, not a scan of a real repository.
                </p>
              </div>
              <FindingPanel />
            </div>
          </Reveal>
        </div>
      </section>

      <EarlyAccessCTA index="07" />
    </>
  );
}
