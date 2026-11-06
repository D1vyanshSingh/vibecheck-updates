import type { Metadata } from "next";
import Link from "next/link";
import { ArrowRight } from "lucide-react";
import { PageHeader } from "@/components/sections/PageHeader";
import { Reveal } from "@/components/animations/Reveal";
import { FlowDiagram } from "@/components/sections/FlowDiagram";
import { StatusChip } from "@/components/ui/StatusChip";
import { EarlyAccessCTA } from "@/components/sections/EarlyAccessCTA";
import { workflowSteps } from "@/lib/content";
import { cn } from "@/lib/cn";

export const metadata: Metadata = {
  title: "How It Works",
  description:
    "From connecting a repository to verifying a fix: the six-step VibeCheck workflow, with the automation boundary stated for each step.",
  alternates: { canonical: "/how-it-works" },
};

const artifacts: Record<string, { label: string; lines: string[] }> = {
  "01": {
    label: "connection",
    lines: [
      "$ vibecheck connect",
      "→ requesting read-only repository scope",
      "→ installation: acme/web-app",
      "✓ connected  branches: 1  files: 214",
      "· no write access requested",
    ],
  },
  "02": {
    label: "analysis",
    lines: [
      "parsing  214 files",
      "routes   38   handlers 52",
      "tables   9    policies 7",
      "config   4    env refs 12",
      "⚠ 2 tables have RLS enabled with no policy",
    ],
  },
  "03": {
    label: "findings",
    lines: [
      "VBC-1042  high    invoices: missing RLS policy",
      "VBC-1039  medium  src/lib/upload.ts: public bucket",
      "VBC-1031  medium  .env.example: live key shape",
      "VBC-1027  low     next.config.js: permissive CORS",
      "4 findings · 1 requires immediate review",
    ],
  },
  "04": {
    label: "explanation",
    lines: [
      "attack surface   anon key + REST",
      "precondition     authenticated client",
      "impact           reads all tenant invoices",
      "confidence       high",
      "reachability     confirmed via /api/invoices",
    ],
  },
  "05": {
    label: "patch preview",
    lines: [
      "+ create policy \"own invoices\" on public.invoices",
      "+   for select",
      "+   using (auth.uid() = owner_id);",
      "",
      "· 1 file changed · not applied",
      "· review required before merge",
    ],
  },
  "06": {
    label: "verification",
    lines: [
      "re-testing VBC-1042",
      "✓ policy present",
      "✓ ownership filter matches auth.uid()",
      "✓ second-user read denied",
      "status: verified · 2026-11-06",
    ],
  },
};

const automationTone: Record<string, string> = {
  automated: "border-lavender/35 text-lavender",
  assisted: "border-white/15 text-muted",
  manual: "border-white/10 text-ash",
};

export default function HowItWorksPage() {
  return (
    <>
      <PageHeader
        code="03"
        eyebrow="How it works"
        title="A workflow that ends in evidence, not a score."
        description="Connect a project, let the analysis map it, read the findings and their reasoning, apply what you agree with, then re-test the exact issue. Every step below states what is automated and what is not."
        meta={[
          { label: "Steps", value: "Six" },
          { label: "Analysis type", value: "Static" },
          { label: "Fix application", value: "Manual" },
          { label: "Availability", value: "Private beta" },
        ]}
      />

      <section aria-labelledby="model-heading" className="section">
        <div className="shell grid gap-12 lg:grid-cols-[0.95fr_1.1fr] lg:gap-16">
          <Reveal>
            <p className="mono text-ash">The model</p>
            <h2 id="model-heading" className="display display-section mt-5 max-w-[15ch] text-fog">
              Four surfaces, one inspection plane.
            </h2>
            <p className="lede mt-6 max-w-[44ch]">
              A generated application is not only code. It is a schema, an
              authentication model and a deployment configuration that were
              assembled separately and rarely reviewed together.
            </p>
            <div className="mt-8 space-y-4">
              {[
                "Code defines what the application can be asked to do.",
                "Data policies decide whose rows come back.",
                "Auth determines who can ask at all.",
                "Deployment decides which defaults are live.",
              ].map((line, index) => (
                <div key={line} className="flex gap-4 border-t border-hairline-soft pt-3">
                  <span className="mono-sm text-violet-bright">0{index + 1}</span>
                  <p className="body-copy text-[13px]">{line}</p>
                </div>
              ))}
            </div>
          </Reveal>
          <Reveal delay={0.06}>
            <FlowDiagram className="border border-hairline bg-void/70 p-2" />
            <p className="mono-sm mt-3 text-ash">
              Conceptual diagram. No runtime agent is installed on your systems.
            </p>
          </Reveal>
        </div>
      </section>

      <section aria-labelledby="steps-heading" className="section hair-t bg-abyss">
        <div className="shell">
          <div className="flex items-center gap-4">
            <span className="mono-sm text-violet-bright">01 — 06</span>
            <span className="mono text-ash">The workflow</span>
            <span className="h-px flex-1 bg-hairline" aria-hidden="true" />
          </div>
          <h2 id="steps-heading" className="display display-section mt-6 max-w-[18ch] text-fog">
            Six steps, in the order they happen.
          </h2>

          <ol className="mt-14">
            {workflowSteps.map((step, index) => {
              const artifact = artifacts[step.index];
              return (
                <li key={step.index} className="border-t border-hairline">
                  <Reveal className="grid gap-8 py-10 md:grid-cols-[72px_1fr_1fr] md:gap-10 md:py-12">
                    <div className="flex items-baseline gap-3 md:flex-col md:gap-4">
                      <span className="font-display text-[34px] leading-none tracking-[-0.05em] text-[#2b2442]">
                        {step.index}
                      </span>
                      <span
                        className={cn(
                          "chip",
                          automationTone[step.automation],
                        )}
                      >
                        {step.automation}
                      </span>
                    </div>

                    <div>
                      <h3 className="display-sub text-fog">{step.title}</h3>
                      <p className="body-copy mt-3 max-w-[46ch]">{step.summary}</p>
                      <p className="body-copy mt-3 max-w-[46ch] text-[12.5px] text-ash">
                        {step.detail}
                      </p>
                      <p className="mono-sm mt-4 text-lavender">{step.automationNote}</p>
                    </div>

                    <div className="panel bg-[#0a0911]">
                      <div className="flex items-center justify-between border-b border-hairline-soft px-3 py-2">
                        <span className="mono-sm text-ash">{artifact.label}</span>
                        <span className="mono-sm text-ash">illustrative</span>
                      </div>
                      <pre className="overflow-x-auto p-3 font-mono text-[10.5px] leading-[1.9] text-[#cfc9e6] sm:text-[11px]">
{artifact.lines.join("\n")}
                      </pre>
                    </div>
                  </Reveal>
                </li>
              );
            })}
          </ol>
          <p className="mono-sm mt-4 text-ash">
            Output shown is a demonstration of format. Nothing here is a live scan.
          </p>
        </div>
      </section>

      <section aria-labelledby="boundary-heading" className="section hair-t">
        <div className="shell">
          <div className="grid gap-10 lg:grid-cols-[0.85fr_1fr] lg:gap-16">
            <Reveal>
              <h2 id="boundary-heading" className="display display-section max-w-[16ch] text-fog">
                Where the automation stops.
              </h2>
              <p className="lede mt-6 max-w-[42ch]">
                Automation is useful until it acts on something it does not
                understand. This is the line we are drawing.
              </p>
              <Link
                href="/platform"
                className="mono mt-8 inline-flex items-center gap-2 text-lavender hover:text-fog"
              >
                Platform modules
                <ArrowRight className="h-3.5 w-3.5" aria-hidden="true" />
              </Link>
            </Reveal>

            <div className="grid gap-px border border-hairline bg-hairline-soft">
              {[
                {
                  label: "Automated",
                  status: "mvp" as const,
                  items: [
                    "Repository reading and file mapping",
                    "Static rule evaluation",
                    "Secret-pattern detection",
                    "Re-test of a recorded finding",
                  ],
                },
                {
                  label: "Assisted",
                  status: "development" as const,
                  items: [
                    "Plain-language risk explanation",
                    "Suggested patch generation",
                    "Prioritisation by reachability",
                  ],
                },
                {
                  label: "Human",
                  status: "planned" as const,
                  items: [
                    "Accepting or rejecting a fix",
                    "Merging and deploying",
                    "Deciding business-logic risk",
                    "Signing off a release",
                  ],
                },
              ].map((group) => (
                <div key={group.label} className="bg-void p-6">
                  <div className="flex items-center justify-between gap-4">
                    <h3 className="mono text-fog">{group.label}</h3>
                    <StatusChip status={group.status} />
                  </div>
                  <ul className="mt-4 space-y-2.5">
                    {group.items.map((item) => (
                      <li key={item} className="flex gap-3">
                        <span className="mt-2 h-1 w-1 shrink-0 bg-violet-bright" aria-hidden="true" />
                        <span className="text-[13.5px] text-muted">{item}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              ))}
            </div>
          </div>
        </div>
      </section>

      <EarlyAccessCTA
        index="07"
        title="See the workflow against your own project."
        copy="Early access is the only way to run the current build. Bring a repository you own and we will walk the six steps with you."
      />
    </>
  );
}
