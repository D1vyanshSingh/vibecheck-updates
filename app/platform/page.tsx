import type { Metadata } from "next";
import Link from "next/link";
import { ArrowRight, ArrowUpRight, ShieldAlert } from "lucide-react";
import { PageHeader } from "@/components/sections/PageHeader";
import { PlatformExplorer } from "@/components/sections/PlatformExplorer";
import { Reveal } from "@/components/animations/Reveal";
import { StatusChip } from "@/components/ui/StatusChip";
import { FindingPanel } from "@/components/ui/FindingPanel";
import { EarlyAccessCTA } from "@/components/sections/EarlyAccessCTA";
import { capabilities } from "@/lib/content";

export const metadata: Metadata = {
  title: "Platform",
  description:
    "Code security, secret exposure, dependency risk, database and access-control checks, configuration review, AI-assisted explanations, remediation guidance and verification — with honest status labels.",
  alternates: { canonical: "/platform" },
};

const limits = [
  {
    title: "No runtime guarantee",
    body: "Analysis is static in the current design. It reasons about code and configuration; it does not prove that a running deployment behaves safely.",
  },
  {
    title: "Coverage is finite",
    body: "Rule-based detection finds the patterns it knows. Business-logic flaws and novel attack paths are outside what a scanner can honestly promise.",
  },
  {
    title: "Explanations are drafts",
    body: "Model-written context is a reading aid, grounded in matched evidence. It can be wrong, and it is always presented with confidence and preconditions.",
  },
  {
    title: "No silent changes",
    body: "VibeCheck proposes patches. It does not commit, merge or deploy. The decision and the responsibility stay with you.",
  },
];

export default function PlatformPage() {
  return (
    <>
      <PageHeader
        code="02"
        eyebrow="Platform"
        title="Security checks that read the way you built the app."
        description="VibeCheck examines the layers an AI-built application actually depends on: source, secrets, dependencies, data policies, configuration and the deployment that ties them together. Each module is labelled with what exists today."
        meta={[
          { label: "MVP modules", value: "02", status: <StatusChip status="mvp" compact /> },
          { label: "In development", value: "04", status: <StatusChip status="development" compact /> },
          { label: "Planned", value: "02", status: <StatusChip status="planned" compact /> },
          { label: "Deployment", value: "Private beta" },
        ]}
      />

      <PlatformExplorer />

      {/* Legend */}
      <section className="relative py-10">
        <div className="shell flex flex-col gap-5 lg:flex-row lg:items-center lg:justify-between">
          <div className="flex flex-wrap items-center gap-3">
            <span className="mono-sm text-ash">Status key</span>
            <StatusChip status="mvp" />
            <StatusChip status="development" />
            <StatusChip status="planned" />
          </div>
          <p className="mono-sm max-w-[42rem] text-ash">
            Modules are never described as available unless they run today.
          </p>
        </div>
      </section>

      {/* Modules */}
      <div className="shell">
        {capabilities.map((capability, index) => (
          <section
            key={capability.id}
            id={capability.id}
            aria-labelledby={`${capability.id}-title`}
            className="scroll-mt-24 border-t border-hairline py-14 md:py-20"
          >
            <div className="grid gap-10 lg:grid-cols-[0.34fr_1fr] lg:gap-16">
              <Reveal className="lg:sticky lg:top-28 lg:self-start">
                <div className="flex items-baseline gap-4">
                  <span className="font-display text-[44px] leading-none tracking-[-0.05em] text-[#2b2442]">
                    {capability.index}
                  </span>
                  <StatusChip status={capability.status} />
                </div>
                <h2 id={`${capability.id}-title`} className="display display-sub mt-6 text-fog">
                  {capability.title}
                </h2>
                <p className="mono-sm mt-4 text-ash">Module / {capability.index}</p>
              </Reveal>

              <Reveal delay={0.05} className="grid gap-8 md:grid-cols-[1.25fr_0.75fr] md:gap-12">
                <div>
                  <p className="font-display text-[clamp(1.15rem,1.7vw,1.5rem)] leading-[1.25] tracking-[-0.025em] text-fog">
                    {capability.summary}
                  </p>
                  <p className="body-copy mt-5 max-w-[60ch]">{capability.detail}</p>
                  <div className="mt-7 flex flex-wrap gap-2">
                    {capability.signals.map((signal) => (
                      <span key={signal} className="chip">
                        {signal}
                      </span>
                    ))}
                  </div>
                </div>

                <aside className="panel flex flex-col justify-between p-5">
                  <div>
                    <p className="mono-sm text-ash">Status</p>
                    <p className="mt-2 text-[13.5px] text-fog">
                      {capability.status === "mvp"
                        ? "Runs in the current MVP build."
                        : capability.status === "development"
                          ? "Implemented in the private build; not ready for public use."
                          : "Designed, not implemented."}
                    </p>
                  </div>
                  <div className="mt-6 border-t border-hairline-soft pt-4">
                    <p className="mono-sm text-ash">Evidence kept</p>
                    <p className="body-copy mt-2 text-[12.5px]">
                      {capability.status === "planned"
                        ? "The evidence format is defined alongside implementation."
                        : "File, line, matched rule and surrounding context."}
                    </p>
                  </div>
                </aside>
              </Reveal>
            </div>
          </section>
        ))}
      </div>

      {/* Honest limits */}
      <section aria-labelledby="limits-heading" className="section hair-t bg-abyss">
        <div className="shell">
          <div className="grid gap-10 lg:grid-cols-[0.9fr_1fr] lg:gap-16">
            <Reveal>
              <div className="flex items-center gap-4">
                <span className="mono-sm text-violet-bright">09</span>
                <span className="mono text-ash">Limits, stated plainly</span>
              </div>
              <h2 id="limits-heading" className="display display-section mt-6 max-w-[16ch] text-fog">
                What this platform will not do for you.
              </h2>
              <p className="lede mt-6 max-w-[42ch]">
                Every security product has a boundary between what it checks and
                what you still have to think about. Ours is written down.
              </p>
              <div className="mt-8 inline-flex items-center gap-2 border border-hairline px-3 py-2">
                <ShieldAlert className="h-3.5 w-3.5 text-lavender" aria-hidden="true" />
                <span className="mono-sm text-muted">
                  Security is a practice, not a purchase order.
                </span>
              </div>
            </Reveal>

            <div>
              {limits.map((limit, index) => (
                <Reveal key={limit.title} delay={index * 0.05}>
                  <div className="rule-row grid gap-2 py-6 sm:grid-cols-[180px_1fr] sm:gap-8">
                    <h3 className="font-display text-[15px] tracking-[-0.015em] text-fog">
                      {limit.title}
                    </h3>
                    <p className="body-copy text-[13.5px]">{limit.body}</p>
                  </div>
                </Reveal>
              ))}
              <div className="border-t border-hairline" />
            </div>
          </div>

          <Reveal className="mt-16 grid gap-8 border-t border-hairline pt-12 lg:grid-cols-[0.9fr_1.1fr] lg:gap-16">
            <div>
              <p className="mono text-ash">Report format</p>
              <h3 className="display-sub mt-4 max-w-[22ch] text-fog">
                One finding, written so it can be argued with.
              </h3>
              <p className="body-copy mt-4 max-w-[44ch] text-[13.5px]">
                Demonstration content. Real reports carry the same structure, with
                the evidence taken from your repository.
              </p>
              <div className="mt-6 flex flex-wrap gap-3">
                <Link
                  href="/developers#findings"
                  className="mono inline-flex items-center gap-2 text-lavender hover:text-fog"
                >
                  More examples
                  <ArrowRight className="h-3.5 w-3.5" aria-hidden="true" />
                </Link>
                <Link
                  href="/how-it-works"
                  className="mono inline-flex items-center gap-2 text-muted hover:text-fog"
                >
                  How analysis runs
                  <ArrowUpRight className="h-3.5 w-3.5" aria-hidden="true" />
                </Link>
              </div>
            </div>
            <FindingPanel />
          </Reveal>
        </div>
      </section>

      <EarlyAccessCTA
        index="10"
        title="Get the narrow version before the wide one."
        copy="The MVP focuses on code and secrets precisely so the analysis can be trusted before scope grows. Early access puts you in that first group."
      />
    </>
  );
}
