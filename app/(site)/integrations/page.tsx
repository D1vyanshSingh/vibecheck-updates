import type { Metadata } from "next";
import { ArrowRight, Cable, CircleDashed, ShieldCheck } from "lucide-react";
import { PageHeader } from "@/components/sections/PageHeader";
import { Reveal } from "@/components/animations/Reveal";
import { StatusChip } from "@/components/ui/StatusChip";
import { EarlyAccessCTA } from "@/components/sections/EarlyAccessCTA";
import { integrations } from "@/lib/content";

export const metadata: Metadata = {
  title: "Integrations",
  description:
    "The intended VibeCheck ecosystem: GitHub, GitLab, Vercel, Supabase, VS Code and AI coding environments — with honest status labels for each.",
  alternates: { canonical: "/integrations" },
};

export default function IntegrationsPage() {
  const live = integrations.filter((item) => item.status === "mvp").length;

  return (
    <>
      <PageHeader
        code="04"
        eyebrow="Integrations"
        title="Meet the project where it already lives."
        description="VibeCheck is designed to plug into source control, deployment, data and the editor. This page is a status board, not a partner wall — every entry states exactly how far it has got."
        meta={[
          { label: "Public integrations", value: String(live) },
          { label: "In development", value: "01" },
          { label: "Planned", value: "05" },
          { label: "Policy", value: "Read-only first" },
        ]}
      />

      <section aria-labelledby="status-heading" className="section">
        <div className="shell">
          <div className="flex flex-col gap-6 border border-hairline bg-surface/40 p-6 sm:flex-row sm:items-center sm:justify-between">
            <div className="flex items-start gap-3">
              <Cable className="mt-0.5 h-4 w-4 shrink-0 text-violet-bright" aria-hidden="true" />
              <div>
                <h2 id="status-heading" className="font-display text-[17px] tracking-[-0.02em] text-fog">
                  No public integration is live yet.
                </h2>
                <p className="body-copy mt-1.5 max-w-[62ch] text-[13px]">
                  The GitHub connection runs in a private build. Until an
                  integration is generally available, it is not listed as
                  available here — no logo wall, no implied adoption.
                </p>
              </div>
            </div>
            <div className="flex shrink-0 flex-wrap gap-2">
              <StatusChip status="development" />
              <StatusChip status="planned" />
            </div>
          </div>

          <div className="mt-12 grid gap-px border border-hairline bg-hairline-soft md:grid-cols-2">
            {integrations.map((integration, index) => (
              <Reveal key={integration.name} delay={index * 0.04} className="bg-void">
                <article className="flex h-full flex-col gap-5 p-6 sm:p-7">
                  <div className="flex items-start justify-between gap-4">
                    <div className="flex items-center gap-3">
                      <span className="flex h-10 w-10 items-center justify-center border border-hairline bg-surface font-mono text-[11px] tracking-[0.06em] text-lavender">
                        {integration.glyph}
                      </span>
                      <div>
                        <h3 className="font-display text-[18px] tracking-[-0.025em] text-fog">
                          {integration.name}
                        </h3>
                        <p className="mono-sm mt-1 text-ash">{integration.category}</p>
                      </div>
                    </div>
                    <StatusChip status={integration.status} />
                  </div>

                  <p className="body-copy text-[13.5px]">{integration.intent}</p>

                  <div className="mt-auto border-t border-hairline-soft pt-4">
                    <p className="mono-sm flex items-start gap-2 text-ash">
                      {integration.status === "development" ? (
                        <CircleDashed className="mt-0.5 h-3 w-3 shrink-0 text-lavender" aria-hidden="true" />
                      ) : (
                        <CircleDashed className="mt-0.5 h-3 w-3 shrink-0" aria-hidden="true" />
                      )}
                      {integration.note}
                    </p>
                  </div>
                </article>
              </Reveal>
            ))}
          </div>
        </div>
      </section>

      <section aria-labelledby="ecosystem-heading" className="section hair-t bg-abyss">
        <div className="shell grid gap-12 lg:grid-cols-[0.95fr_1fr] lg:gap-16">
          <Reveal>
            <p className="mono text-ash">Ecosystem model</p>
            <h2 id="ecosystem-heading" className="display display-section mt-5 max-w-[16ch] text-fog">
              Read-only by default, scoped by design.
            </h2>
            <p className="lede mt-6 max-w-[44ch]">
              Every integration in the plan follows the same rule: request the
              narrowest permission that makes the check possible, and say so in the
              interface.
            </p>

            <div className="mt-10 space-y-4">
              {[
                {
                  title: "Source control",
                  body: "Read files and history. No pushes, no branch protection changes.",
                },
                {
                  title: "Deployment",
                  body: "Read environment configuration and headers. No redeploys.",
                },
                {
                  title: "Data layer",
                  body: "Read schema and policies — never row data.",
                },
                {
                  title: "Editor",
                  body: "Push findings to the file you are editing. No code execution.",
                },
              ].map((row) => (
                <div key={row.title} className="rule-row grid gap-1 py-4 sm:grid-cols-[150px_1fr] sm:gap-6">
                  <p className="mono text-lavender">{row.title}</p>
                  <p className="body-copy text-[13px]">{row.body}</p>
                </div>
              ))}
            </div>
            <div className="mt-6 flex items-start gap-2.5">
              <ShieldCheck className="mt-0.5 h-3.5 w-3.5 shrink-0 text-lavender" aria-hidden="true" />
              <p className="mono-sm max-w-[40rem] text-ash">
                These are design intentions for planned integrations, not shipped
                guarantees.
              </p>
            </div>
          </Reveal>

          <Reveal delay={0.06}>
            <EcosystemMap />
          </Reveal>
        </div>
      </section>

      <section className="section hair-t">
        <div className="shell">
          <div className="grid gap-8 lg:grid-cols-[0.9fr_1fr] lg:gap-16">
            <div>
              <p className="mono text-ash">How integrations get announced</p>
              <h2 className="display display-sub mt-4 max-w-[22ch] text-fog">
                A merged pull request, then a changelog entry, then this page.
              </h2>
            </div>
            <div className="space-y-4">
              <p className="body-copy">
                Integration status changes here only after the code exists and has
                been tested against a real account. There is no “coming soon”
                carousel and no logo used to imply a partnership that does not
                exist.
              </p>
              <p className="body-copy">
                If you maintain a platform and want to talk about a native
                integration, the address is in the footer. We would rather build
                one well than list six optimistically.
              </p>
              <a
                href="mailto:hello@vibecheck.dev?subject=Integration%20conversation"
                className="mono inline-flex items-center gap-2 text-lavender hover:text-fog"
              >
                Start a conversation
                <ArrowRight className="h-3.5 w-3.5" aria-hidden="true" />
              </a>
            </div>
          </div>
        </div>
      </section>

      <EarlyAccessCTA
        index="05"
        title="Want your stack connected first?"
        copy="Early-access teams get to choose the order integrations are built in. Tell us what you use and why it matters."
      />
    </>
  );
}

function EcosystemMap() {
  const nodes = [
    { label: "GitHub", x: 280, y: 46, state: "dev" },
    { label: "GitLab", x: 428, y: 120, state: "planned" },
    { label: "Vercel", x: 452, y: 268, state: "planned" },
    { label: "Supabase", x: 340, y: 356, state: "planned" },
    { label: "VS Code", x: 168, y: 356, state: "planned" },
    { label: "AI envs", x: 96, y: 210, state: "planned" },
  ];

  return (
    <div className="border border-hairline bg-void/70 p-3">
      <svg
        viewBox="0 0 560 420"
        role="img"
        aria-label="Ecosystem map: VibeCheck at the centre, with GitHub in development and five planned integrations around it"
        className="h-auto w-full"
      >
        <defs>
          <radialGradient id="eco-hub" cx="0.5" cy="0.5" r="0.5">
            <stop offset="0" stopColor="#702BFF" stopOpacity="0.4" />
            <stop offset="1" stopColor="#702BFF" stopOpacity="0" />
          </radialGradient>
        </defs>

        <g stroke="#ffffff" strokeOpacity="0.045">
          {Array.from({ length: 14 }).map((_, i) => (
            <line key={`x${i}`} x1={i * 40} y1="0" x2={i * 40} y2="420" />
          ))}
          {Array.from({ length: 11 }).map((_, i) => (
            <line key={`y${i}`} x1="0" y1={i * 40} x2="560" y2={i * 40} />
          ))}
        </g>

        <circle cx="280" cy="210" r="120" fill="url(#eco-hub)" />
        <circle cx="280" cy="210" r="96" fill="none" stroke="#C9B5FF" strokeOpacity="0.16" />
        <circle cx="280" cy="210" r="150" fill="none" stroke="#ffffff" strokeOpacity="0.07" />

        {nodes.map((node) => {
          const inDev = node.state === "dev";
          return (
            <g key={node.label}>
              <line
                x1="280"
                y1="210"
                x2={node.x}
                y2={node.y}
                stroke={inDev ? "#C9B5FF" : "#ffffff"}
                strokeOpacity={inDev ? 0.55 : 0.14}
                strokeDasharray={inDev ? undefined : "3 7"}
              />
              <rect
                x={node.x - 52}
                y={node.y - 17}
                width="104"
                height="34"
                fill="#11101A"
                stroke={inDev ? "#C9B5FF" : "#ffffff"}
                strokeOpacity={inDev ? 0.5 : 0.14}
              />
              <text
                x={node.x}
                y={node.y + 4}
                textAnchor="middle"
                fill={inDev ? "#F5F3FF" : "#A5A0B5"}
                fontSize="9.5"
                letterSpacing="1.4"
                fontFamily="var(--font-jetbrains), monospace"
              >
                {node.label.toUpperCase()}
              </text>
            </g>
          );
        })}

        <circle cx="280" cy="210" r="54" fill="#151222" stroke="#C9B5FF" strokeOpacity="0.45" />
        <text
          x="280"
          y="206"
          textAnchor="middle"
          fill="#F5F3FF"
          fontSize="10.5"
          letterSpacing="1.8"
          fontFamily="var(--font-jetbrains), monospace"
        >
          VIBECHECK
        </text>
        <text
          x="280"
          y="222"
          textAnchor="middle"
          fill="#A5A0B5"
          fontSize="7.5"
          letterSpacing="1.2"
          fontFamily="var(--font-jetbrains), monospace"
        >
          ANALYSIS CORE
        </text>

        <g fontFamily="var(--font-jetbrains), monospace" fontSize="8" letterSpacing="1.2">
          <line x1="34" y1="392" x2="86" y2="392" stroke="#C9B5FF" strokeOpacity="0.6" />
          <text x="94" y="395" fill="#6C677D">IN DEVELOPMENT</text>
          <line x1="220" y1="392" x2="272" y2="392" stroke="#ffffff" strokeOpacity="0.2" strokeDasharray="3 6" />
          <text x="280" y="395" fill="#6C677D">PLANNED</text>
        </g>
      </svg>
    </div>
  );
}
