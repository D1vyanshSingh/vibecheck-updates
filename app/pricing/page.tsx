import type { Metadata } from "next";
import Link from "next/link";
import { ArrowUpRight, Minus } from "lucide-react";
import { PageHeader } from "@/components/sections/PageHeader";
import { Reveal } from "@/components/animations/Reveal";
import { StatusChip } from "@/components/ui/StatusChip";
import { EarlyAccessCTA } from "@/components/sections/EarlyAccessCTA";
import { tiers } from "@/lib/content";
import { cn } from "@/lib/cn";

export const metadata: Metadata = {
  title: "Pricing",
  description:
    "VibeCheck pricing is not finalised. Proposed tiers — Free/Community, Pro, Team/Agency and Enterprise — with scope marked as proposed rather than committed.",
  alternates: { canonical: "/pricing" },
};

const comparison: { label: string; cells: string[] }[] = [
  { label: "Connected projects", cells: ["1 (proposed)", "Multiple", "Client-separated", "Custom"] },
  { label: "Code & secret checks", cells: ["Proposed", "Proposed", "Proposed", "Proposed"] },
  { label: "Dependency analysis", cells: ["—", "Proposed", "Proposed", "Proposed"] },
  { label: "Data & access analysis", cells: ["—", "Proposed", "Proposed", "Proposed"] },
  { label: "Verification records", cells: ["—", "Proposed", "Proposed", "Proposed"] },
  { label: "Shared workspace", cells: ["—", "—", "Proposed", "Proposed"] },
  { label: "Custom detection policy", cells: ["—", "—", "—", "Proposed"] },
];

export default function PricingPage() {
  return (
    <>
      <PageHeader
        code="06"
        eyebrow="Pricing"
        title="Pricing that is not pretending to be final."
        description="VibeCheck is pre-commercial. No price, quota or contractual term has been decided, so none is published here. What follows is proposed scope, written down so early-access teams can tell us what is wrong with it."
        meta={[
          { label: "Prices published", value: "None" },
          { label: "Billing live", value: "No" },
          { label: "Free tier", value: "Intended" },
          { label: "Waitlist", value: "Open" },
        ]}
      />

      <section aria-labelledby="tiers-heading" className="section">
        <div className="shell">
          <div className="flex flex-wrap items-end justify-between gap-4">
            <div>
              <p className="mono text-ash">Proposed tiers</p>
              <h2 id="tiers-heading" className="display display-section mt-4 max-w-[18ch] text-fog">
                Four shapes. Zero commitments.
              </h2>
            </div>
            <span className="chip chip-planned">Subject to change</span>
          </div>

          <div className="mt-12 grid gap-px border border-hairline bg-hairline-soft md:grid-cols-2 xl:grid-cols-4">
            {tiers.map((tier, index) => (
              <Reveal key={tier.name} delay={index * 0.04} className="bg-void">
                <article
                  className={cn(
                    "relative flex h-full flex-col p-6",
                    tier.featured && "bg-surface",
                  )}
                >
                  {tier.featured && (
                    <span className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-violet-bright to-transparent" />
                  )}
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <p className="mono-sm text-violet-bright">Tier {String(index + 1).padStart(2, "0")}</p>
                      <h3 className="mt-2 font-display text-[19px] tracking-[-0.03em] text-fog">
                        {tier.name}
                      </h3>
                    </div>
                    {tier.featured && <span className="chip chip-dev">Focus</span>}
                  </div>

                  <p className="mono-sm mt-2 text-ash">{tier.audience}</p>

                  <div className="mt-6 border-y border-hairline-soft py-4">
                    <p className="font-display text-[22px] tracking-[-0.03em] text-fog">
                      {tier.price}
                    </p>
                    <p className="mono-sm mt-1 text-ash">{tier.priceNote}</p>
                  </div>

                  <p className="body-copy mt-4 text-[13px]">{tier.summary}</p>

                  <ul className="mt-5 flex-1 space-y-2.5">
                    {tier.includes.map((item) => (
                      <li key={item} className="flex gap-2.5">
                        <span className="mt-1.5 h-1 w-1 shrink-0 bg-violet-bright" aria-hidden="true" />
                        <span className="text-[12.5px] leading-relaxed text-muted">{item}</span>
                      </li>
                    ))}
                  </ul>

                  <div className="mt-6 flex flex-col gap-2">
                    {tier.status === "waitlist" ? (
                      <Link href="#early-access" className="btn btn-primary w-full">
                        {tier.cta}
                        <ArrowUpRight className="h-3.5 w-3.5" aria-hidden="true" />
                      </Link>
                    ) : (
                      <a
                        href={`mailto:hello@vibecheck.dev?subject=${encodeURIComponent(tier.name + " enquiry")}`}
                        className="btn btn-outline w-full"
                      >
                        {tier.cta}
                        <ArrowUpRight className="h-3.5 w-3.5" aria-hidden="true" />
                      </a>
                    )}
                    <p className="mono-sm text-center text-ash">Proposed, not purchasable</p>
                  </div>
                </article>
              </Reveal>
            ))}
          </div>

          <p className="mono-sm mt-4 text-ash">
            No tier can be bought today. Buttons that mention a waitlist submit to
            the early-access list; enterprise buttons open an email draft.
          </p>
        </div>
      </section>

      {/* Comparison */}
      <section aria-labelledby="compare-heading" className="section hair-t bg-abyss">
        <div className="shell">
          <div className="flex flex-wrap items-end justify-between gap-4">
            <h2 id="compare-heading" className="display display-section max-w-[20ch] text-fog">
              What each tier is intended to include.
            </h2>
            <p className="mono-sm max-w-[26rem] text-ash">
              Intentions, not entitlements. Nothing in this table is a contractual
              commitment or a shipped feature.
            </p>
          </div>

          <div className="mt-10 overflow-x-auto border border-hairline">
            <table className="w-full min-w-[42rem] border-collapse text-left">
              <caption className="sr-only">
                Proposed capability scope by tier. All entries are proposals.
              </caption>
              <thead>
                <tr className="border-b border-hairline bg-surface/60">
                  <th scope="col" className="mono px-4 py-3 text-ash">
                    Capability
                  </th>
                  {["Community", "Pro", "Team", "Enterprise"].map((name) => (
                    <th key={name} scope="col" className="mono px-4 py-3 text-ash">
                      {name}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {comparison.map((row) => (
                  <tr key={row.label} className="border-b border-hairline-soft last:border-b-0">
                    <th scope="row" className="px-4 py-3 font-sans text-[13px] font-normal text-fog">
                      {row.label}
                    </th>
                    {row.cells.map((cell, index) => (
                      <td key={index} className="px-4 py-3">
                        {cell === "—" ? (
                          <Minus className="h-3.5 w-3.5 text-[#3a3450]" aria-label="Not proposed" />
                        ) : (
                          <span className="font-mono text-[11px] text-muted">{cell}</span>
                        )}
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </section>

      {/* Principles */}
      <section aria-labelledby="pricing-principles-heading" className="section hair-t">
        <div className="shell grid gap-10 lg:grid-cols-[0.9fr_1fr] lg:gap-16">
          <Reveal>
            <h2 id="pricing-principles-heading" className="display display-section max-w-[15ch] text-fog">
              How we intend to price.
            </h2>
            <p className="lede mt-6 max-w-[42ch]">
              These are principles, not terms. They exist so the eventual page has
              something to be held to.
            </p>
            <div className="mt-8 flex flex-wrap gap-2">
              <StatusChip status="planned" />
              <span className="mono-sm self-center text-ash">Not yet applicable</span>
            </div>
          </Reveal>

          <div>
            {[
              {
                title: "The free tier stays useful",
                body: "A community tier that cannot complete a real check is a demo, not a tier. One project should be enough to find something true.",
              },
              {
                title: "No seat-count surprises",
                body: "If pricing changes with team size, the boundary will be published before anyone signs up, not discovered on an invoice.",
              },
              {
                title: "Verification is not a premium toggle",
                body: "Re-testing a finding is the point of the product. Charging extra for proof would make the core promise conditional.",
              },
              {
                title: "No annual lock-in for a beta",
                body: "Nothing is being sold while the product is in development, so no commitment can be made that the build cannot support.",
              },
            ].map((row, index) => (
              <Reveal key={row.title} delay={index * 0.05}>
                <div className="rule-row grid gap-2 py-6 sm:grid-cols-[190px_1fr] sm:gap-8">
                  <h3 className="font-display text-[15px] tracking-[-0.015em] text-fog">{row.title}</h3>
                  <p className="body-copy text-[13.5px]">{row.body}</p>
                </div>
              </Reveal>
            ))}
            <div className="border-t border-hairline" />
          </div>
        </div>
      </section>

      <EarlyAccessCTA
        index="07"
        title="Influence the pricing by using the product first."
        copy="Early-access teams see the scope before it is packaged and priced. The first conversation is about what the analysis found, not about a contract."
      />
    </>
  );
}
