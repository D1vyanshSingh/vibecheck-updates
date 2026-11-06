import type { Metadata } from "next";
import { ArrowUpRight, Handshake, Mail, ShieldCheck, Users } from "lucide-react";
import { PageHeader } from "@/components/sections/PageHeader";
import { Reveal } from "@/components/animations/Reveal";
import { EarlyAccessForm } from "@/components/ui/EarlyAccessForm";
import { OrbitalCore } from "@/components/3d/OrbitalCore";
import { StatusChip } from "@/components/ui/StatusChip";
import { principles } from "@/lib/content";

export const metadata: Metadata = {
  title: "About",
  description:
    "Why VibeCheck exists, what it is trying to make true for AI-built software, and how to reach the team. No invented founders, awards or clients.",
  alternates: { canonical: "/about" },
};

const contacts = [
  {
    icon: <Mail />,
    label: "General",
    address: "hello@vibecheck.dev",
    note: "Product questions, early access, anything else.",
  },
  {
    icon: <Handshake />,
    label: "Partnerships",
    address: "hello@vibecheck.dev",
    note: "Platforms, agencies and design partners. Use the subject line “partnership”.",
  },
  {
    icon: <ShieldCheck />,
    label: "Security",
    address: "security@vibecheck.dev",
    note: "Responsible disclosure. We will acknowledge every report.",
  },
];

export default function AboutPage() {
  return (
    <>
      <PageHeader
        code="07"
        eyebrow="About"
        title="Security verification for the decade of generated software."
        description="VibeCheck is a small, early-stage effort with one thesis: as more software is written by machines, verification becomes the scarce skill — and it should be available to the people shipping, not only to the ones with a security team."
        meta={[
          { label: "Stage", value: "Private development" },
          { label: "Team", value: "Small founding team" },
          { label: "Funding", value: "Not disclosed" },
          { label: "Early access", value: "Open" },
        ]}
      />

      {/* Why */}
      <section aria-labelledby="why-heading" className="section">
        <div className="shell grid gap-12 lg:grid-cols-[1.05fr_1fr] lg:gap-20">
          <Reveal>
            <p className="mono text-ash">Why VibeCheck exists</p>
            <h2 id="why-heading" className="display display-section mt-5 max-w-[16ch] text-fog">
              A missing condition is harder to see than a syntax error.
            </h2>
            <div className="mt-7 space-y-5">
              <p className="body-copy">
                Code generation made building software accessible to a much larger
                group of people. That is a good thing. It also moved the moment a
                security decision gets made — from a reviewed pull request to a
                suggestion accepted between two other tasks.
              </p>
              <p className="body-copy">
                The failures that follow are quiet. A policy that was never written.
                A key with a live prefix in a committed example file. A route that
                trusts whatever tenant id the client sent. None of these produce an
                error message, and all of them are cheap to fix early and expensive
                to fix after launch.
              </p>
              <p className="body-copy">
                VibeCheck exists to make those failures visible in the place they
                are created, with enough evidence to act on and enough honesty to be
                disagreed with.
              </p>
            </div>
          </Reveal>

          <Reveal delay={0.06} className="flex flex-col justify-center">
            <div className="relative border border-hairline bg-abyss p-8">
              <div
                aria-hidden="true"
                className="pointer-events-none absolute inset-0 bg-[radial-gradient(60%_60%_at_70%_30%,rgba(112,43,255,0.2),transparent_70%)]"
              />
              <OrbitalCore className="relative mx-auto h-40 w-40" />
              <p className="mono-sm relative mt-8 text-center text-ash">
                Brand mark / orbital verification core
              </p>
              <p className="relative mt-3 text-center font-display text-[20px] tracking-[-0.03em] text-fog">
                Secure what you build.
              </p>
            </div>
            <div className="mt-4 grid grid-cols-2 gap-4">
              <div className="border border-hairline p-4">
                <p className="mono-sm text-ash">Mission</p>
                <p className="mt-2 text-[13px] leading-relaxed text-muted">
                  Make verified security evidence a normal part of shipping
                  software, not a quarterly audit.
                </p>
              </div>
              <div className="border border-hairline p-4">
                <p className="mono-sm text-ash">Vision</p>
                <p className="mt-2 text-[13px] leading-relaxed text-muted">
                  A world where generated applications are inspected as routinely
                  as they are compiled.
                </p>
              </div>
            </div>
          </Reveal>
        </div>
      </section>

      {/* Principles */}
      <section aria-labelledby="principles-heading" className="section hair-t bg-abyss">
        <div className="shell">
          <div className="flex flex-wrap items-end justify-between gap-4">
            <div>
              <p className="mono text-ash">Engineering principles</p>
              <h2 id="principles-heading" className="display display-section mt-4 max-w-[18ch] text-fog">
                Six rules that shaped the build.
              </h2>
            </div>
            <span className="mono-sm max-w-[24rem] text-ash">
              These govern the product and this website. Where we fall short, the
              rule is the standard, not the excuse.
            </span>
          </div>

          <div className="mt-12 grid gap-px border border-hairline bg-hairline-soft md:grid-cols-2 xl:grid-cols-3">
            {principles.map((principle, index) => (
              <Reveal key={principle.index} delay={index * 0.04} className="bg-void">
                <div className="flex h-full flex-col p-6">
                  <div className="flex items-center justify-between">
                    <span className="mono-sm text-violet-bright">{principle.index}</span>
                    <span className="h-1 w-1 bg-[#2a2340]" aria-hidden="true" />
                  </div>
                  <h3 className="mt-5 font-display text-[17px] leading-snug tracking-[-0.02em] text-fog">
                    {principle.title}
                  </h3>
                  <p className="body-copy mt-3 text-[13px]">{principle.body}</p>
                </div>
              </Reveal>
            ))}
          </div>
        </div>
      </section>

      {/* Team */}
      <section aria-labelledby="team-heading" className="section hair-t">
        <div className="shell grid gap-10 lg:grid-cols-[0.9fr_1fr] lg:gap-16">
          <Reveal>
            <p className="mono text-ash">Founding team</p>
            <h2 id="team-heading" className="display display-section mt-5 max-w-[14ch] text-fog">
              A small team, deliberately unnamed for now.
            </h2>
            <p className="lede mt-6 max-w-[44ch]">
              VibeCheck is being built by a founding team that will introduce itself
              when the product does. This section is intentionally empty rather than
              filled with invented names, portraits or credentials.
            </p>
            <a
              href="mailto:hello@vibecheck.dev?subject=Introduction"
              className="mono mt-8 inline-flex items-center gap-2 text-lavender hover:text-fog"
            >
              Introduce yourself
              <ArrowUpRight className="h-3.5 w-3.5" aria-hidden="true" />
            </a>
          </Reveal>

          <Reveal delay={0.06}>
            <div className="border border-hairline">
              <div className="flex items-center justify-between border-b border-hairline px-5 py-4">
                <div className="flex items-center gap-2.5">
                  <Users className="h-3.5 w-3.5 text-lavender" aria-hidden="true" />
                  <span className="mono text-ash">Team roster</span>
                </div>
                <StatusChip status="planned" />
              </div>

              <div className="grid gap-px bg-hairline-soft sm:grid-cols-2">
                {["Founder profile", "Founder profile", "Engineering", "Security research"].map(
                  (role, index) => (
                    <div key={`${role}-${index}`} className="bg-void p-5">
                      <div className="flex h-10 w-10 items-center justify-center border border-hairline border-dashed">
                        <span className="mono-sm text-[#3d3654]">{String(index + 1).padStart(2, "0")}</span>
                      </div>
                      <p className="mono-sm mt-4 text-ash">{role}</p>
                      <p className="mt-1 font-display text-[15px] tracking-[-0.02em] text-[#4b4560]">
                        Publishing at launch
                      </p>
                    </div>
                  ),
                )}
              </div>

              <p className="border-t border-hairline px-5 py-4 text-[12.5px] leading-relaxed text-ash">
                No founders, advisors, investors, awards, certifications or client
                logos are claimed anywhere on this site. If a name appears here
                later, it will be a real person who agreed to be listed.
              </p>
            </div>
          </Reveal>
        </div>
      </section>

      {/* Contact + early access */}
      <section id="contact" aria-labelledby="contact-heading" className="section hair-t scroll-mt-24 bg-abyss">
        <div className="shell">
          <div className="grid gap-12 lg:grid-cols-[1fr_1fr] lg:gap-20">
            <div>
              <p className="mono text-ash">Contact</p>
              <h2 id="contact-heading" className="display display-section mt-4 max-w-[16ch] text-fog">
                Talk to a person, not a funnel.
              </h2>
              <p className="lede mt-6 max-w-[42ch]">
                Every message lands in a human inbox. Response times are honest:
                usually a couple of days, faster if you are reporting a
                vulnerability.
              </p>

              <div className="mt-10">
                {contacts.map((contact) => (
                  <div
                    key={contact.label}
                    className="rule-row grid gap-2 py-5 sm:grid-cols-[130px_1fr] sm:gap-6"
                  >
                    <div className="flex items-center gap-2">
                      <span className="text-lavender [&_svg]:h-3.5 [&_svg]:w-3.5">{contact.icon}</span>
                      <span className="mono text-fog">{contact.label}</span>
                    </div>
                    <div>
                      <a
                        href={`mailto:${contact.address}`}
                        className="text-[14px] text-lavender transition-colors hover:text-fog"
                      >
                        {contact.address}
                      </a>
                      <p className="body-copy mt-1 text-[12.5px]">{contact.note}</p>
                    </div>
                  </div>
                ))}
                <div className="border-t border-hairline" />
              </div>
            </div>

            <div id="early-access" className="scroll-mt-24">
              <EarlyAccessForm idPrefix="about" />
              <div className="mt-4 space-y-2">
                <p className="mono-sm text-ash">
                  Submissions are only forwarded when a destination is configured on
                  the server. Until then the form says so and stores nothing.
                </p>
                <p className="mono-sm text-ash">
                  No tracking pixels. No marketing automation. One list, one reply.
                </p>
              </div>
            </div>
          </div>
        </div>
      </section>
    </>
  );
}
