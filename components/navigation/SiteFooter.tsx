import Link from "next/link";
import { ArrowUpRight } from "lucide-react";
import { VibeCheckMark } from "@/components/brand/VibeCheckLogo";
import { primaryNav, secondaryNav } from "@/lib/content";

const columns = [
  {
    title: "Product",
    links: [
      { label: "Platform", href: "/platform" },
      { label: "How It Works", href: "/how-it-works" },
      { label: "Integrations", href: "/integrations" },
      { label: "Pricing", href: "/pricing" },
    ],
  },
  {
    title: "Build",
    links: [
      { label: "Developers", href: "/developers" },
      { label: "API overview", href: "/developers#api" },
      { label: "Example findings", href: "/developers#findings" },
      { label: "Getting started", href: "/developers#start" },
    ],
  },
  {
    title: "Company",
    links: [
      { label: "About", href: "/about" },
      { label: "Contact", href: "/about#contact" },
      { label: "Early access", href: "/about#early-access" },
    ],
  },
];

export function SiteFooter() {
  return (
    <footer className="relative overflow-hidden border-t border-hairline bg-abyss">
      <div className="shell pt-16 md:pt-20">
        <div className="grid gap-12 lg:grid-cols-[1.3fr_2fr]">
          <div>
            <div className="flex items-center gap-3">
              <VibeCheckMark size={30} />
              <span className="font-display text-[19px] font-semibold tracking-[-0.04em]">
                VibeCheck<span className="text-violet-bright">.</span>
              </span>
            </div>
            <p className="mono-sm mt-4 text-ash">Secure what you build.</p>
            <p className="body-copy mt-6 max-w-sm text-[13.5px]">
              Security verification infrastructure for the AI-powered software
              development era. Currently in private development — capabilities
              on this site are labelled by status.
            </p>
            <a
              href="mailto:hello@vibecheck.dev"
              className="mono mt-6 inline-flex items-center gap-2 text-lavender transition-colors hover:text-fog"
            >
              hello@vibecheck.dev
              <ArrowUpRight className="h-3.5 w-3.5" aria-hidden="true" />
            </a>
          </div>

          <div className="grid grid-cols-2 gap-8 sm:grid-cols-3">
            {columns.map((column) => (
              <div key={column.title}>
                <h3 className="mono-sm text-ash">{column.title}</h3>
                <ul className="mt-4 space-y-3">
                  {column.links.map((link) => (
                    <li key={link.href + link.label}>
                      <Link
                        href={link.href}
                        className="text-[13.5px] text-muted transition-colors hover:text-fog"
                      >
                        {link.label}
                      </Link>
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
        </div>

        <div className="mt-14 flex flex-col gap-4 border-t border-hairline-soft py-6 sm:flex-row sm:items-center sm:justify-between">
          <p className="mono-sm text-ash">
            © {new Date().getFullYear()} VibeCheck. All rights reserved.
          </p>
          <div className="flex flex-wrap items-center gap-x-6 gap-y-2">
            <span className="mono-sm text-ash">Status: private development</span>
            <Link href="/about#contact" className="mono-sm text-muted hover:text-fog">
              Security contact
            </Link>
            <Link href="/about" className="mono-sm text-muted hover:text-fog">
              Principles
            </Link>
          </div>
        </div>
      </div>

      {/* Cropped closing wordmark — bookends the hero. */}
      <div aria-hidden="true" className="shell pb-0">
        <div className="relative -mb-[0.19em] overflow-hidden">
          <span className="block select-none whitespace-nowrap font-display text-[clamp(64px,19.4vw,300px)] font-semibold leading-[0.74] tracking-[-0.06em] text-[#1a1626]">
            VIBECHECK
          </span>
        </div>
      </div>
      <div className="pointer-events-none absolute inset-x-0 bottom-0 h-40 bg-gradient-to-t from-void/90 to-transparent" />
      <nav aria-label="Footer" className="sr-only">
        {[...primaryNav, ...secondaryNav].map((item) => (
          <Link key={item.href} href={item.href}>
            {item.label}
          </Link>
        ))}
      </nav>
    </footer>
  );
}
