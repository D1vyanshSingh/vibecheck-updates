import Link from "next/link";
import { ArrowUpRight, Mail } from "lucide-react";
import { EarlyAccessForm } from "@/components/ui/EarlyAccessForm";
import { OrbitalCore } from "@/components/3d/OrbitalCore";
import { Reveal } from "@/components/animations/Reveal";

export function EarlyAccessCTA({
  index = "07",
  title = "Ship fast. Then know what you shipped.",
  copy = "Early access is deliberate and small. Connect a project, see what the analysis finds, and tell us where it is wrong — that feedback shapes the product.",
  id = "early-access",
}: {
  index?: string;
  title?: string;
  copy?: string;
  id?: string;
}) {
  return (
    <section
      id={id}
      aria-labelledby={`${id}-heading`}
      className="section relative overflow-hidden border-t border-hairline bg-abyss"
    >
      <div
        aria-hidden="true"
        className="pointer-events-none absolute -right-32 top-1/2 h-[34rem] w-[34rem] -translate-y-1/2 opacity-40"
      >
        <OrbitalCore className="h-full w-full" />
      </div>

      <div className="shell relative grid gap-12 lg:grid-cols-[1.05fr_1fr] lg:gap-20">
        <div className="flex flex-col justify-center">
          <div className="flex items-center gap-4">
            <span className="mono-sm text-violet-bright">{index}</span>
            <span className="mono text-ash">Early access</span>
          </div>
          <h2 id={`${id}-heading`} className="display display-section mt-6 max-w-[15ch] text-fog">
            {title}
          </h2>
          <p className="lede mt-6 max-w-[46ch]">{copy}</p>

          <Reveal className="mt-9 grid gap-4 border-t border-hairline pt-6 sm:grid-cols-2">
            <div>
              <p className="mono-sm text-ash">General &amp; partnerships</p>
              <a
                href="mailto:hello@vibecheck.dev"
                className="mt-2 flex items-center gap-2 text-[13.5px] text-lavender transition-colors hover:text-fog"
              >
                <Mail className="h-3.5 w-3.5" aria-hidden="true" />
                hello@vibecheck.dev
              </a>
            </div>
            <div>
              <p className="mono-sm text-ash">Security disclosure</p>
              <a
                href="mailto:security@vibecheck.dev"
                className="mt-2 flex items-center gap-2 text-[13.5px] text-lavender transition-colors hover:text-fog"
              >
                <Mail className="h-3.5 w-3.5" aria-hidden="true" />
                security@vibecheck.dev
              </a>
            </div>
          </Reveal>

          <Link
            href="/developers"
            className="mono mt-8 inline-flex items-center gap-2 text-muted transition-colors hover:text-fog"
          >
            Building something and want the API shape?
            <ArrowUpRight className="h-3.5 w-3.5" aria-hidden="true" />
          </Link>
        </div>

        <div className="flex items-center">
          <EarlyAccessForm idPrefix={id} />
        </div>
      </div>
    </section>
  );
}
