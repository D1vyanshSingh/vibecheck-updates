import type { ReactNode } from "react";
import { cn } from "@/lib/cn";

export function PageHeader({
  code,
  eyebrow,
  title,
  description,
  meta,
  className,
}: {
  code: string;
  eyebrow: string;
  title: ReactNode;
  description: ReactNode;
  meta?: { label: string; value: string; status?: ReactNode }[];
  className?: string;
}) {
  return (
    <section
      className={cn(
        "relative overflow-hidden border-b border-hairline bg-abyss pt-[72px]",
        className,
      )}
    >
      <div aria-hidden="true" className="grid-field pointer-events-none absolute inset-0 opacity-50" />
      <div
        aria-hidden="true"
        className="pointer-events-none absolute -right-40 -top-24 h-[30rem] w-[30rem] rounded-full bg-[radial-gradient(circle,rgba(112,43,255,0.34),transparent_68%)] blur-2xl"
      />
      <div className="shell relative pb-14 pt-12 md:pb-20 md:pt-16">
        <div className="flex items-center gap-4">
          <span className="mono-sm text-violet-bright">{code}</span>
          <span className="mono text-ash">{eyebrow}</span>
          <span className="h-px flex-1 bg-hairline" aria-hidden="true" />
          <span className="mono-sm hidden text-ash sm:block">VibeCheck / 2026</span>
        </div>

        <h1 className="display mt-8 max-w-[22ch] text-[clamp(2.3rem,5.2vw,4.4rem)] leading-[0.96] text-fog">
          {title}
        </h1>

        <div className="mt-7 max-w-[62ch]">
          <p className="lede">{description}</p>
        </div>

        {meta && (
          <dl className="mt-12 grid gap-px border border-hairline bg-hairline-soft sm:grid-cols-2 lg:grid-cols-4">
            {meta.map((item) => (
              <div key={item.label} className="bg-abyss p-4">
                <dt className="mono-sm text-ash">{item.label}</dt>
                <dd className="mt-2 flex items-center gap-2 font-display text-[15px] tracking-[-0.01em] text-fog">
                  {item.value}
                  {item.status}
                </dd>
              </div>
            ))}
          </dl>
        )}
      </div>
    </section>
  );
}
