import type { ReactNode } from "react";
import { cn } from "@/lib/cn";

export function SectionHead({
  index,
  eyebrow,
  title,
  description,
  aside,
  className,
  id,
}: {
  index?: string;
  eyebrow: string;
  title: ReactNode;
  description?: ReactNode;
  aside?: ReactNode;
  className?: string;
  id?: string;
}) {
  return (
    <div className={cn("grid gap-8 lg:grid-cols-[1fr_1fr] lg:gap-16", className)}>
      <div>
        <div className="flex items-center gap-4">
          {index && <span className="mono-sm text-violet-bright">{index}</span>}
          <span className="mono text-ash">{eyebrow}</span>
          <span className="h-px flex-1 bg-hairline" aria-hidden="true" />
        </div>
        <h2 id={id} className="display display-section mt-6 max-w-[16ch] text-fog">
          {title}
        </h2>
      </div>
      {(description || aside) && (
        <div className="flex flex-col justify-end gap-6">
          {description && (
            <p className="lede max-w-[52ch] lg:ml-auto">{description}</p>
          )}
          {aside}
        </div>
      )}
    </div>
  );
}

export function SectionFrame({
  children,
  className,
  id,
  labelledBy,
}: {
  children: ReactNode;
  className?: string;
  id?: string;
  labelledBy?: string;
}) {
  return (
    <section
      id={id}
      aria-labelledby={labelledBy}
      className={cn("section hair-t", className)}
    >
      {children}
    </section>
  );
}
