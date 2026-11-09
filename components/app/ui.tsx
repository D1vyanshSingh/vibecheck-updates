import Link from "next/link";
import type { ReactNode } from "react";

/** Page-level heading used by every console route. */
export function PageHeader({
  eyebrow,
  title,
  description,
  actions,
}: {
  eyebrow: string;
  title: string;
  description?: string;
  actions?: ReactNode;
}) {
  return (
    <header className="mb-8 flex flex-col gap-4 border-b border-hairline pb-6 md:flex-row md:items-end md:justify-between">
      <div>
        <p className="eyebrow-plain mb-2">{eyebrow}</p>
        <h1 className="display text-[clamp(1.6rem,2.6vw,2.2rem)] text-fog">{title}</h1>
        {description ? (
          <p className="body-copy mt-2 max-w-2xl text-[13.5px]">{description}</p>
        ) : null}
      </div>
      {actions ? <div className="flex flex-wrap gap-2">{actions}</div> : null}
    </header>
  );
}

/** Numeric tile. Value must come from stored data — never a placeholder. */
export function StatCard({
  label,
  value,
  hint,
  tone = "default",
}: {
  label: string;
  value: number | string;
  hint?: string;
  tone?: "default" | "warn" | "accent";
}) {
  const valueClass =
    tone === "warn"
      ? "text-amber-300"
      : tone === "accent"
        ? "text-lavender"
        : "text-fog";
  return (
    <div className="panel p-4">
      <p className="mono-sm text-ash">{label}</p>
      <p className={`mt-2 font-display text-[26px] leading-none ${valueClass}`}>
        {value}
      </p>
      {hint ? <p className="mt-2 font-mono text-[10.5px] text-ash">{hint}</p> : null}
    </div>
  );
}

/**
 * Empty state that states the real reason there is nothing to show.
 * `action` must be a working control, not decoration.
 */
export function EmptyState({
  title,
  body,
  action,
}: {
  title: string;
  body: string;
  action?: ReactNode;
}) {
  return (
    <div className="panel flex flex-col items-start gap-3 p-7">
      <p className="mono-sm text-ash">Nothing stored yet</p>
      <h2 className="display-sub text-fog">{title}</h2>
      <p className="body-copy max-w-xl text-[13.5px]">{body}</p>
      {action ? <div className="mt-2">{action}</div> : null}
    </div>
  );
}

/** Setup blocker shown when the database schema has not been applied yet. */
export function SetupNotice({ detail }: { detail?: string }) {
  return (
    <div className="border border-amber-400/30 bg-amber-400/5 p-6">
      <p className="mono-sm text-amber-300">Database not provisioned</p>
      <h2 className="display-sub mt-2 text-fog">
        The workspace schema is missing
      </h2>
      <p className="body-copy mt-2 max-w-2xl text-[13.5px]">
        This console reads live rows with row-level security. It cannot render
        until the migrations in <code className="mono-body">supabase/migrations</code>{" "}
        have been applied to the linked project. Nothing is being faked in the
        meantime.
      </p>
      {detail ? (
        <pre className="code-surface mt-3 overflow-x-auto p-3 text-[11.5px]">
          {detail}
        </pre>
      ) : null}
    </div>
  );
}

export function SeverityDot({ severity }: { severity: string }) {
  const tone =
    severity === "critical"
      ? "bg-red-400"
      : severity === "high"
        ? "bg-orange-400"
        : severity === "medium"
          ? "bg-amber-300"
          : severity === "low"
            ? "bg-sky-300"
            : "bg-ash";
  return <span className={`inline-block h-1.5 w-1.5 rounded-full ${tone}`} />;
}

export function Pill({
  children,
  tone = "muted",
}: {
  children: ReactNode;
  tone?: "muted" | "live" | "warn" | "danger";
}) {
  const classes =
    tone === "live"
      ? "border-violet-bright/40 bg-violet/10 text-lavender"
      : tone === "warn"
        ? "border-amber-400/30 bg-amber-400/5 text-amber-200"
        : tone === "danger"
          ? "border-red-500/30 bg-red-500/10 text-red-200"
          : "border-hairline text-muted";
  return (
    <span
      className={`inline-flex h-[21px] items-center border px-2 font-mono text-[9px] uppercase tracking-[0.16em] ${classes}`}
    >
      {children}
    </span>
  );
}

/** Table shell: header row plus body, hairline separators, mono numbers. */
export function DataTable({
  head,
  children,
  empty,
}: {
  head: ReactNode;
  children?: ReactNode;
  empty?: ReactNode;
}) {
  return (
    <div className="panel overflow-hidden">
      <div className="overflow-x-auto">
        <table className="w-full border-collapse text-left">
          <thead className="border-b border-hairline bg-elevated/40">
            <tr className="mono-sm text-ash">{head}</tr>
          </thead>
          <tbody className="divide-y divide-hairline/60">{children}</tbody>
        </table>
      </div>
      {empty}
    </div>
  );
}

export function Th({ children }: { children?: ReactNode }) {
  return <th className="px-4 py-2.5 font-normal">{children}</th>;
}

export function Td({
  children,
  className = "",
}: {
  children?: ReactNode;
  className?: string;
}) {
  return (
    <td className={`px-4 py-3 align-middle text-[13px] text-muted ${className}`}>
      {children}
    </td>
  );
}

export function InlineLink({
  href,
  children,
}: {
  href: string;
  children: ReactNode;
}) {
  return (
    <Link href={href} className="text-lavender underline-offset-4 hover:underline">
      {children}
    </Link>
  );
}
