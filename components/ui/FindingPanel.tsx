import { AlertTriangle, CheckCircle2, ShieldAlert } from "lucide-react";
import { cn } from "@/lib/cn";

/**
 * A demonstration finding, styled like the product UI. Explicitly labelled as
 * sample data everywhere it appears — it is not a live scan result.
 */
export function FindingPanel({
  className,
  compact = false,
}: {
  className?: string;
  compact?: boolean;
}) {
  return (
    <div className={cn("panel relative overflow-hidden", className)}>
      <div className="flex items-center justify-between gap-4 border-b border-hairline px-4 py-3">
        <div className="flex items-center gap-2.5">
          <ShieldAlert className="h-3.5 w-3.5 text-violet-bright" aria-hidden="true" />
          <span className="mono text-ash">Finding / VBC-1042</span>
        </div>
        <span className="chip chip-live">High</span>
      </div>

      <div className="px-4 py-4 sm:px-5">
        <h3 className="font-display text-[17px] leading-snug tracking-[-0.02em] text-fog">
          Row-level policy missing on <span className="font-mono text-[15px] text-lavender">invoices</span>
        </h3>
        <p className="mono-sm mt-2 text-ash">
          supabase/policies.sql · table: public.invoices · confidence: high
        </p>

        <div className="mt-4 border border-hairline-soft bg-[#0a0911] p-3">
          <p className="mono-sm text-ash">Evidence</p>
          <pre className="mt-2 overflow-x-auto font-mono text-[11px] leading-relaxed text-[#cfc9e6]">
{`-- policies present on other tables
create policy "own rows" on public.projects
  for select using (auth.uid() = owner_id);

-- invoices: no policy found
alter table public.invoices enable row level security;`}
          </pre>
        </div>

        {!compact && (
          <>
            <div className="mt-4">
              <p className="mono-sm text-ash">What it means</p>
              <p className="body-copy mt-2 text-[13px]">
                With RLS enabled and no policy defined, an authenticated client can
                read every invoice through the anon key, not only its own. The
                missing clause is the ownership filter, not a missing table grant.
              </p>
            </div>

            <div className="mt-4">
              <p className="mono-sm text-ash">Suggested direction</p>
              <p className="body-copy mt-2 text-[13px]">
                Add a select policy scoped to{" "}
                <span className="font-mono text-[12px] text-lavender">auth.uid()</span>{" "}
                and confirm it with a second user account before closing the finding.
              </p>
            </div>

            <div className="mt-4 flex flex-wrap items-center gap-2 border-t border-hairline-soft pt-3">
              <span className="chip chip-planned">
                <CheckCircle2 className="h-3 w-3" aria-hidden="true" /> Not verified
              </span>
              <span className="chip chip-planned">
                <AlertTriangle className="h-3 w-3" aria-hidden="true" /> Review required
              </span>
            </div>
          </>
        )}
      </div>

      <div className="flex items-center justify-between gap-3 border-t border-hairline bg-[#0d0b15] px-4 py-2">
        <span className="mono-sm text-ash">Demonstration data — illustrative only</span>
        <span className="mono-sm text-ash">2026</span>
      </div>
    </div>
  );
}
