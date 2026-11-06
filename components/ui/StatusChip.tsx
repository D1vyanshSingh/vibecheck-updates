import type { CapabilityStatus } from "@/lib/content";
import { cn } from "@/lib/cn";

const labels: Record<CapabilityStatus, string> = {
  mvp: "In current MVP",
  development: "In development",
  planned: "Planned",
};

export function StatusChip({
  status,
  className,
  compact = false,
}: {
  status: CapabilityStatus;
  className?: string;
  compact?: boolean;
}) {
  return (
    <span
      className={cn(
        "chip",
        status === "mvp" && "chip-live",
        status === "development" && "chip-dev",
        status === "planned" && "chip-planned",
        className,
      )}
    >
      <span className="chip-dot" aria-hidden="true" />
      {compact && status === "development" ? "Dev" : labels[status]}
    </span>
  );
}

export const statusLabel = (status: CapabilityStatus) => labels[status];
