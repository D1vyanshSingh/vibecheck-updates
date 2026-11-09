import Link from "next/link";

import { PageHeader, Pill } from "@/components/app/ui";

export const metadata = { title: "OmniRoute" };

type Health = {
  status?: string;
  omniroute?: boolean;
  supabase?: boolean;
  service_role?: boolean;
  detail?: string;
};

type Capabilities = {
  scanners?: Record<string, unknown>;
  limits?: Record<string, number>;
};

async function probe<T>(path: string): Promise<{ data: T | null; error: string | null }> {
  const origin = (
    process.env.BACKEND_PUBLIC_URL ??
    process.env.NEXT_PUBLIC_BACKEND_URL ??
    ""
  ).replace(/\/+$/, "");

  if (!origin) {
    return { data: null, error: "BACKEND_PUBLIC_URL is not configured." };
  }

  try {
    const response = await fetch(`${origin}${path}`, { cache: "no-store" });
    if (!response.ok) {
      return { data: null, error: `${path} returned ${response.status}.` };
    }
    return { data: (await response.json()) as T, error: null };
  } catch {
    return { data: null, error: `Could not reach ${origin}${path}.` };
  }
}

export default async function OmniRoutePage() {
  const [health, capabilities] = await Promise.all([
    probe<Health>("/health"),
    probe<Capabilities>("/v1/capabilities"),
  ]);

  const aiConfigured = health.data?.omniroute === true;

  return (
    <div className="max-w-4xl">
      <PageHeader
        eyebrow="AI gateway"
        title="OmniRoute"
        description="Status is read from the backend on every render. A configured gateway is not the same as a healthy one, and neither is assumed here."
        actions={
          <Link href="/app/ai-intelligence" className="btn btn-outline h-9 px-3">
            AI assessments
          </Link>
        }
      />

      <div className="mb-5 grid gap-3 sm:grid-cols-3">
        <div className="panel p-4">
          <p className="mono-sm text-ash">Backend</p>
          <p className="mt-2 text-[14px] text-fog">
            {health.data ? "reachable" : "unreachable"}
          </p>
          <p className="mt-1 font-mono text-[10px] text-ash">
            {health.error ?? `/health → ${health.data?.status ?? "unknown"}`}
          </p>
        </div>
        <div className="panel p-4">
          <p className="mono-sm text-ash">Gateway configured</p>
          <p className="mt-2 text-[14px] text-fog">{aiConfigured ? "yes" : "no"}</p>
          <p className="mt-1 font-mono text-[10px] text-ash">
            Based on OMNIROUTE_BASE_URL / API key presence server-side.
          </p>
        </div>
        <div className="panel p-4">
          <p className="mono-sm text-ash">Scanners</p>
          <p className="mt-2 text-[14px] text-fog">
            {capabilities.data?.scanners
              ? `${Object.keys(capabilities.data.scanners).length} registered`
              : "unknown"}
          </p>
          <p className="mt-1 font-mono text-[10px] text-ash">
            {capabilities.error ?? "/v1/capabilities"}
          </p>
        </div>
      </div>

      <section className="panel p-5">
        <h2 className="mono mb-3 text-ash">Scanner availability</h2>
        {!capabilities.data?.scanners ? (
          <p className="font-mono text-[11.5px] text-ash">
            The capability endpoint did not answer, so availability is unknown —
            not assumed available.
          </p>
        ) : (
          <ul className="space-y-2">
            {Object.entries(capabilities.data.scanners).map(([name, value]) => (
              <li key={name} className="flex items-center justify-between font-mono text-[11px]">
                <span className="text-muted">{name}</span>
                <Pill tone={value === true ? "live" : "muted"}>
                  {value === true ? "available" : String(value)}
                </Pill>
              </li>
            ))}
          </ul>
        )}
      </section>

      <section className="panel mt-4 p-5">
        <h2 className="mono mb-2 text-ash">Process control</h2>
        <p className="font-mono text-[11px] leading-relaxed text-ash">
          Start, stop and restart are intentionally absent: a Vercel deployment
          cannot manage a process on your machine, and this build ships no local
          controller. Provider and model discovery will be wired to the installed
          OmniRoute version once its endpoint and credentials are configured. Do not
          expose an unauthenticated gateway to the network in the meantime.
        </p>
      </section>
    </div>
  );
}
