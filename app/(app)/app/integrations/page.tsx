import Link from "next/link";

import { PageHeader, Pill, SetupNotice } from "@/components/app/ui";
import { requireSession } from "@/lib/data/context";
import { integrations as marketingIntegrations } from "@/lib/content";

export const metadata = { title: "Integrations" };

type Config = {
  id: string;
  provider: string;
  status: string;
  created_at: string;
};

export default async function IntegrationsPage() {
  const { supabase, workspace } = await requireSession();
  if (!workspace) return null;

  const { data, error } = await supabase
    .from("integration_configs")
    .select("id, provider, status, created_at")
    .eq("workspace_id", workspace.id);

  const configs = (data ?? []) as unknown as Config[];
  const connected = new Set(configs.filter((c) => c.status === "connected").map((c) => c.provider));

  return (
    <div className="max-w-4xl">
      <PageHeader
        eyebrow="Integrations"
        title="Connected sources"
        description="Nothing here is connected by default. A provider only shows as connected when a configuration row exists for this workspace."
        actions={
          <Link href="/app/projects" className="btn btn-outline h-9 px-3">
            Add a source manually
          </Link>
        }
      />

      {error ? <SetupNotice detail={error.message} /> : null}

      <ul className="panel divide-y divide-hairline">
        {marketingIntegrations.map((item) => {
          const isConnected = connected.has(item.name.toLowerCase());
          return (
            <li key={item.name} className="flex items-start justify-between gap-4 px-4 py-4">
              <div>
                <p className="text-[14px] text-fog">{item.name}</p>
                <p className="mt-0.5 max-w-xl font-mono text-[10.5px] leading-relaxed text-ash">
                  {item.intent}
                </p>
              </div>
              <Pill tone={isConnected ? "live" : "muted"}>
                {isConnected ? "connected" : "not connected"}
              </Pill>
            </li>
          );
        })}
      </ul>

      <div className="mt-5 panel p-5">
        <h2 className="mono mb-2 text-ash">What is actually implemented</h2>
        <p className="font-mono text-[11px] leading-relaxed text-ash">
          ZIP source upload works today. GitHub App installation and website URL
          assessment require backend configuration (app id, private key, webhook
          secret) and are not enabled in this build. There is no button here that
          pretends otherwise.
        </p>
      </div>
    </div>
  );
}
