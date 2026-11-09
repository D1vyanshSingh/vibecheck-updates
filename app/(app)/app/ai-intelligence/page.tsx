import Link from "next/link";

import { EmptyState, PageHeader, Pill, SetupNotice } from "@/components/app/ui";
import { requireSession } from "@/lib/data/context";

export const metadata = { title: "AI intelligence" };

type Session = {
  id: string;
  status: string;
  model: string | null;
  provider: string | null;
  created_at: string;
  scan_id: string | null;
};

export default async function AiIntelligencePage() {
  const { supabase, workspace } = await requireSession();
  if (!workspace) return null;

  const { data, error } = await supabase
    .from("ai_sessions")
    .select("id, status, model, provider, created_at, scan_id")
    .eq("workspace_id", workspace.id)
    .order("created_at", { ascending: false })
    .limit(50);

  const sessions = (data ?? []) as unknown as Session[];

  return (
    <div className="max-w-4xl">
      <PageHeader
        eyebrow="AI intelligence"
        title="Assessment reasoning"
        description="Every AI session is stored with its provider, model and prompt version. Conclusions are only displayed next to the findings and evidence they cite."
        actions={
          <Link href="/app/omniroute" className="btn btn-outline h-9 px-3">
            Gateway status
          </Link>
        }
      />

      {error ? (
        <SetupNotice detail={error.message} />
      ) : sessions.length === 0 ? (
        <EmptyState
          title="No AI session has run"
          body="AI analysis is optional. Deterministic scanner results are stored and viewable without it; a session appears here only after the orchestration layer actually calls the gateway."
        />
      ) : (
        <ul className="panel divide-y divide-hairline">
          {sessions.map((session) => (
            <li key={session.id} className="flex items-center justify-between gap-3 px-4 py-3">
              <div>
                <p className="font-mono text-[11.5px] text-fog">
                  {session.provider ?? "provider"} · {session.model ?? "model unset"}
                </p>
                <p className="mt-0.5 font-mono text-[10px] text-ash">
                  {new Date(session.created_at).toLocaleString()}
                  {session.scan_id ? ` · scan ${session.scan_id.slice(0, 8)}` : ""}
                </p>
              </div>
              <Pill
                tone={
                  session.status === "completed"
                    ? "live"
                    : session.status === "failed"
                      ? "danger"
                      : "warn"
                }
              >
                {session.status}
              </Pill>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
