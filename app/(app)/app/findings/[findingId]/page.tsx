import Link from "next/link";
import { notFound } from "next/navigation";

import { PageHeader, Pill, SetupNotice, SeverityDot } from "@/components/app/ui";
import { requestVerificationAction } from "@/lib/actions";
import { requireSession } from "@/lib/data/context";

export const metadata = { title: "Finding" };

type Finding = {
  id: string;
  project_id: string;
  scan_id: string | null;
  severity: string;
  status: string;
  category: string;
  title: string;
  description: string | null;
  file_path: string | null;
  line_start: number | null;
  line_end: number | null;
  rule_id: string | null;
  scanner: string;
  scanner_version: string | null;
  confidence: string;
  remediation: string | null;
  redacted_evidence: string | null;
  verified_at: string | null;
  created_at: string;
  updated_at: string;
  projects: { name: string } | { name: string }[] | null;
};

type Evidence = {
  id: string;
  kind: string;
  file_path: string | null;
  line_start: number | null;
  snippet: string | null;
  created_at: string;
};

type Verification = {
  id: string;
  status: string;
  notes: string | null;
  created_at: string;
  completed_at: string | null;
};

export default async function FindingDetailPage({
  params,
}: {
  params: Promise<{ findingId: string }>;
}) {
  const { findingId } = await params;
  const { supabase, workspace } = await requireSession();
  if (!workspace) return null;

  const { data, error } = await supabase
    .from("findings")
    .select(
      "id, project_id, scan_id, severity, status, category, title, description, file_path, line_start, line_end, rule_id, scanner, scanner_version, confidence, remediation, redacted_evidence, verified_at, created_at, updated_at, projects(name)",
    )
    .eq("id", findingId)
    .eq("workspace_id", workspace.id)
    .maybeSingle();

  if (error) return <SetupNotice detail={error.message} />;
  if (!data) notFound();

  const finding = data as unknown as Finding;
  const project = Array.isArray(finding.projects) ? finding.projects[0] : finding.projects;

  const [{ data: evidenceData }, { data: verificationData }, { data: sourceData }] =
    await Promise.all([
      supabase
        .from("finding_evidence")
        .select("id, kind, file_path, line_start, snippet, created_at")
        .eq("finding_id", finding.id)
        .limit(20),
      supabase
        .from("verification_runs")
        .select("id, status, notes, created_at, completed_at")
        .eq("finding_id", finding.id)
        .order("created_at", { ascending: false }),
      supabase
        .from("project_sources")
        .select("id, label, created_at")
        .eq("project_id", finding.project_id)
        .order("created_at", { ascending: false })
        .limit(1)
        .maybeSingle(),
    ]);

  const evidence = (evidenceData ?? []) as unknown as Evidence[];
  const verifications = (verificationData ?? []) as unknown as Verification[];
  const source = sourceData as { id: string; label: string | null } | null;

  return (
    <div className="max-w-4xl">
      <PageHeader
        eyebrow={`${finding.scanner} · ${finding.category}`}
        title={finding.title}
        description={project?.name ?? "Project"}
        actions={
          <Link
            href={`/app/findings?projectId=${finding.project_id}`}
            className="btn btn-outline h-9 px-3"
          >
            Project findings
          </Link>
        }
      />

      <div className="mb-6 flex flex-wrap items-center gap-2.5">
        <span className="flex items-center gap-1.5 font-mono text-[10.5px] uppercase tracking-[0.14em] text-muted">
          <SeverityDot severity={finding.severity} />
          {finding.severity}
        </span>
        <Pill>{finding.confidence} confidence</Pill>
        <Pill tone={finding.status === "verified" ? "live" : "warn"}>
          {finding.status.replace(/_/g, " ")}
        </Pill>
        {finding.verified_at ? (
          <span className="font-mono text-[10px] text-ash">
            verified {new Date(finding.verified_at).toLocaleDateString()}
          </span>
        ) : (
          <span className="font-mono text-[10px] text-ash">not verified</span>
        )}
      </div>

      <div className="grid gap-5 md:grid-cols-[1.4fr_1fr]">
        <div className="space-y-5">
          <section className="panel p-5">
            <h2 className="mono mb-2 text-ash">Description</h2>
            <p className="font-mono text-[12px] leading-relaxed text-muted">
              {finding.description ?? "No description stored for this finding."}
            </p>
          </section>

          <section className="panel p-5">
            <h2 className="mono mb-2 text-ash">Evidence</h2>
            {evidence.length === 0 ? (
              <p className="font-mono text-[11.5px] leading-relaxed text-ash">
                No evidence rows stored. A finding without stored evidence cannot be
                validated — it stays a scanner observation.
              </p>
            ) : (
              <ul className="space-y-3">
                {evidence.map((item) => (
                  <li key={item.id} className="border-l border-violet/40 pl-3">
                    <p className="mono-sm text-ash">
                      {item.kind}
                      {item.file_path
                        ? ` · ${item.file_path}${item.line_start ? `:${item.line_start}` : ""}`
                        : ""}
                    </p>
                    {item.snippet ? (
                      <pre className="code-surface mt-2 overflow-x-auto p-2.5 text-[11px]">
                        {item.snippet}
                      </pre>
                    ) : null}
                  </li>
                ))}
              </ul>
            )}
          </section>

          <section className="panel p-5">
            <h2 className="mono mb-2 text-ash">Remediation</h2>
            <p className="font-mono text-[12px] leading-relaxed text-muted">
              {finding.remediation ??
                "No remediation guidance stored. It is written only when the analysis produced it."}
            </p>
          </section>
        </div>

        <aside className="space-y-4">
          <section className="panel p-5">
            <h2 className="mono mb-3 text-ash">Source of record</h2>
            <dl className="space-y-2 font-mono text-[11px]">
              <div className="flex justify-between gap-3">
                <dt className="text-ash">Rule</dt>
                <dd className="truncate text-muted">{finding.rule_id ?? "—"}</dd>
              </div>
              <div className="flex justify-between gap-3">
                <dt className="text-ash">Scanner</dt>
                <dd className="text-muted">
                  {finding.scanner}
                  {finding.scanner_version ? ` ${finding.scanner_version}` : ""}
                </dd>
              </div>
              <div className="flex justify-between gap-3">
                <dt className="text-ash">Location</dt>
                <dd className="truncate text-muted">
                  {finding.file_path
                    ? `${finding.file_path}${finding.line_start ? `:${finding.line_start}` : ""}`
                    : "—"}
                </dd>
              </div>
              <div className="flex justify-between gap-3">
                <dt className="text-ash">Detected</dt>
                <dd className="text-muted">
                  {new Date(finding.created_at).toLocaleDateString()}
                </dd>
              </div>
            </dl>
          </section>

          <section className="panel p-5">
            <h2 className="mono mb-2 text-ash">Verification</h2>
            {verifications.length === 0 ? (
              <p className="font-mono text-[11px] leading-relaxed text-ash">
                No verification run has been requested for this finding.
              </p>
            ) : (
              <ul className="space-y-2">
                {verifications.map((run) => (
                  <li key={run.id} className="font-mono text-[11px]">
                    <span className="text-lavender">{run.status}</span>
                    <span className="ml-2 text-ash">
                      {new Date(run.created_at).toLocaleString()}
                    </span>
                  </li>
                ))}
              </ul>
            )}

            <form action={requestVerificationAction} className="mt-4">
              <input type="hidden" name="finding_id" value={finding.id} />
              <button
                type="submit"
                disabled={!source}
                className="btn btn-outline h-9 w-full px-3 disabled:opacity-40"
              >
                Re-test this finding
              </button>
            </form>
            <p className="mt-2 font-mono text-[10px] leading-relaxed text-ash">
              {source
                ? `Uses the latest stored source (${source.label ?? source.id.slice(0, 8)}). The backend re-checks membership before queuing.`
                : "No source snapshot is stored for this project, so a re-test cannot be requested yet."}
            </p>
          </section>
        </aside>
      </div>
    </div>
  );
}
