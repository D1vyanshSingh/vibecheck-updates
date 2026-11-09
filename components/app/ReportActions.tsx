"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";

import {
  createApiClient,
  type ReportOutput,
  type ReportRecord,
} from "@/lib/api/client";
import { getSupabaseBrowserClient } from "@/lib/supabase/client";

type ReportType = "client" | "technical";

const OUTPUTS: Array<{ output: ReportOutput; label: string; type: string }> = [
  { output: "json", label: "JSON", type: "application/json" },
  { output: "html", label: "HTML", type: "text/html" },
  { output: "pdf", label: "PDF", type: "application/pdf" },
];

/**
 * Report generation and download for one scan.
 *
 * Generation records a snapshot row; rendering happens on the backend from
 * persisted scan and finding rows, so every format shows the same data.
 */
export function ReportActions({ scanId }: { scanId: string }) {
  const router = useRouter();
  const [reportType, setReportType] = useState<ReportType>("technical");
  const [version, setVersion] = useState(1);
  const [report, setReport] = useState<ReportRecord | null>(null);
  const [pending, setPending] = useState(false);
  const [downloading, setDownloading] = useState<ReportOutput | null>(null);
  const [error, setError] = useState<string | null>(null);

  const api = () => createApiClient(getSupabaseBrowserClient());

  async function onGenerate() {
    setPending(true);
    setError(null);
    const response = await api().createReport(scanId, reportType, version);
    setPending(false);
    if (response.error) {
      setError(response.error.message);
      return;
    }
    setReport(response.data.report);
    router.refresh();
  }

  async function onDownload(output: ReportOutput, mime: string) {
    setDownloading(output);
    setError(null);
    const response = await api().downloadReport(scanId, {
      reportType,
      output,
      version,
    });
    setDownloading(null);

    if (response.error) {
      setError(response.error.message);
      return;
    }

    const filename =
      response.data.filename ??
      `vibecheck-${scanId.slice(0, 8)}-${reportType}-v${version}.${output}`;
    const href = URL.createObjectURL(new Blob([response.data.blob], { type: mime }));
    const anchor = document.createElement("a");
    anchor.href = href;
    anchor.download = filename;
    document.body.append(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(href);
  }

  return (
    <section>
      <h2 className="mono mb-3 text-ash">Reports</h2>
      <div className="panel space-y-3 p-4">
        {error ? (
          <p
            role="alert"
            className="border border-red-500/30 bg-red-500/10 px-3 py-2 font-mono text-[11px] text-red-200"
          >
            {error}
          </p>
        ) : null}

        <div className="flex flex-wrap items-end gap-3">
          <label className="block">
            <span className="mono-sm text-ash">Type</span>
            <select
              value={reportType}
              onChange={(event) => setReportType(event.target.value as ReportType)}
              className="mt-1 block h-9 border border-hairline bg-void px-2 font-mono text-[11.5px] text-fog outline-none focus:border-violet-bright/60"
            >
              <option value="technical">Technical assessment</option>
              <option value="client">Client security report</option>
            </select>
          </label>

          <label className="block">
            <span className="mono-sm text-ash">Version</span>
            <input
              type="number"
              min={1}
              max={99}
              value={version}
              onChange={(event) =>
                setVersion(Math.min(99, Math.max(1, Number(event.target.value) || 1)))
              }
              className="mt-1 block h-9 w-20 border border-hairline bg-void px-2 font-mono text-[11.5px] text-fog outline-none focus:border-violet-bright/60"
            />
          </label>

          <button
            type="button"
            onClick={onGenerate}
            disabled={pending}
            className="btn btn-primary h-9 px-3 disabled:opacity-50"
          >
            {pending ? "Recording…" : "Generate snapshot"}
          </button>
        </div>

        <div className="flex flex-wrap items-center gap-2 border-t border-hairline pt-3">
          <span className="mono-sm text-ash">Download</span>
          {OUTPUTS.map((item) => (
            <button
              key={item.output}
              type="button"
              onClick={() => onDownload(item.output, item.type)}
              disabled={downloading !== null}
              className="btn btn-outline h-8 px-3 disabled:opacity-50"
            >
              {downloading === item.output ? "…" : item.label}
            </button>
          ))}
        </div>

        {report ? (
          <p className="font-mono text-[10.5px] text-ash">
            Snapshot recorded:{" "}
            <Link
              href={`/app/reports/${report.id}`}
              className="text-lavender hover:text-fog"
            >
              {report.report_type} v{report.version}
            </Link>{" "}
            · {report.status}
          </p>
        ) : (
          <p className="font-mono text-[10px] leading-relaxed text-ash">
            Downloads render from stored rows even before a snapshot is recorded.
            Recording one puts it in the reports list with its summary.
          </p>
        )}
      </div>
    </section>
  );
}
