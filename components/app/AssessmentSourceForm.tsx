"use client";

import { useState } from "react";

import { createApiClient, type ScanRecord } from "@/lib/api/client";
import { getSupabaseBrowserClient } from "@/lib/supabase/client";

type Props = {
  workspaceId: string;
  projectId: string;
};

/**
 * Source upload → scan creation → status polling.
 *
 * Calls the FastAPI backend with the user's bearer token. Nothing is written
 * to the database from the browser: the backend stores the source and the scan
 * under the service role after verifying workspace membership.
 */
export function AssessmentSourceForm({ workspaceId, projectId }: Props) {
  const [file, setFile] = useState<File | null>(null);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [scan, setScan] = useState<ScanRecord | null>(null);

  const api = () => createApiClient(getSupabaseBrowserClient());

  async function poll(scanId: string) {
    for (let attempt = 0; attempt < 40; attempt += 1) {
      const result = await api().getScan(scanId);
      if (result.data) {
        setScan(result.data.scan);
        if (["completed", "failed", "cancelled"].includes(result.data.scan.status)) {
          return;
        }
      }
      await new Promise((resolve) => setTimeout(resolve, 3000));
    }
  }

  async function onSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!file) {
      setError("Choose a .zip archive of the source tree.");
      return;
    }
    setError(null);
    setPending(true);
    setScan(null);

    const uploaded = await api().uploadSource(workspaceId, projectId, file);
    if (uploaded.error) {
      setError(uploaded.error.message);
      setPending(false);
      return;
    }

    const created = await api().createScan(
      workspaceId,
      projectId,
      uploaded.data.source.id,
    );
    if (created.error) {
      setError(created.error.message);
      setPending(false);
      return;
    }

    setScan(created.data.scan);
    await poll(created.data.scan.id);
    setPending(false);
  }

  async function onCancel() {
    if (!scan) return;
    const result = await api().cancelScan(scan.id);
    if (result.error) setError(result.error.message);
    else setScan(result.data.scan);
  }

  return (
    <div className="panel p-5">
      <h3 className="display-sub mb-1 text-fog">Source archive</h3>
      <p className="body-copy mb-4 text-[13px]">
        ZIP only. The archive is validated for traversal, symlinks, size and file
        count, then stored server-side. Uploaded code is never executed.
      </p>

      <form onSubmit={onSubmit} className="space-y-3">
        {error ? (
          <p
            role="alert"
            className="border border-red-500/30 bg-red-500/10 px-3 py-2 font-mono text-[11px] text-red-200"
          >
            {error}
          </p>
        ) : null}

        <input
          type="file"
          accept=".zip,application/zip"
          onChange={(event) => setFile(event.target.files?.[0] ?? null)}
          className="block w-full cursor-pointer border border-dashed border-hairline bg-void px-3 py-6 font-mono text-[11.5px] text-muted file:mr-3 file:border-0 file:bg-violet/20 file:px-3 file:py-2 file:font-mono file:text-[10px] file:uppercase file:tracking-[0.14em] file:text-lavender"
        />

        <div className="flex items-center gap-3">
          <button
            type="submit"
            disabled={pending || !file}
            className="btn btn-primary h-9 px-3 disabled:opacity-50"
          >
            {pending ? "Running…" : "Upload and assess"}
          </button>
          {scan && ["queued", "running"].includes(scan.status) ? (
            <button
              type="button"
              onClick={onCancel}
              className="btn btn-outline h-9 px-3"
            >
              Cancel run
            </button>
          ) : null}
        </div>
      </form>

      {scan ? (
        <dl className="mt-4 space-y-1.5 border-t border-hairline pt-4 font-mono text-[11px]">
          <div className="flex justify-between gap-3">
            <dt className="text-ash">Scan</dt>
            <dd className="text-muted">{scan.id.slice(0, 8)}</dd>
          </div>
          <div className="flex justify-between gap-3">
            <dt className="text-ash">Status</dt>
            <dd className="uppercase tracking-[0.14em] text-lavender">
              {scan.status}
            </dd>
          </div>
          <div className="flex justify-between gap-3">
            <dt className="text-ash">Findings stored</dt>
            <dd className="text-muted">{scan.findings_total ?? 0}</dd>
          </div>
          {scan.error_message ? (
            <div className="pt-2 text-red-300">{scan.error_message}</div>
          ) : null}
        </dl>
      ) : null}

      <p className="mt-4 font-mono text-[10px] leading-relaxed text-ash">
        A queued scan needs a running worker. If the status stays queued, the
        worker process is not consuming jobs — that is a deployment state, not a
        finding.
      </p>
    </div>
  );
}
