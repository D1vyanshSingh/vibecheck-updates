"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

import { createApiClient, type ScanRecord } from "@/lib/api/client";
import { getSupabaseBrowserClient } from "@/lib/supabase/client";

const REPOSITORY = /^[A-Za-z0-9._-]+$/;

/**
 * Read-only repository import through the GitHub App.
 *
 * When the deployment has no GitHub App credentials the backend answers 503 and
 * that message is shown verbatim — the form never pretends an import happened.
 */
export function GitHubImportForm({
  workspaceId,
  projectId,
}: {
  workspaceId: string;
  projectId: string;
}) {
  const router = useRouter();
  const [repository, setRepository] = useState("");
  const [ref, setRef] = useState("");
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [scan, setScan] = useState<ScanRecord | null>(null);

  const [owner, repo] = repository.split("/");

  async function onSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!owner || !repo || !REPOSITORY.test(owner) || !REPOSITORY.test(repo)) {
      setError("Use the owner/name form, for example acme/widgets.");
      return;
    }

    setError(null);
    setScan(null);
    setPending(true);

    const api = createApiClient(getSupabaseBrowserClient());
    const response = await api.importGitHubRepository(workspaceId, projectId, owner, repo, ref);
    setPending(false);

    if (response.error) {
      setError(response.error.message);
      return;
    }

    setScan(response.data.scan);
    router.refresh();
  }

  return (
    <div className="panel p-5">
      <h3 className="display-sub mb-1 text-fog">GitHub import</h3>
      <p className="body-copy mb-4 text-[13px]">
        Read-only archive of one repository, then a normal assessment run. Requires
        a configured GitHub App installation; without one the backend refuses rather
        than guessing.
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

        <label className="block">
          <span className="mono-sm text-ash">Repository</span>
          <input
            value={repository}
            onChange={(event) => setRepository(event.target.value)}
            placeholder="owner/name"
            className="mt-1 block h-10 w-full border border-hairline bg-void px-3 font-mono text-[12px] text-fog outline-none focus:border-violet-bright/60"
          />
        </label>

        <label className="block">
          <span className="mono-sm text-ash">Ref (optional)</span>
          <input
            value={ref}
            onChange={(event) => setRef(event.target.value)}
            placeholder="main"
            className="mt-1 block h-10 w-full border border-hairline bg-void px-3 font-mono text-[12px] text-fog outline-none focus:border-violet-bright/60"
          />
        </label>

        <button
          type="submit"
          disabled={pending}
          className="btn btn-outline h-9 px-3 disabled:opacity-50"
        >
          {pending ? "Importing…" : "Import repository"}
        </button>
      </form>

      {scan ? (
        <p className="mt-4 font-mono text-[11px] text-muted">
          Queued scan {scan.id.slice(0, 8)} for the imported archive.
        </p>
      ) : null}
    </div>
  );
}
