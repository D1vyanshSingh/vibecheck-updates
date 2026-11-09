"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

import { Pill, SeverityDot } from "@/components/app/ui";
import { createApiClient, type AssessmentResult } from "@/lib/api/client";
import { getSupabaseBrowserClient } from "@/lib/supabase/client";

type Props = {
  workspaceId: string;
  projectId: string;
  defaultUrl?: string | null;
};

/**
 * Website assessment over HTTP.
 *
 * The backend fetches the URL once, guards every hop against SSRF, and persists
 * the result as a completed scan. This form only collects the URL and an
 * explicit authorisation acknowledgement; it never contacts the target itself.
 */
export function UrlAssessmentForm({ workspaceId, projectId, defaultUrl }: Props) {
  const router = useRouter();
  const [url, setUrl] = useState(defaultUrl ?? "");
  const [authorized, setAuthorized] = useState(false);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<AssessmentResult | null>(null);

  async function onSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!url.trim()) {
      setError("Enter the URL you are authorised to assess.");
      return;
    }
    if (!authorized) {
      setError("Confirm that you are authorised to test this target.");
      return;
    }

    setError(null);
    setPending(true);
    const api = createApiClient(getSupabaseBrowserClient());
    const response = await api.assessUrl(workspaceId, projectId, url.trim());
    setPending(false);

    if (response.error) {
      setError(response.error.message);
      return;
    }

    setResult(response.data);
    router.refresh();
  }

  return (
    <div className="panel p-5">
      <h3 className="display-sub mb-1 text-fog">Website assessment</h3>
      <p className="body-copy mb-4 text-[13px]">
        One authorised URL. The backend checks headers and transport only — no
        authentication, fuzzing or injection testing runs from the console.
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
          <span className="mono-sm text-ash">Target URL</span>
          <input
            type="url"
            required
            value={url}
            onChange={(event) => setUrl(event.target.value)}
            placeholder="https://staging.example.com"
            className="mt-1 block h-10 w-full border border-hairline bg-void px-3 font-mono text-[12px] text-fog outline-none focus:border-violet-bright/60"
          />
        </label>

        <label className="flex items-start gap-2 font-mono text-[10.5px] leading-relaxed text-ash">
          <input
            type="checkbox"
            checked={authorized}
            onChange={(event) => setAuthorized(event.target.checked)}
            className="mt-0.5 accent-violet-bright"
          />
          <span>
            I own or am authorised to test this target. Private and loopback
            addresses are refused unless the deployment enables them explicitly.
          </span>
        </label>

        <button
          type="submit"
          disabled={pending || !authorized}
          className="btn btn-primary h-9 px-3 disabled:opacity-50"
        >
          {pending ? "Assessing…" : "Assess URL"}
        </button>
      </form>

      {result ? (
        <div className="mt-4 space-y-4 border-t border-hairline pt-4">
          <dl className="space-y-1.5 font-mono text-[11px]">
            <div className="flex justify-between gap-3">
              <dt className="text-ash">HTTP status</dt>
              <dd className="text-muted">{result.assessment.status_code ?? "no response"}</dd>
            </div>
            <div className="flex justify-between gap-3">
              <dt className="text-ash">Final URL</dt>
              <dd className="truncate text-muted">
                {result.assessment.final_url ?? "not resolved"}
              </dd>
            </div>
            <div className="flex justify-between gap-3">
              <dt className="text-ash">Redirects followed</dt>
              <dd className="text-muted">{result.assessment.redirects.length}</dd>
            </div>
            <div className="flex justify-between gap-3">
              <dt className="text-ash">Findings stored</dt>
              <dd className="text-muted">{result.findings.length}</dd>
            </div>
            <div className="flex justify-between gap-3">
              <dt className="text-ash">Scan</dt>
              <dd className="text-muted">{result.scan.id.slice(0, 8)}</dd>
            </div>
          </dl>

          {result.assessment.error ? (
            <p className="font-mono text-[11px] text-amber-200">
              {result.assessment.error}
            </p>
          ) : null}

          {result.findings.length > 0 ? (
            <ul className="divide-y divide-hairline border border-hairline">
              {result.findings.map((finding) => (
                <li
                  key={finding.id}
                  className="flex items-start justify-between gap-3 px-3 py-2"
                >
                  <div className="min-w-0">
                    <p className="flex items-center gap-2 text-[12.5px] text-fog">
                      <SeverityDot severity={finding.severity} />
                      <span className="truncate">{finding.title}</span>
                    </p>
                    <p className="mt-0.5 font-mono text-[10px] text-ash">
                      {finding.rule_id ?? finding.scanner}
                    </p>
                  </div>
                  <Pill
                    tone={
                      finding.severity === "critical" || finding.severity === "high"
                        ? "danger"
                        : "muted"
                    }
                  >
                    {finding.severity}
                  </Pill>
                </li>
              ))}
            </ul>
          ) : (
            <p className="font-mono text-[11px] text-ash">
              No header observations were produced. That is not proof the site is
              secure: only the checks listed above executed.
            </p>
          )}

          {result.assessment.limitations.length > 0 ? (
            <div>
              <p className="mono-sm mb-1 text-ash">Coverage limitations</p>
              <ul className="space-y-1 font-mono text-[10.5px] leading-relaxed text-ash">
                {result.assessment.limitations.map((limitation) => (
                  <li key={limitation}>· {limitation}</li>
                ))}
              </ul>
            </div>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}
