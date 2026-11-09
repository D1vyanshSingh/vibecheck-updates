import type { SupabaseClient } from "@supabase/supabase-js";

/**
 * Single typed client for the VibeCheck FastAPI backend.
 *
 * - Reads the backend origin from NEXT_PUBLIC_BACKEND_URL (browser) with a
 *   server-side fallback to BACKEND_PUBLIC_URL.
 * - Attaches the current Supabase access token as a bearer token, refreshing it
 *   once if the first attempt returns 401.
 * - Handles JSON and multipart/form-data without ever setting a multipart
 *   boundary by hand.
 * - Never touches the service-role key: this module is browser-safe.
 */

export type ApiErrorKind =
  | "not_configured"
  | "network"
  | "unauthorized"
  | "forbidden"
  | "not_found"
  | "conflict"
  | "server"
  | "unavailable"
  | "invalid";

export type ApiError = {
  kind: ApiErrorKind;
  message: string;
  status?: number;
};

export type ApiResult<T> = { data: T; error: null } | { data: null; error: ApiError };

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Confidence = "low" | "medium" | "high";

export type ScanStatus =
  | "queued"
  | "running"
  | "completed"
  | "failed"
  | "cancelled";

export type FindingStatus =
  | "open"
  | "triaged"
  | "under_review"
  | "fix_proposed"
  | "ready_for_verification"
  | "fixed"
  | "verified"
  | "still_present"
  | "unable_to_verify"
  | "accepted_risk"
  | "false_positive";

export interface ScanRecord {
  id: string;
  workspace_id: string;
  project_id: string;
  source_id: string | null;
  status: ScanStatus;
  trigger: string;
  findings_total: number | null;
  error_message: string | null;
  started_at: string | null;
  completed_at: string | null;
  created_at: string;
  coverage: Record<string, unknown> | null;
}

export interface ScanJob {
  id: string;
  scan_id: string;
  kind: string;
  status: string;
  attempts: number | null;
  error_message: string | null;
  started_at: string | null;
  finished_at: string | null;
}

export interface SourceRecord {
  id: string;
  workspace_id: string;
  project_id: string;
  kind: string;
  label: string | null;
  size_bytes: number | null;
  file_count: number | null;
  sha256: string | null;
  created_at: string;
}

export interface FindingRecord {
  id: string;
  workspace_id: string;
  project_id: string;
  scan_id: string | null;
  severity: Severity;
  status: FindingStatus;
  category: string;
  title: string;
  description: string | null;
  file_path: string | null;
  line_start: number | null;
  line_end: number | null;
  rule_id: string | null;
  scanner: string;
  confidence: Confidence;
  remediation: string | null;
  redacted_evidence: string | null;
  verified_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface FindingsPage {
  findings: FindingRecord[];
  total: number;
  limit: number;
  offset: number;
}

export interface AssessmentRecord {
  requested_url: string;
  final_url: string | null;
  status_code: number | null;
  headers: Record<string, string>;
  redirects: string[];
  body_bytes: number;
  error: string | null;
  limitations: string[];
}

export interface AssessmentResult {
  assessment: AssessmentRecord;
  scan: ScanRecord;
  findings: FindingRecord[];
  source: SourceRecord;
}

export type Observation = {
  kind: "cluster" | "coverage_gap" | "exposure_chain" | string;
  title: string;
  body: string;
  finding_ids?: string[];
};

export interface ScanAnalysis {
  scan_id: string;
  summary: {
    total: number;
    by_severity: Record<string, number>;
    by_scanner: Record<string, number>;
  };
  observations: Observation[];
  plan: {
    steps: Array<{ tool: string; reason: string; required: boolean }>;
    source: string;
    rejected: string[];
    notes: string;
  };
  tools_available: Record<string, boolean>;
}

export interface ReportRecord {
  id: string;
  workspace_id: string;
  project_id: string;
  scan_id: string | null;
  report_type: "client" | "technical";
  version: number;
  status: string;
  summary: string | null;
  created_at: string;
}

export type ReportOutput = "json" | "html" | "pdf";

export interface Capabilities {
  scanners: Record<string, unknown>;
  limits: Record<string, number>;
  [key: string]: unknown;
}

function backendOrigin(): string {
  const raw =
    process.env.NEXT_PUBLIC_BACKEND_URL ??
    process.env.BACKEND_PUBLIC_URL ??
    "";
  return raw.replace(/\/+$/, "");
}

async function accessToken(supabase: SupabaseClient): Promise<string | null> {
  const { data, error } = await supabase.auth.getSession();
  if (error) return null;
  return data.session?.access_token ?? null;
}

function classify(status: number, detail: string | null): ApiError {
  if (status === 401) return { kind: "unauthorized", message: "Session expired. Sign in again.", status };
  if (status === 403) return { kind: "forbidden", message: detail ?? "Your role does not allow this.", status };
  if (status === 404) return { kind: "not_found", message: detail ?? "Not found.", status };
  if (status === 409) return { kind: "conflict", message: detail ?? "The resource is in a conflicting state.", status };
  if (status === 422 || status === 400) return { kind: "invalid", message: detail ?? "The request was rejected.", status };
  if (status === 503) return { kind: "unavailable", message: detail ?? "The assessment service is unavailable.", status };
  if (status >= 500) return { kind: "server", message: detail ?? "The backend returned a server error.", status };
  return { kind: "invalid", message: detail ?? `Request failed (${status}).`, status };
}

async function request<T>(
  method: string,
  path: string,
  init: { body?: BodyInit | null; token: string | null; headers?: Record<string, string> },
): Promise<ApiResult<T>> {
  const origin = backendOrigin();
  if (!origin) {
    return {
      data: null,
      error: {
        kind: "not_configured",
        message: "NEXT_PUBLIC_BACKEND_URL is not set, so no assessment service is reachable.",
      },
    };
  }

  const headers: Record<string, string> = { ...(init.headers ?? {}) };
  if (init.token) headers.Authorization = `Bearer ${init.token}`;
  if (init.body && !(init.body instanceof FormData)) {
    headers["Content-Type"] = "application/json";
  }

  let response: Response;
  try {
    response = await fetch(`${origin}${path}`, {
      method,
      headers,
      body: init.body ?? undefined,
      cache: "no-store",
    });
  } catch {
    return {
      data: null,
      error: { kind: "network", message: "Could not reach the assessment service." },
    };
  }

  const text = await response.text();

  if (!response.ok) {
    let detail: string | null = null;
    try {
      const parsed = JSON.parse(text) as { detail?: unknown };
      if (typeof parsed.detail === "string") detail = parsed.detail;
    } catch {
      detail = text.slice(0, 200) || null;
    }
    return { data: null, error: classify(response.status, detail) };
  }

  if (!text) return { data: {} as T, error: null };

  try {
    return { data: JSON.parse(text) as T, error: null };
  } catch {
    return {
      data: null,
      error: { kind: "server", message: "The backend returned a non-JSON response." },
    };
  }
}

/** Binary/text download that skips JSON parsing and keeps the HTTP status. */
async function requestBlob(
  path: string,
  token: string | null,
): Promise<ApiResult<{ blob: Blob; filename: string | null }>> {
  const origin = backendOrigin();
  if (!origin) {
    return {
      data: null,
      error: {
        kind: "not_configured",
        message: "NEXT_PUBLIC_BACKEND_URL is not set, so no assessment service is reachable.",
      },
    };
  }

  let response: Response;
  try {
    response = await fetch(`${origin}${path}`, {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
      cache: "no-store",
    });
  } catch {
    return {
      data: null,
      error: { kind: "network", message: "Could not reach the assessment service." },
    };
  }

  if (!response.ok) {
    const text = await response.text();
    let detail: string | null = null;
    try {
      const parsed = JSON.parse(text) as { detail?: unknown };
      if (typeof parsed.detail === "string") detail = parsed.detail;
    } catch {
      detail = text.slice(0, 200) || null;
    }
    return { data: null, error: classify(response.status, detail) };
  }

  const disposition = response.headers.get("content-disposition") ?? "";
  const match = /filename="?([^";]+)"?/.exec(disposition);

  return {
    data: { blob: await response.blob(), filename: match?.[1] ?? null },
    error: null,
  };
}

export function createApiClient(supabase: SupabaseClient) {
  async function authed<T>(
    method: string,
    path: string,
    init: { body?: BodyInit | null; headers?: Record<string, string> } = {},
  ): Promise<ApiResult<T>> {
    let token = await accessToken(supabase);
    let result = await request<T>(method, path, { ...init, token });

    if (result.error?.kind === "unauthorized") {
      // One refresh attempt: the access token may simply have expired.
      const { data, error } = await supabase.auth.refreshSession();
      if (!error && data.session) {
        token = data.session.access_token;
        result = await request<T>(method, path, { ...init, token });
      }
    }

    return result;
  }

  return {
    async health() {
      return request<{ status: string }>("GET", "/health", { token: null });
    },

    async capabilities() {
      return request<Capabilities>("GET", "/v1/capabilities", { token: null });
    },

    async uploadSource(workspaceId: string, projectId: string, file: File) {
      const form = new FormData();
      form.append("workspace_id", workspaceId);
      form.append("project_id", projectId);
      form.append("file", file);
      return authed<{ source: SourceRecord }>("POST", "/v1/sources", { body: form });
    },

    async createScan(
      workspaceId: string,
      projectId: string,
      sourceId: string,
      trigger: "manual" | "push" | "scheduled" = "manual",
    ) {
      return authed<{ scan: ScanRecord }>("POST", "/v1/scans", {
        body: JSON.stringify({
          workspace_id: workspaceId,
          project_id: projectId,
          source_id: sourceId,
          trigger,
        }),
      });
    },

    async getScan(scanId: string) {
      return authed<{ scan: ScanRecord; jobs: ScanJob[] }>(
        "GET",
        `/v1/scans/${encodeURIComponent(scanId)}`,
      );
    },

    async cancelScan(scanId: string) {
      return authed<{ scan: ScanRecord }>(
        "POST",
        `/v1/scans/${encodeURIComponent(scanId)}/cancel`,
      );
    },

    async listFindings(
      workspaceId: string,
      filters: {
        severity?: Severity;
        status?: FindingStatus;
        projectId?: string;
        scanner?: string;
        limit?: number;
        offset?: number;
      } = {},
    ) {
      const params = new URLSearchParams();
      if (filters.severity) params.set("severity", filters.severity);
      if (filters.status) params.set("status", filters.status);
      if (filters.projectId) params.set("project_id", filters.projectId);
      if (filters.scanner) params.set("scanner", filters.scanner);
      if (filters.limit) params.set("limit", String(filters.limit));
      if (filters.offset) params.set("offset", String(filters.offset));
      const query = params.toString();
      return authed<FindingsPage>(
        "GET",
        `/v1/workspaces/${encodeURIComponent(workspaceId)}/findings${query ? `?${query}` : ""}`,
      );
    },

    async getFinding(findingId: string) {
      return authed<{
        finding: FindingRecord;
        evidence: Array<Record<string, unknown>>;
      }>("GET", `/v1/findings/${encodeURIComponent(findingId)}`);
    },

    async importGitHubRepository(
      workspaceId: string,
      projectId: string,
      owner: string,
      repo: string,
      ref?: string,
    ) {
      return authed<{ source: SourceRecord; scan: ScanRecord }>(
        "POST",
        `/v1/workspaces/${encodeURIComponent(workspaceId)}/integrations/github/import`,
        {
          body: JSON.stringify({
            project_id: projectId,
            owner,
            repo,
            ref: ref?.trim() ? ref.trim() : undefined,
          }),
        },
      );
    },

    async runBenchmark(workspaceId: string, corpusVersion = "v1") {
      return authed<{ run: Record<string, unknown>; result: Record<string, unknown> }>(
        "POST",
        `/v1/workspaces/${encodeURIComponent(workspaceId)}/benchmarks`,
        { body: JSON.stringify({ corpus_version: corpusVersion }) },
      );
    },

    async assessUrl(workspaceId: string, projectId: string, sourceUrl: string) {
      return authed<AssessmentResult>(
        "POST",
        `/v1/workspaces/${encodeURIComponent(workspaceId)}/url-assessment`,
        { body: JSON.stringify({ project_id: projectId, source_url: sourceUrl }) },
      );
    },

    async getAnalysis(scanId: string) {
      return authed<ScanAnalysis>(
        "GET",
        `/v1/scans/${encodeURIComponent(scanId)}/analysis`,
      );
    },

    async createReport(
      scanId: string,
      reportType: "client" | "technical",
      version = 1,
    ) {
      return authed<{ report: ReportRecord }>(
        "POST",
        `/v1/scans/${encodeURIComponent(scanId)}/reports`,
        { body: JSON.stringify({ report_type: reportType, version }) },
      );
    },

    async downloadReport(
      scanId: string,
      options: { reportType?: "client" | "technical"; output?: ReportOutput; version?: number } = {},
    ) {
      const params = new URLSearchParams({
        report_type: options.reportType ?? "technical",
        output: options.output ?? "json",
        version: String(options.version ?? 1),
      });
      const path = `/v1/scans/${encodeURIComponent(scanId)}/report?${params.toString()}`;

      let token = await accessToken(supabase);
      let result = await requestBlob(path, token);

      if (result.error?.kind === "unauthorized") {
        const { data, error } = await supabase.auth.refreshSession();
        if (!error && data.session) {
          token = data.session.access_token;
          result = await requestBlob(path, token);
        }
      }

      return result;
    },

    async requestVerification(findingId: string, sourceId: string) {
      return authed<{ scan: ScanRecord; verification_run: Record<string, unknown> }>(
        "POST",
        `/v1/findings/${encodeURIComponent(findingId)}/verify`,
        { body: JSON.stringify({ source_id: sourceId }) },
      );
    },
  };
}

export type ApiClient = ReturnType<typeof createApiClient>;
