"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import {
  AlertTriangle,
  ArrowRight,
  Download,
  ExternalLink,
  LoaderCircle,
  Radar,
  RotateCcw,
  ShieldCheck,
} from "lucide-react";

import { VibeCheckLogo } from "@/components/brand/VibeCheckLogo";
import { cn } from "@/lib/cn";
import type {
  ScanFinding,
  ScanReport,
  ScanResult,
  Severity,
} from "@/lib/scan/types";

const SEVERITY_ORDER: Severity[] = [
  "critical",
  "high",
  "medium",
  "low",
  "informational",
];

const SEVERITY_META: Record<
  Severity,
  { label: string; color: string; wash: string }
> = {
  critical: { label: "Critical", color: "#ff8a9b", wash: "rgba(255,92,110,0.13)" },
  high: { label: "High", color: "#ff9d7a", wash: "rgba(255,122,80,0.13)" },
  medium: { label: "Medium", color: "#ffc46b", wash: "rgba(255,176,32,0.12)" },
  low: { label: "Low", color: "#8ec5ff", wash: "rgba(80,150,255,0.12)" },
  informational: {
    label: "Informational",
    color: "#b9b3cc",
    wash: "rgba(165,160,181,0.12)",
  },
};

type State =
  | { kind: "idle" }
  | { kind: "scanning" }
  | { kind: "done"; result: ScanResult }
  | { kind: "error"; message: string };

const PROGRESS = [
  "Resolving the host and checking which ports answer",
  "Reading banners, TLS certificates and HTTP headers",
  "Applying the checks and scoring what was found",
  "Writing the branded report",
];

function ScanForm({
  onSubmit,
  busy,
  initialUrl,
}: {
  onSubmit: (url: string) => void;
  busy: boolean;
  initialUrl: string;
}) {
  const [url, setUrl] = useState(initialUrl);

  useEffect(() => {
    if (initialUrl) setUrl(initialUrl);
  }, [initialUrl]);

  return (
    <form
      onSubmit={(event) => {
        event.preventDefault();
        if (!url.trim() || busy) return;
        onSubmit(url);
      }}
      className="panel p-6 sm:p-8"
    >
      <div className="flex items-center justify-between gap-4">
        <p className="mono text-lavender">Scan a URL</p>
        <span className="mono-sm text-ash">Live scan</span>
      </div>

      <label htmlFor="scan-url" className="mono-sm mt-6 block text-ash">
        Target URL
      </label>
      <div className="mt-2 flex flex-col gap-2 sm:flex-row">
        <input
          id="scan-url"
          name="url"
          type="text"
          inputMode="url"
          autoComplete="url"
          spellCheck={false}
          required
          value={url}
          onChange={(event) => setUrl(event.target.value)}
          placeholder="https://your-app.com"
          className="h-11 w-full border border-hairline bg-[#0b0a11] px-3 font-mono text-[13px] text-fog outline-none transition-colors placeholder:text-[#4f4b5e] focus:border-lavender/60"
        />
        <button
          type="submit"
          disabled={busy}
          aria-busy={busy}
          className="btn btn-primary h-11 shrink-0 sm:w-auto disabled:cursor-not-allowed disabled:opacity-60"
        >
          {busy ? (
            <>
              <LoaderCircle className="h-3.5 w-3.5 animate-spin" aria-hidden="true" />
              Scanning
            </>
          ) : (
            <>
              Run scan
              <ArrowRight className="h-3.5 w-3.5" aria-hidden="true" />
            </>
          )}
        </button>
      </div>

      <p className="mono-sm mt-4 text-ash">
        Only scan hosts you own or have written permission to test. The scan is
        non-intrusive: it reads what the service answers and never exploits it.
      </p>
    </form>
  );
}

function Scanning({ seconds }: { seconds: number }) {
  const stage =
    seconds < 6
      ? PROGRESS[0]
      : seconds < 20
        ? PROGRESS[1]
        : seconds < 60
          ? PROGRESS[2]
          : PROGRESS[3];

  return (
    <div className="panel mt-6 flex items-center gap-5 p-6" role="status" aria-live="polite">
      <span className="relative flex h-10 w-10 shrink-0 items-center justify-center">
        <span className="absolute inset-0 animate-ping rounded-full bg-violet/20" aria-hidden="true" />
        <Radar className="relative h-5 w-5 text-lavender" aria-hidden="true" />
      </span>
      <div className="min-w-0">
        <p className="mono text-fog">
          Scanning · {seconds}s
        </p>
        <p className="body-copy mt-1 text-[13px]">{stage}.</p>
      </div>
    </div>
  );
}

function formatWhen(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return `${date.toLocaleString("en-GB", {
    dateStyle: "medium",
    timeStyle: "short",
    timeZone: "UTC",
  })} UTC`;
}

function assetLabel(finding: ScanFinding): string {
  const asset = finding.asset;
  if (asset.url) return asset.url;
  const host = asset.host || asset.ip || "unknown host";
  return `${host}:${asset.port ?? "?"}/${asset.protocol ?? "tcp"}`;
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <p className="mono-sm text-ash">{label}</p>
      <div className="body-copy mt-1.5 text-[13px]">{children}</div>
    </div>
  );
}

function FindingCard({ finding }: { finding: ScanFinding }) {
  const meta = SEVERITY_META[finding.severity] ?? SEVERITY_META.informational;
  const score = finding.cvss?.score;

  return (
    <article className="panel p-5" style={{ borderLeft: `3px solid ${meta.color}` }}>
      <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
        <span
          className="mono-sm px-2 py-1"
          style={{ color: meta.color, backgroundColor: meta.wash }}
        >
          {meta.label}
        </span>
        <span className="mono-sm text-ash">{finding.id}</span>
        <span className="mono-sm text-ash">CVSS {score ?? "—"}</span>
        <span className="mono-sm text-ash">{finding.confidence}</span>
        {finding.entry_point && (
          <span className="mono-sm text-violet-bright">initial access</span>
        )}
      </div>

      <h3 className="mt-3 font-display text-[18px] tracking-[-0.02em] text-fog">
        {finding.title}
      </h3>
      <p className="mt-1.5 font-mono text-[11.5px] text-ash">{assetLabel(finding)}</p>
      <p className="body-copy mt-3 text-[13px]">{finding.description}</p>

      <details className="group mt-4 border-t border-hairline-soft pt-3">
        <summary className="mono-sm cursor-pointer list-none text-lavender transition-colors hover:text-fog">
          Evidence, impact and fix
          <span className="ml-2 text-ash group-open:hidden">+</span>
          <span className="ml-2 hidden text-ash group-open:inline">−</span>
        </summary>
        <div className="mt-4 space-y-4">
          <Field label="Evidence">
            <pre className="max-h-56 overflow-auto whitespace-pre-wrap break-words border border-hairline bg-void p-3 font-mono text-[11.5px] leading-relaxed text-[#d9d2f2]">
              {finding.evidence || "No raw evidence was recorded."}
            </pre>
          </Field>
          <Field label="Impact">{finding.impact}</Field>
          <Field label="Recommended fix">{finding.remediation}</Field>
          {finding.cvss?.vector && (
            <Field label="CVSS 3.1 vector">
              <span className="font-mono text-[11.5px] text-muted">
                {finding.cvss.vector}
              </span>
            </Field>
          )}
          {finding.cve?.length ? (
            <Field label="References">
              <span className="font-mono text-[11.5px] text-muted">
                {finding.cve.join(" · ")}
              </span>
            </Field>
          ) : null}
        </div>
      </details>
    </article>
  );
}

/**
 * Prints the branded HTML report through the browser, which is how a scan host
 * without Chrome produces a PDF: the print dialog saves one.
 */
function printReport(html: string) {
  const frame = document.createElement("iframe");
  frame.setAttribute("aria-hidden", "true");
  frame.style.cssText =
    "position:fixed;right:0;bottom:0;width:0;height:0;border:0;";
  frame.srcdoc = html;
  frame.onload = () => {
    const view = frame.contentWindow;
    if (!view) return;
    view.focus();
    view.print();
    window.setTimeout(() => frame.remove(), 60_000);
  };
  document.body.appendChild(frame);
}

function ReportView({
  result,
  onReset,
}: {
  result: ScanResult;
  onReset: () => void;
}) {
  const { report } = result;
  const [filter, setFilter] = useState<Severity | "all">("all");

  // A remote scan host returns the report inline; serve it from memory.
  const inlineHtmlUrl = useMemo(() => {
    if (!result.html) return "";
    return URL.createObjectURL(new Blob([result.html], { type: "text/html" }));
  }, [result.html]);

  useEffect(() => {
    return () => {
      if (inlineHtmlUrl) URL.revokeObjectURL(inlineHtmlUrl);
    };
  }, [inlineHtmlUrl]);

  const htmlHref = result.htmlUrl || inlineHtmlUrl;

  const counts = report.summary.counts_by_severity;
  const criticalAndHigh = (counts.critical ?? 0) + (counts.high ?? 0);
  const total = Math.max(report.summary.total_findings, 1);

  const findings = useMemo(() => {
    const ordered = [...report.findings].sort(
      (a, b) =>
        SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity),
    );
    return filter === "all"
      ? ordered
      : ordered.filter((finding) => finding.severity === filter);
  }, [report.findings, filter]);

  return (
    <div className="mt-10 space-y-8">
      {/* Cover */}
      <section className="relative overflow-hidden border border-hairline bg-void p-6 sm:p-9">
        <div
          aria-hidden="true"
          className="pointer-events-none absolute inset-0 bg-[radial-gradient(60%_60%_at_20%_20%,rgba(112,43,255,0.42),transparent_72%),radial-gradient(45%_52%_at_88%_4%,rgba(151,79,255,0.26),transparent_72%)]"
        />
        <div className="relative">
          <div className="flex flex-wrap items-start justify-between gap-4">
            <VibeCheckLogo size="lg" showTagline />
            <span className="mono-sm border border-lavender/30 bg-violet/15 px-3 py-1.5 text-lavender">
              URL scan
            </span>
          </div>

          <h2 className="display mt-8 text-[clamp(1.7rem,3.4vw,2.5rem)] leading-[1.02] text-fog">
            {report.metadata.title}
          </h2>
          <p className="mt-3 font-mono text-[12px] text-muted">
            Target <span className="text-lavender">{result.target.url}</span> ·{" "}
            {formatWhen(report.metadata.started_at)}
          </p>

          <dl className="mt-8 grid gap-px border border-hairline bg-hairline sm:grid-cols-2 lg:grid-cols-4">
            {[
              {
                label: "Findings",
                value: String(report.summary.total_findings),
                note: `across ${report.summary.open_services} open service(s)`,
              },
              {
                label: "Critical + high",
                value: String(criticalAndHigh),
                note: "fix these first",
              },
              {
                label: "Open services",
                value: String(report.summary.open_services),
                note: `${report.scope.ports_scanned} web ports probed`,
              },
              {
                label: "Duration",
                value: `${report.metadata.duration_seconds.toFixed(1)}s`,
                note: `engine: ${report.metadata.engine}`,
              },
            ].map((kpi) => (
              <div key={kpi.label} className="bg-[#0c0b13] p-4">
                <dt className="mono-sm text-ash">{kpi.label}</dt>
                <dd className="mt-2 font-display text-[28px] leading-none tracking-[-0.03em] text-fog">
                  {kpi.value}
                </dd>
                <p className="mt-2 text-[11px] leading-relaxed text-ash">{kpi.note}</p>
              </div>
            ))}
          </dl>

          <div className="mt-6 flex flex-wrap gap-3">
            {result.pdfUrl ? (
              <a href={result.pdfUrl} download className="btn btn-primary">
                <Download className="h-3.5 w-3.5" aria-hidden="true" />
                Download branded PDF
              </a>
            ) : result.html ? (
              <button
                type="button"
                onClick={() => printReport(result.html as string)}
                className="btn btn-primary"
              >
                <Download className="h-3.5 w-3.5" aria-hidden="true" />
                Print / save as PDF
              </button>
            ) : null}
            {htmlHref ? (
              <a
                href={htmlHref}
                target="_blank"
                rel="noreferrer"
                className="btn btn-outline"
              >
                <ExternalLink className="h-3.5 w-3.5" aria-hidden="true" />
                Open full report
              </a>
            ) : null}
            <button type="button" onClick={onReset} className="btn btn-quiet">
              <RotateCcw className="h-3.5 w-3.5" aria-hidden="true" />
              Scan another URL
            </button>
          </div>
          {!result.pdfUrl && result.html && (
            <p className="mono-sm mt-3 text-ash">
              This scan host has no browser to render a PDF, so the report is
              printed instead — choose “Save as PDF” in the print dialog.
            </p>
          )}
        </div>
      </section>

      {/* Severity rail */}
      <section aria-labelledby="scan-severity" className="panel p-6">
        <div className="flex flex-wrap items-baseline justify-between gap-3">
          <h2 id="scan-severity" className="font-display text-[20px] tracking-[-0.03em] text-fog">
            What the scan found
          </h2>
          <p className="mono-sm text-ash">
            {report.summary.total_findings} finding(s) · report schema{" "}
            {report.report_version}
          </p>
        </div>

        <div className="mt-5 flex h-2 overflow-hidden rounded-full bg-white/5" aria-hidden="true">
          {SEVERITY_ORDER.map((severity) => {
            const value = counts[severity] ?? 0;
            if (!value) return null;
            return (
              <span
                key={severity}
                style={{
                  width: `${(value / total) * 100}%`,
                  backgroundColor: SEVERITY_META[severity].color,
                }}
              />
            );
          })}
        </div>

        <div className="mt-4 flex flex-wrap gap-2">
          <button
            type="button"
            onClick={() => setFilter("all")}
            aria-pressed={filter === "all"}
            className={cn(
              "mono-sm border px-3 py-2 transition-colors",
              filter === "all"
                ? "border-lavender/50 bg-lavender/10 text-fog"
                : "border-hairline text-muted hover:text-fog",
            )}
          >
            All {report.summary.total_findings}
          </button>
          {SEVERITY_ORDER.map((severity) => {
            const meta = SEVERITY_META[severity];
            const value = counts[severity] ?? 0;
            return (
              <button
                key={severity}
                type="button"
                onClick={() => setFilter(severity)}
                aria-pressed={filter === severity}
                className={cn(
                  "mono-sm flex items-center gap-2 border px-3 py-2 transition-colors",
                  filter === severity
                    ? "border-white/25 bg-white/5 text-fog"
                    : "border-hairline text-muted hover:text-fog",
                )}
              >
                <span
                  className="h-1.5 w-1.5 rounded-full"
                  style={{ backgroundColor: meta.color }}
                  aria-hidden="true"
                />
                {meta.label} {value}
              </button>
            );
          })}
        </div>

        <div className="mt-6 space-y-4">
          {findings.length ? (
            findings.map((finding) => (
              <FindingCard key={finding.id} finding={finding} />
            ))
          ) : (
            <p className="body-copy text-[13px]">
              No finding in this band. That is not proof the service is clean —
              a surface scan only sees what answers.
            </p>
          )}
        </div>
      </section>

      {/* Assets */}
      <section aria-labelledby="scan-assets" className="panel p-6">
        <div className="flex flex-wrap items-baseline justify-between gap-3">
          <h2 id="scan-assets" className="font-display text-[20px] tracking-[-0.03em] text-fog">
            Services observed
          </h2>
          <p className="mono-sm text-ash">
            {report.services.length} open · {report.scope.port_range}
          </p>
        </div>

        {report.services.length ? (
          <div className="mt-4 overflow-x-auto">
            <table className="w-full min-w-[44rem] border-collapse text-left">
              <thead>
                <tr className="border-b border-hairline">
                  {["Host:port", "Service", "Product / version", "Identified by"].map(
                    (heading) => (
                      <th key={heading} scope="col" className="mono-sm px-3 py-3 text-ash">
                        {heading}
                      </th>
                    ),
                  )}
                </tr>
              </thead>
              <tbody>
                {report.services.map((service) => (
                  <tr
                    key={`${service.host}-${service.port}`}
                    className="border-b border-hairline-soft last:border-b-0"
                  >
                    <td className="px-3 py-3 font-mono text-[12px] text-lavender">
                      {service.host}:{service.port}
                    </td>
                    <td className="px-3 py-3 text-[13px] text-fog">
                      {service.service || "unknown"}
                    </td>
                    <td className="px-3 py-3 text-[13px] text-muted">
                      {[service.product, service.version].filter(Boolean).join(" ") ||
                        "not disclosed"}
                    </td>
                    <td className="px-3 py-3 font-mono text-[11px] text-ash">
                      {service.identified_by || service.source || "port"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <p className="body-copy mt-4 text-[13px]">
            No open port answered on the scanned set. The host may be down, firewalled,
            or serving only on a port that was not probed.
          </p>
        )}
      </section>

      <p className="mono-sm text-ash">
        Surface scan, not an authenticated audit. Engine {report.metadata.scanner.name}{" "}
        {report.metadata.scanner.version} · generated {formatWhen(report.metadata.generated_at)} ·
        findings describe reachable exposure, not proof of exploitability.
      </p>
    </div>
  );
}

export function ScanConsole() {
  const [state, setState] = useState<State>({ kind: "idle" });
  const [seconds, setSeconds] = useState(0);
  const [initialUrl, setInitialUrl] = useState("");
  const resultRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (state.kind !== "scanning") return;
    setSeconds(0);
    const started = Date.now();
    const timer = window.setInterval(() => {
      setSeconds(Math.floor((Date.now() - started) / 1000));
    }, 1000);
    return () => window.clearInterval(timer);
  }, [state.kind]);

  useEffect(() => {
    if (state.kind === "done") {
      resultRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  }, [state.kind]);

  const start = async (url: string) => {
    setState({ kind: "scanning" });

    const controller = new AbortController();
    const timeout = window.setTimeout(() => controller.abort(), 240_000);

    try {
      const response = await fetch("/api/scan", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ url }),
        signal: controller.signal,
      });

      const data = (await response.json().catch(() => null)) as
        | ({ status: "ok" } & ScanResult)
        | { status: "error"; message?: string }
        | null;

      if (response.ok && data && data.status === "ok") {
        setState({ kind: "done", result: data });
        return;
      }

      setState({
        kind: "error",
        message:
          data && "message" in data && data.message
            ? data.message
            : "The scan could not run. Try again.",
      });
    } catch (error) {
      setState({
        kind: "error",
        message:
          error instanceof DOMException && error.name === "AbortError"
            ? "The scan ran for more than four minutes and was stopped."
            : "The scan could not reach the server. Try again.",
      });
    } finally {
      window.clearTimeout(timeout);
    }
  };

  // A shared or bookmarked /scan?url=... link scans straight away; this is also
  // what a form submit before hydration falls back to.
  const queryHandled = useRef(false);
  useEffect(() => {
    if (queryHandled.current) return;
    queryHandled.current = true;

    const requested = new URLSearchParams(window.location.search)
      .get("url")
      ?.trim();
    if (!requested) return;

    setInitialUrl(requested);
    window.history.replaceState(null, "", window.location.pathname);
    void start(requested);
  }, []);

  return (
    <div>
      <ScanForm
        onSubmit={start}
        busy={state.kind === "scanning"}
        initialUrl={initialUrl}
      />

      {state.kind === "scanning" && <Scanning seconds={seconds} />}

      {state.kind === "error" && (
        <div
          role="alert"
          className="mt-6 flex gap-3 border border-[#ff6b8a]/30 bg-[#ff6b8a]/[0.05] p-5"
        >
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-[#ff9bb0]" aria-hidden="true" />
          <div>
            <p className="mono-sm text-fog">Scan failed</p>
            <p className="body-copy mt-2 text-[13px]">{state.message}</p>
          </div>
        </div>
      )}

      <div ref={resultRef} className="scroll-mt-24">
        {state.kind === "done" && (
          <ReportView result={state.result} onReset={() => setState({ kind: "idle" })} />
        )}
      </div>

      {state.kind === "idle" && (
        <div className="mt-8 grid gap-px border border-hairline bg-hairline-soft sm:grid-cols-3">
          {[
            {
              title: "Scoped to the URL",
              body: "The host is probed on its own web port plus 80, 443, 8080 and 8443. Nothing else on the network is touched.",
            },
            {
              title: "Evidence, then judgement",
              body: "A port only becomes a finding when the service answers with something that proves it — a banner, a certificate, a header.",
            },
            {
              title: "Same report, two surfaces",
              body: "The page and the PDF are rendered from one JSON report, so the download never says something the screen does not.",
            },
          ].map((item) => (
            <div key={item.title} className="bg-void p-5">
              <ShieldCheck className="h-4 w-4 text-lavender" aria-hidden="true" />
              <h3 className="mt-3 font-display text-[15px] tracking-[-0.02em] text-fog">
                {item.title}
              </h3>
              <p className="body-copy mt-2 text-[12.5px]">{item.body}</p>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
