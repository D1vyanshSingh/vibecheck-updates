/** Shapes produced by the vulnscan JSON report (schema 1.3). */

export type Severity = "critical" | "high" | "medium" | "low" | "informational";

export type ScanFinding = {
  id: string;
  rule_id: string;
  title: string;
  severity: Severity;
  confidence: string;
  status: string;
  cwe?: string[];
  cve?: string[];
  asset: {
    host?: string;
    ip?: string;
    port?: number;
    protocol?: string;
    service?: string;
    url?: string;
  };
  description: string;
  impact: string;
  evidence: string;
  remediation: string;
  references?: string[];
  cvss?: {
    score?: number;
    vector?: string;
    version?: string;
    band?: string;
    source?: string;
  };
  attack?: { id: string; name: string }[];
  detection?: string;
  next_step?: string;
  entry_point?: boolean;
};

export type ScanService = {
  host: string;
  ip?: string;
  port: number;
  protocol?: string;
  state?: string;
  service?: string;
  product?: string;
  version?: string;
  banner?: string;
  tls?: { ok?: boolean };
  source?: string;
  identified_by?: string;
  identification_confidence?: number;
};

export type ScanReport = {
  report_version: string;
  metadata: {
    title: string;
    report_name?: string;
    scanner: { name: string; version: string };
    engine: string;
    generated_at: string;
    started_at: string;
    duration_seconds: number;
  };
  scope: {
    targets: string[];
    ports_scanned: number;
    port_range: string;
  };
  coverage?: {
    engine?: string;
    command?: string;
    started_at?: string;
    duration_s?: number;
    ports_scanned?: number;
    port_range?: string;
    advisory?: { available?: boolean };
  };
  summary: {
    total_findings: number;
    counts_by_severity: Record<Severity, number>;
    open_services: number;
  };
  services: ScanService[];
  findings: ScanFinding[];
};

export type ScanResult = {
  id: string;
  target: { url: string; host: string; port: number };
  report: ScanReport;
  /** Present when the scan host rendered a PDF artifact. */
  pdfUrl: string | null;
  /** Empty when the report only exists inline (a remote scan host). */
  htmlUrl: string;
  /** Branded standalone report, returned inline by the scan service. */
  html?: string;
};
