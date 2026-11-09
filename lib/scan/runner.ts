import "server-only";

import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { lookup } from "node:dns/promises";
import { existsSync } from "node:fs";
import { access, mkdir, readFile } from "node:fs/promises";
import { isIP } from "node:net";
import os from "node:os";
import path from "node:path";

import type { ScanReport, ScanResult } from "@/lib/scan/types";

/**
 * URL scans are run by the local Python scanner.
 *
 * The report engine is the same one that writes the branded HTML/PDF, so the
 * page and the PDF cannot drift: the JSON returned here is what the PDF was
 * rendered from.
 */

const SCANNER_DIR_NAME = "scanner-service";

/** Configured path first, then the copy inside this app, then a sibling. */
const SCANNER_DIR = (() => {
  const configured = process.env.VULNSCAN_DIR;
  if (configured) {
    return path.isAbsolute(configured)
      ? configured
      : path.resolve(process.cwd(), configured);
  }

  return [
    path.resolve(process.cwd(), SCANNER_DIR_NAME),
    path.resolve(process.cwd(), "..", SCANNER_DIR_NAME),
  ].find((candidate) => existsSync(path.join(candidate, "vulnscan", "__main__.py")))
    ?? path.resolve(process.cwd(), SCANNER_DIR_NAME);
})();

const PYTHON = process.env.SCANNER_PYTHON ?? "python3";
/**
 * A deployed scan host has no Python process, so it points this at the scanner
 * service instead (see scanner-service/). Unset means scan locally.
 */
const REMOTE_SCANNER = process.env.SCANNER_URL?.trim().replace(/\/$/, "") ?? "";
const SCAN_SECRET = process.env.SCAN_SECRET ?? "";
/**
 * By default any host that resolves is scannable, including loopback and
 * private (LAN) addresses: scans run from the operator's own machine and
 * people's hostnames often resolve internally.
 *
 * Set to 1 on a shared/public deployment to refuse loopback and private
 * ranges. Metadata and link-local addresses stay blocked either way.
 */
const BLOCK_PRIVATE = process.env.SCAN_BLOCK_PRIVATE_TARGETS === "1";
const SCAN_TIMEOUT_MS = 180_000;

export const SCAN_ROOT = path.join(os.tmpdir(), "vibecheck-scans");

/** A failure with an HTTP status the route can pass through. */
export class ScanError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
    this.name = "ScanError";
  }
}

type Target = { url: string; host: string; port: number };

const METADATA_HOSTNAMES = ["metadata.google.internal", "instance-data"];

function isPrivateIPv4(address: string): boolean {
  const parts = address.split(".").map(Number);
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part))) {
    return false;
  }
  const [a, b] = parts;
  if (a === 10 || a === 127 || a === 0) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 100 && b >= 64 && b <= 127) return true;
  return a >= 224;
}

function isPrivateIPv6(address: string): boolean {
  const lower = address.toLowerCase();
  return (
    lower === "::1" ||
    lower === "::" ||
    lower.startsWith("fc") ||
    lower.startsWith("fd") ||
    lower.startsWith("fe80") ||
    lower.startsWith("::ffff:127.") ||
    lower.startsWith("::ffff:10.") ||
    lower.startsWith("::ffff:192.168.")
  );
}

function isPrivateAddress(address: string): boolean {
  return isIP(address) === 6
    ? isPrivateIPv6(address)
    : isPrivateIPv4(address);
}

/**
 * Addresses that are never a scan target: link-local (where cloud metadata
 * services live), unspecified, multicast and reserved space.
 */
function isAlwaysBlocked(address: string): boolean {
  const lower = address.toLowerCase();

  if (isIP(lower) === 6) {
    return (
      lower === "::" ||
      lower.startsWith("fe80") ||
      lower.startsWith("ff") ||
      lower.startsWith("::ffff:169.254.")
    );
  }

  const parts = lower.split(".").map(Number);
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part))) {
    return false;
  }

  const [a, b] = parts;
  if (a === 0) return true;
  if (a === 169 && b === 254) return true;
  return a >= 224;
}

const PRIVATE_TARGETS_MESSAGE =
  "Private and local targets are blocked here. Only public hosts can be scanned.";

async function assertScannableHost(host: string): Promise<void> {
  const lower = host.toLowerCase();

  if (METADATA_HOSTNAMES.includes(lower)) {
    throw new ScanError(403, "Cloud metadata endpoints cannot be scanned.");
  }

  let addresses: string[];
  if (isIP(lower)) {
    addresses = [lower];
  } else {
    try {
      addresses = (await lookup(lower, { all: true })).map(
        (record) => record.address,
      );
    } catch {
      throw new ScanError(400, "That hostname could not be resolved.");
    }
  }

  if (addresses.some(isAlwaysBlocked)) {
    throw new ScanError(
      403,
      "That address is link-local or reserved, so it cannot be scanned.",
    );
  }

  if (BLOCK_PRIVATE && addresses.some(isPrivateAddress)) {
    throw new ScanError(403, PRIVATE_TARGETS_MESSAGE);
  }
}

/** Accepts a bare hostname or a URL; returns the host and web port to scan. */
export async function resolveTarget(raw: string): Promise<Target> {
  const trimmed = raw.trim();
  if (!trimmed) throw new ScanError(400, "Enter a URL to scan.");
  if (trimmed.length > 500) {
    throw new ScanError(400, "That URL is too long.");
  }

  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed)
    ? trimmed
    : `https://${trimmed}`;

  let url: URL;
  try {
    url = new URL(withScheme);
  } catch {
    throw new ScanError(400, "That doesn't look like a valid URL.");
  }

  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new ScanError(400, "Only http:// and https:// targets can be scanned.");
  }
  if (url.username || url.password) {
    throw new ScanError(400, "Remove the credentials from the URL before scanning.");
  }

  const host = url.hostname.replace(/^\[|\]$/g, "").toLowerCase();
  if (!host) throw new ScanError(400, "That URL has no host to scan.");

  const port = Number(url.port) || (url.protocol === "https:" ? 443 : 80);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new ScanError(400, "That port is not valid.");
  }

  await assertScannableHost(host);

  return { url: url.toString(), host, port };
}

function runScanner(args: string[]): Promise<void> {
  return new Promise((resolve, reject) => {
    const child = spawn(PYTHON, args, {
      cwd: SCANNER_DIR,
      env: { ...process.env, PYTHONUNBUFFERED: "1" },
      stdio: ["ignore", "pipe", "pipe"],
    });

    let stderr = "";
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      reject(
        new ScanError(
          504,
          "The scan took too long and was stopped. Try a host with fewer open ports.",
        ),
      );
    }, SCAN_TIMEOUT_MS);

    child.stderr?.on("data", (chunk: Buffer) => {
      stderr = (stderr + chunk.toString()).slice(-4000);
    });

    child.on("error", () => {
      clearTimeout(timer);
      reject(
        new ScanError(
          503,
          "The scanner could not be started on this host. URL scanning needs the local Python scanner.",
        ),
      );
    });

    child.on("close", (code) => {
      clearTimeout(timer);
      // The tool exits 1 when it found something and 0 when the target is
      // clean; anything else is a real failure.
      if (code === 0 || code === 1) {
        resolve();
        return;
      }
      console.error("[scan] scanner exited", code, stderr);
      reject(new ScanError(502, "The scan failed before it produced a report."));
    });
  });
}

async function isReadable(file: string): Promise<boolean> {
  try {
    await access(file);
    return true;
  } catch {
    return false;
  }
}

/**
 * Scans through the scanner service. The service returns the branded HTML with
 * the report because function instances share no disk to store it on.
 */
async function runRemoteScan(
  target: Target,
  id: string,
): Promise<ScanResult> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), SCAN_TIMEOUT_MS + 30_000);

  try {
    const response = await fetch(`${REMOTE_SCANNER}/scan`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-scan-secret": SCAN_SECRET,
      },
      body: JSON.stringify({
        host: target.host,
        port: target.port,
        label: `URL scan — ${target.host}`,
      }),
      signal: controller.signal,
      cache: "no-store",
    });

    const data = (await response.json().catch(() => null)) as
      | { status: "ok"; report: ScanReport; html?: string }
      | { status: "error"; message?: string }
      | null;

    if (!response.ok || !data || data.status !== "ok") {
      const message =
        data && "message" in data && data.message
          ? data.message
          : "The scan service returned an error.";
      console.error("[scan] service error", response.status, message);
      throw new ScanError(502, message);
    }

    return {
      id,
      target,
      report: data.report,
      pdfUrl: null,
      htmlUrl: "",
      html: data.html,
    };
  } catch (error) {
    if (error instanceof ScanError) throw error;
    if (error instanceof DOMException && error.name === "AbortError") {
      throw new ScanError(504, "The scan service took too long and was stopped.");
    }
    console.error("[scan] service unreachable", error);
    throw new ScanError(503, "The scan service could not be reached.");
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Scans the host behind a URL and returns the report the PDF was built from.
 * Artifacts live in a per-scan temp directory named by the scan id.
 */
export async function runUrlScan(rawUrl: string): Promise<ScanResult> {
  const target = await resolveTarget(rawUrl);

  if (REMOTE_SCANNER) {
    return runRemoteScan(target, randomUUID());
  }

  if (!existsSync(path.join(SCANNER_DIR, "vulnscan", "__main__.py"))) {
    throw new ScanError(
      503,
      "The scanner is not installed in this environment, so the URL scan cannot run.",
    );
  }

  const id = randomUUID();
  const dir = path.join(SCAN_ROOT, id);
  await mkdir(dir, { recursive: true });

  const htmlPath = path.join(dir, "report.html");
  const jsonPath = path.join(dir, "report.json");
  const pdfPath = path.join(dir, "report.pdf");

  // Only web-facing ports: the URL is the scope, not the whole host.
  const ports = [...new Set([target.port, 80, 443, 8080, 8443])].join(",");

  await runScanner([
    "-m",
    "vulnscan",
    target.host,
    "-p",
    ports,
    "-r",
    `URL scan — ${target.host}`,
    "--engine",
    "native",
    "-o",
    dir,
    "--html",
    htmlPath,
    "--json",
    jsonPath,
    "--pdf",
    pdfPath,
    "--no-color",
    "-q",
  ]);

  let report: ScanReport;
  try {
    report = JSON.parse(await readFile(jsonPath, "utf8")) as ScanReport;
  } catch {
    throw new ScanError(502, "The scanner finished but its report could not be read.");
  }

  const hasPdf = await isReadable(pdfPath);

  return {
    id,
    target,
    report,
    pdfUrl: hasPdf ? `/api/scan/${id}/pdf` : null,
    htmlUrl: `/api/scan/${id}/html`,
  };
}
