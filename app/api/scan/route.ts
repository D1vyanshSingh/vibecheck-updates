import { NextResponse } from "next/server";

import { ScanError, runUrlScan } from "@/lib/scan/runner";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export const maxDuration = 300;

const WINDOW_MS = 10 * 60 * 1000;
const MAX_PER_WINDOW = 6;
const MAX_CONCURRENT = 2;

const recent = new Map<string, number[]>();
let active = 0;

function rateLimited(key: string): boolean {
  const now = Date.now();
  const hits = (recent.get(key) ?? []).filter((at) => now - at < WINDOW_MS);
  if (hits.length >= MAX_PER_WINDOW) {
    recent.set(key, hits);
    return true;
  }
  hits.push(now);
  recent.set(key, hits);
  // Keep the map from growing without bound in a long-lived dev process.
  if (recent.size > 500) {
    for (const [entry, times] of recent) {
      if (times.every((at) => now - at >= WINDOW_MS)) recent.delete(entry);
    }
  }
  return false;
}

export async function POST(request: Request) {
  const forwarded = request.headers.get("x-forwarded-for") ?? "";
  const ip = forwarded.split(",")[0]?.trim() || "local";

  if (rateLimited(ip)) {
    return NextResponse.json(
      {
        status: "error",
        message:
          "Too many scans from this address. Wait a few minutes before scanning again.",
      },
      { status: 429 },
    );
  }

  if (active >= MAX_CONCURRENT) {
    return NextResponse.json(
      {
        status: "error",
        message: "Two scans are already running. Try again in a moment.",
      },
      { status: 429 },
    );
  }

  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json(
      { status: "error", message: "Send a JSON body with a url field." },
      { status: 400 },
    );
  }

  const url =
    typeof body === "object" && body !== null && "url" in body
      ? (body as { url?: unknown }).url
      : undefined;

  if (typeof url !== "string" || !url.trim()) {
    return NextResponse.json(
      { status: "error", message: "Enter a URL to scan." },
      { status: 400 },
    );
  }

  active += 1;
  try {
    const result = await runUrlScan(url);
    return NextResponse.json({ status: "ok", ...result });
  } catch (error) {
    if (error instanceof ScanError) {
      return NextResponse.json(
        { status: "error", message: error.message },
        { status: error.status },
      );
    }
    console.error("[scan] unexpected failure", error);
    return NextResponse.json(
      { status: "error", message: "The scan failed unexpectedly." },
      { status: 500 },
    );
  } finally {
    active -= 1;
  }
}
