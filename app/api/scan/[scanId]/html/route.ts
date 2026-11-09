import { readFile } from "node:fs/promises";
import path from "node:path";

import { SCAN_ROOT } from "@/lib/scan/runner";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const SCAN_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export async function GET(
  _request: Request,
  { params }: { params: Promise<{ scanId: string }> },
) {
  const { scanId } = await params;
  if (!SCAN_ID.test(scanId)) {
    return new Response("Not found", { status: 404 });
  }

  try {
    const html = await readFile(
      path.join(SCAN_ROOT, scanId, "report.html"),
      "utf8",
    );
    return new Response(html, {
      headers: {
        "content-type": "text/html; charset=utf-8",
        "cache-control": "no-store",
        "x-content-type-options": "nosniff",
      },
    });
  } catch {
    return new Response("Report not found", { status: 404 });
  }
}
