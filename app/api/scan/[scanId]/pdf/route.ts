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
    const file = await readFile(path.join(SCAN_ROOT, scanId, "report.pdf"));
    return new Response(new Uint8Array(file), {
      headers: {
        "content-type": "application/pdf",
        "content-disposition": `attachment; filename="vibecheck-report-${scanId.slice(0, 8)}.pdf"`,
        "cache-control": "no-store",
      },
    });
  } catch {
    return new Response("Report not found", { status: 404 });
  }
}
