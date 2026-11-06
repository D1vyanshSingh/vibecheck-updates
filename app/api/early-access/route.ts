import { NextResponse } from "next/server";
import { EARLY_ACCESS_TABLE, getSupabaseServerClient } from "@/lib/supabase";

/**
 * POST /api/early-access
 *
 * Validates, normalises and inserts one early-access request into Supabase.
 * Success is reported only when Supabase returns no error. Missing
 * configuration and database failures are distinct, explicit states.
 */

const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
const NAME_MIN = 2;
const NAME_MAX = 100;
const EMAIL_MAX = 254;
const BUILD_TYPE_MAX = 80;
const DESCRIPTION_MAX = 2000;

type Payload = {
  name?: unknown;
  email?: unknown;
  role?: unknown;
  buildType?: unknown;
  message?: unknown;
  projectDescription?: unknown;
  company?: unknown; // honeypot
};

const attempts = new Map<string, { count: number; reset: number }>();

function rateLimited(key: string) {
  const now = Date.now();
  const entry = attempts.get(key);
  if (!entry || now > entry.reset) {
    attempts.set(key, { count: 1, reset: now + 60_000 });
    return false;
  }
  entry.count += 1;
  return entry.count > 5;
}

const asString = (value: unknown) =>
  typeof value === "string" ? value : "";

export async function POST(request: Request) {
  let payload: Payload;

  try {
    payload = (await request.json()) as Payload;
  } catch {
    return NextResponse.json(
      { status: "invalid", message: "Request body must be JSON." },
      { status: 400 },
    );
  }

  // Honeypot: real people never fill this. Accept silently, store nothing.
  if (asString(payload.company).trim() !== "") {
    return NextResponse.json({ status: "ok" }, { status: 202 });
  }

  const name = asString(payload.name).trim();
  const email = asString(payload.email).trim().toLowerCase();
  const buildType = asString(payload.buildType ?? payload.role).trim();
  const description = asString(
    payload.projectDescription ?? payload.message,
  ).trim();

  const errors: Record<string, string> = {};

  if (name.length < NAME_MIN) {
    errors.name = "Please add your name (at least 2 characters).";
  } else if (name.length > NAME_MAX) {
    errors.name = `Name must be ${NAME_MAX} characters or fewer.`;
  }

  if (!EMAIL.test(email) || email.length > EMAIL_MAX) {
    errors.email = "Enter a valid email address.";
  }

  if (buildType.length > BUILD_TYPE_MAX) {
    errors.buildType = `Keep this under ${BUILD_TYPE_MAX} characters.`;
  }

  if (description.length > DESCRIPTION_MAX) {
    errors.projectDescription = `Project description must be ${DESCRIPTION_MAX} characters or fewer.`;
  }

  if (Object.keys(errors).length > 0) {
    return NextResponse.json({ status: "invalid", errors }, { status: 422 });
  }

  const ip =
    request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ?? "local";
  if (rateLimited(ip)) {
    return NextResponse.json(
      { status: "rate_limited", message: "Too many attempts. Try again in a minute." },
      { status: 429 },
    );
  }

  const supabase = getSupabaseServerClient();

  if (!supabase) {
    // No credentials in this environment: say so instead of pretending.
    return NextResponse.json(
      {
        status: "not_configured",
        message:
          "The early-access database is not configured for this environment. Nothing was stored.",
      },
      { status: 503 },
    );
  }

  // Column names match public.early_access_requests (see supabase/*.sql).
  const { error } = await supabase.from(EARLY_ACCESS_TABLE).insert({
    name,
    email,
    build_type: buildType || null,
    project_description: description || null,
    source: "vibecheck-website",
  });

  if (error) {
    // Server-side diagnostics only: never echo database detail to the client.
    console.error("[early-access] insert failed", {
      code: error.code,
      message: error.message,
    });
    return NextResponse.json(
      {
        status: "db_error",
        message: "We couldn't submit your request. Please try again.",
      },
      { status: 502 },
    );
  }

  return NextResponse.json({ status: "ok" }, { status: 200 });
}
