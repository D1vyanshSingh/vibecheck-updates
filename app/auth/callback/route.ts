import { NextResponse, type NextRequest } from "next/server";

import { getSupabaseServerClient } from "@/lib/supabase/server";

/**
 * GET /auth/callback
 *
 * Exchanges a Supabase auth code (email confirmation, recovery, invite) for a
 * cookie-bound session, then redirects to the requested in-app path.
 */
export async function GET(request: NextRequest) {
  const url = request.nextUrl;
  const code = url.searchParams.get("code");
  const nextParam = url.searchParams.get("next") ?? "/app";

  // Only relative in-app paths are accepted: an absolute URL here would be an
  // open redirect.
  const next = nextParam.startsWith("/") ? nextParam : "/app";

  if (!code) {
    return NextResponse.redirect(new URL("/login?error=missing_code", url.origin));
  }

  const supabase = await getSupabaseServerClient();
  const { error } = await supabase.auth.exchangeCodeForSession(code);

  if (error) {
    const failure = new URL("/login", url.origin);
    failure.searchParams.set("error", "callback_failed");
    return NextResponse.redirect(failure);
  }

  return NextResponse.redirect(new URL(next, url.origin));
}
