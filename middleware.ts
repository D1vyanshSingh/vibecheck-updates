import type { NextRequest } from "next/server";

import { updateSession } from "@/lib/supabase/middleware";

export async function middleware(request: NextRequest) {
  return updateSession(request);
}

export const config = {
  matcher: [
    /*
     * Refresh sessions on application and auth routes only. Static assets and
     * the marketing pages skip the middleware entirely.
     */
    "/app/:path*",
    "/login",
    "/register",
    "/forgot-password",
    "/reset-password",
    "/invite/:path*",
    "/auth/:path*",
  ],
};
