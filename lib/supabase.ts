import { createClient, type SupabaseClient } from "@supabase/supabase-js";

/**
 * Server-only Supabase access for the early-access form.
 *
 * This module must never be imported from a client component: it reads the
 * anon key from non-public environment variables, so the key is never bundled
 * into browser JavaScript. Row-level security on the table allows INSERT only,
 * which means even a leaked key cannot read, update or delete submissions.
 */

export const EARLY_ACCESS_TABLE = "early_access_requests";

let cached: SupabaseClient | null = null;

export function getSupabaseServerClient(): SupabaseClient | null {
  const url =
    process.env.SUPABASE_URL ?? process.env.NEXT_PUBLIC_SUPABASE_URL ?? "";
  const key =
    process.env.SUPABASE_ANON_KEY ??
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY ??
    "";

  if (!url.trim() || !key.trim()) return null;
  if (!/^https?:\/\/.+/.test(url.trim())) return null;

  if (!cached) {
    cached = createClient(url.trim(), key.trim(), {
      auth: { persistSession: false, autoRefreshToken: false },
      global: { headers: { "x-application-name": "vibecheck-web" } },
    });
  }

  return cached;
}
