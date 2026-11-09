"use client";

import { createBrowserClient } from "@supabase/ssr";
import type { SupabaseClient } from "@supabase/supabase-js";

import { SUPABASE_ANON_KEY, SUPABASE_URL } from "@/lib/env";

let client: SupabaseClient | null = null;

/**
 * Browser Supabase client.
 *
 * Sessions live in cookies so the server can read them, which is what lets
 * middleware refresh the token and server components render authenticated
 * pages without a client round trip.
 *
 * Created lazily: the marketing site must render even when auth is not
 * configured in the current environment.
 */
export function getSupabaseBrowserClient(): SupabaseClient {
  if (!client) {
    if (!SUPABASE_URL || !SUPABASE_ANON_KEY) {
      throw new Error(
        "Supabase is not configured. Set NEXT_PUBLIC_SUPABASE_URL and NEXT_PUBLIC_SUPABASE_ANON_KEY.",
      );
    }
    client = createBrowserClient(SUPABASE_URL, SUPABASE_ANON_KEY);
  }
  return client;
}
