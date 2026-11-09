import "server-only";

import { createServerClient } from "@supabase/ssr";
import { cookies } from "next/headers";
import type { SupabaseClient, User } from "@supabase/supabase-js";

import { SUPABASE_ANON_KEY, SUPABASE_URL } from "@/lib/env";

/**
 * Server Supabase client bound to the request's cookies.
 *
 * Uses the anon key plus the user's session, so every query is still subject
 * to row-level security. The service-role key is never used in this module.
 */
export async function getSupabaseServerClient(): Promise<SupabaseClient> {
  const cookieStore = await cookies();

  return createServerClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
    cookies: {
      getAll() {
        return cookieStore.getAll();
      },
      setAll(cookiesToSet) {
        try {
          for (const { name, value, options } of cookiesToSet) {
            cookieStore.set(name, value, options);
          }
        } catch {
          // Called from a server component: middleware refreshes the session
          // instead. Safe to ignore.
        }
      },
    },
  });
}

/** Returns the signed-in user, or null. */
export async function getUser(): Promise<User | null> {
  if (!SUPABASE_URL || !SUPABASE_ANON_KEY) return null;
  const supabase = await getSupabaseServerClient();
  const { data, error } = await supabase.auth.getUser();
  if (error) return null;
  return data.user ?? null;
}
