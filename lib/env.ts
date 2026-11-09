/**
 * Public environment access.
 *
 * Only values the browser legitimately needs are read here. The service-role
 * key has no accessor in this module and must never gain one.
 */

function required(name: string, value: string | undefined): string {
  if (!value || !value.trim()) {
    throw new Error(
      `Missing ${name}. Copy .env.example to .env.local and fill it in.`,
    );
  }
  return value.trim();
}

export const SUPABASE_URL =
  process.env.NEXT_PUBLIC_SUPABASE_URL ?? process.env.SUPABASE_URL ?? "";

export const SUPABASE_ANON_KEY =
  process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY ??
  process.env.SUPABASE_ANON_KEY ??
  "";

export const BACKEND_URL = (
  process.env.NEXT_PUBLIC_BACKEND_URL ??
  process.env.BACKEND_PUBLIC_URL ??
  ""
).trim();

export const SITE_URL = (
  process.env.NEXT_PUBLIC_SITE_URL ?? "http://localhost:3000"
).trim();

export function supabaseConfigured(): boolean {
  return Boolean(SUPABASE_URL && SUPABASE_ANON_KEY);
}

export function assertSupabaseConfigured(): { url: string; key: string } {
  return {
    url: required("NEXT_PUBLIC_SUPABASE_URL", SUPABASE_URL),
    key: required("NEXT_PUBLIC_SUPABASE_ANON_KEY", SUPABASE_ANON_KEY),
  };
}
