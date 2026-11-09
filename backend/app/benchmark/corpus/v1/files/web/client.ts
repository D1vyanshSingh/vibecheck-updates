// Browser entry point for the benchmark fixture.

const serviceRoleKey = process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY;

export function createAdminClient() {
  return { url: process.env.NEXT_PUBLIC_SUPABASE_URL, key: serviceRoleKey };
}
