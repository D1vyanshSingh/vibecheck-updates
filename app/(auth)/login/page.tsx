"use client";

import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useState } from "react";

import { Alert, AuthCard, Field, Submit, useAsyncAction } from "@/components/auth/AuthCard";
import { getSupabaseBrowserClient } from "@/lib/supabase/client";

function LoginForm() {
  const router = useRouter();
  const params = useSearchParams();
  const next = params.get("next") || "/app";
  const { pending, error, run } = useAsyncAction();

  async function onSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const email = String(form.get("email") ?? "");
    const password = String(form.get("password") ?? "");

    await run(async () => {
      const supabase = getSupabaseBrowserClient();
      const { error: signInError } = await supabase.auth.signInWithPassword({
        email,
        password,
      });
      if (signInError) {
        return signInError.message === "Invalid login credentials"
          ? "Email or password is incorrect."
          : signInError.message;
      }
      router.replace(next.startsWith("/") ? next : "/app");
      router.refresh();
      return null;
    });
  }

  return (
    <AuthCard
      title="Sign in"
      description="Use the account you registered with. Sessions are held in secure cookies and refreshed on every request."
      footer={
        <p className="mono-sm text-ash">
          No account?{" "}
          <Link href="/register" className="text-lavender hover:text-fog">
            Create one
          </Link>
        </p>
      }
    >
      <form onSubmit={onSubmit} className="space-y-4">
        {error ? <Alert>{error}</Alert> : null}
        <Field
          label="Email"
          name="email"
          type="email"
          autoComplete="email"
          required
          placeholder="you@company.com"
        />
        <Field
          label="Password"
          name="password"
          type="password"
          autoComplete="current-password"
          required
          placeholder="••••••••"
        />
        <Submit pending={pending}>Sign in</Submit>
      </form>
      <p className="mt-4 text-center">
        <Link
          href="/forgot-password"
          className="mono-sm text-ash transition-colors hover:text-fog"
        >
          Forgot your password?
        </Link>
      </p>
    </AuthCard>
  );
}

export default function LoginPage() {
  return (
    <Suspense fallback={<div className="panel h-72 animate-pulse" />}>
      <LoginForm />
    </Suspense>
  );
}
