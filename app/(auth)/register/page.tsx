"use client";

import Link from "next/link";
import { useState } from "react";

import {
  Alert,
  AuthCard,
  Field,
  Notice,
  Submit,
  useAsyncAction,
} from "@/components/auth/AuthCard";
import { getSupabaseBrowserClient } from "@/lib/supabase/client";

export default function RegisterPage() {
  const { pending, error, done, run } = useAsyncAction();
  const [emailSent, setEmailSent] = useState(false);

  async function onSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const email = String(form.get("email") ?? "").trim();
    const password = String(form.get("password") ?? "");
    const confirm = String(form.get("confirm") ?? "");

    if (password !== confirm) {
      setEmailSent(false);
      return void run(async () => "Passwords do not match.");
    }
    if (password.length < 8) {
      return void run(async () => "Use at least 8 characters.");
    }

    await run(async () => {
      const supabase = getSupabaseBrowserClient();
      const { data, error: signUpError } = await supabase.auth.signUp({
        email,
        password,
        options: {
          emailRedirectTo: `${window.location.origin}/auth/callback?next=/app`,
        },
      });
      if (signUpError) return signUpError.message;
      if (!data.session) setEmailSent(true);
      return null;
    });
  }

  return (
    <AuthCard
      title="Create your account"
      description="One account can own a personal workspace and belong to any number of client workspaces."
      footer={
        <p className="mono-sm text-ash">
          Already registered?{" "}
          <Link href="/login" className="text-lavender hover:text-fog">
            Sign in
          </Link>
        </p>
      }
    >
      {emailSent ? (
        <Notice>
          Check your inbox for the confirmation link. Your workspace is created
          the first time you sign in.
        </Notice>
      ) : null}
      {done && !emailSent ? (
        <Notice>Account created. Redirecting to your workspace…</Notice>
      ) : null}
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
          autoComplete="new-password"
          minLength={8}
          required
          placeholder="At least 8 characters"
        />
        <Field
          label="Confirm password"
          name="confirm"
          type="password"
          autoComplete="new-password"
          minLength={8}
          required
          placeholder="Repeat password"
        />
        <Submit pending={pending}>Create account</Submit>
      </form>
    </AuthCard>
  );
}
