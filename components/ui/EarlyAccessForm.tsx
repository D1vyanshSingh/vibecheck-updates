"use client";

import { useState } from "react";
import { ArrowRight, LoaderCircle, Mail } from "lucide-react";
import { cn } from "@/lib/cn";

type State =
  | { kind: "idle" }
  | { kind: "submitting" }
  | { kind: "success" }
  | { kind: "notice"; message: string }
  | { kind: "error"; message: string };

const roles = [
  "Vibe coder",
  "AI application builder",
  "Indie hacker",
  "Full-stack developer",
  "Founder",
  "Agency / studio",
  "SaaS engineering team",
  "Other",
];

export function EarlyAccessForm({
  variant = "full",
  className,
  idPrefix = "ea",
}: {
  variant?: "full" | "compact";
  className?: string;
  idPrefix?: string;
}) {
  const [state, setState] = useState<State>({ kind: "idle" });
  const [fields, setFields] = useState({ name: "", email: "", role: "", message: "", company: "" });
  const [errors, setErrors] = useState<Record<string, string>>({});

  const update = (key: keyof typeof fields) => (
    event: React.ChangeEvent<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>,
  ) => {
    setFields((current) => ({ ...current, [key]: event.target.value }));
    setErrors((current) => ({ ...current, [key]: "" }));
  };

  const onSubmit = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const nextErrors: Record<string, string> = {};
    if (fields.name.trim().length < 2) nextErrors.name = "Please add your name.";
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(fields.email.trim()))
      nextErrors.email = "Enter a valid email address.";
    setErrors(nextErrors);
    if (Object.keys(nextErrors).length > 0) return;

    setState({ kind: "submitting" });

    try {
      const response = await fetch("/api/early-access", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(fields),
      });
      const data: { status?: string; message?: string } = await response
        .json()
        .catch(() => ({}));

      if (response.ok && data.status === "ok") {
        setState({ kind: "success" });
        return;
      }

      if (data.status === "not_configured") {
        setState({
          kind: "notice",
          message:
            "This form is not wired to a list yet, so nothing was stored. Until it is, email hello@vibecheck.dev and you will be added manually.",
        });
        return;
      }

      setState({
        kind: "error",
        message:
          data.message ??
          "That did not go through. Please try again, or email hello@vibecheck.dev.",
      });
    } catch {
      setState({
        kind: "error",
        message: "Network error — nothing was submitted. Try again, or email hello@vibecheck.dev.",
      });
    }
  };

  if (state.kind === "success") {
    return (
      <div
        className={cn("panel p-6 sm:p-8", className)}
        role="status"
        aria-live="polite"
      >
        <p className="mono text-lavender">Request received</p>
        <p className="display-sub mt-4 text-fog">
          You are on the list. We will write when there is something real to try.
        </p>
        <p className="body-copy mt-3 text-[13.5px]">
          Early access is small and deliberate. Expect a direct reply from the
          team, not a drip campaign.
        </p>
      </div>
    );
  }

  const disabled = state.kind === "submitting";

  return (
    <form onSubmit={onSubmit} noValidate className={cn("panel p-6 sm:p-8", className)}>
      <div className="flex items-center justify-between gap-4">
        <p className="mono text-lavender">Get early access</p>
        <span className="mono-sm text-ash">Private beta · limited</span>
      </div>

      <div className={cn("mt-6 grid gap-4", variant === "full" && "sm:grid-cols-2")}>
        <div className={cn(variant === "full" ? "sm:col-span-1" : "col-span-1")}>
          <label htmlFor={`${idPrefix}-name`} className="mono-sm block text-ash">
            Name
          </label>
          <input
            id={`${idPrefix}-name`}
            name="name"
            autoComplete="name"
            value={fields.name}
            onChange={update("name")}
            aria-invalid={Boolean(errors.name)}
            aria-describedby={errors.name ? `${idPrefix}-name-error` : undefined}
            className={cn(
              "mt-2 h-11 w-full border border-hairline bg-[#0b0a11] px-3 font-sans text-[14px] text-fog outline-none transition-colors placeholder:text-[#4f4b5e] focus:border-lavender/60",
              errors.name && "border-[#ff6b8a]/60",
            )}
            placeholder="Your name"
          />
          {errors.name && (
            <p id={`${idPrefix}-name-error`} className="mt-1.5 text-[11px] text-[#ff9bb0]">
              {errors.name}
            </p>
          )}
        </div>

        <div>
          <label htmlFor={`${idPrefix}-email`} className="mono-sm block text-ash">
            Email
          </label>
          <input
            id={`${idPrefix}-email`}
            name="email"
            type="email"
            inputMode="email"
            autoComplete="email"
            value={fields.email}
            onChange={update("email")}
            aria-invalid={Boolean(errors.email)}
            aria-describedby={errors.email ? `${idPrefix}-email-error` : undefined}
            className={cn(
              "mt-2 h-11 w-full border border-hairline bg-[#0b0a11] px-3 font-sans text-[14px] text-fog outline-none transition-colors placeholder:text-[#4f4b5e] focus:border-lavender/60",
              errors.email && "border-[#ff6b8a]/60",
            )}
            placeholder="you@company.com"
          />
          {errors.email && (
            <p id={`${idPrefix}-email-error`} className="mt-1.5 text-[11px] text-[#ff9bb0]">
              {errors.email}
            </p>
          )}
        </div>

        <div className={variant === "full" ? "sm:col-span-2" : ""}>
          <label htmlFor={`${idPrefix}-role`} className="mono-sm block text-ash">
            How you build
          </label>
          <select
            id={`${idPrefix}-role`}
            name="role"
            value={fields.role}
            onChange={update("role")}
            className="mt-2 h-11 w-full appearance-none border border-hairline bg-[#0b0a11] px-3 font-sans text-[14px] text-fog outline-none transition-colors focus:border-lavender/60"
          >
            <option value="">Select one (optional)</option>
            {roles.map((role) => (
              <option key={role} value={role}>
                {role}
              </option>
            ))}
          </select>
        </div>

        {variant === "full" && (
          <div className="sm:col-span-2">
            <label htmlFor={`${idPrefix}-message`} className="mono-sm block text-ash">
              What are you building? (optional)
            </label>
            <textarea
              id={`${idPrefix}-message`}
              name="message"
              rows={3}
              value={fields.message}
              onChange={update("message")}
              className="mt-2 w-full resize-y border border-hairline bg-[#0b0a11] px-3 py-2.5 font-sans text-[14px] text-fog outline-none transition-colors placeholder:text-[#4f4b5e] focus:border-lavender/60"
              placeholder="A sentence is plenty."
            />
          </div>
        )}

        {/* Honeypot — hidden from people, available to bots. */}
        <div className="hidden" aria-hidden="true">
          <label htmlFor={`${idPrefix}-company`}>Company</label>
          <input
            id={`${idPrefix}-company`}
            name="company"
            tabIndex={-1}
            autoComplete="off"
            value={fields.company}
            onChange={update("company")}
          />
        </div>
      </div>

      <button type="submit" disabled={disabled} className="btn btn-primary mt-6 w-full disabled:opacity-60">
        {disabled ? (
          <>
            <LoaderCircle className="h-3.5 w-3.5 animate-spin" aria-hidden="true" />
            Sending
          </>
        ) : (
          <>
            Request early access
            <ArrowRight className="h-3.5 w-3.5" aria-hidden="true" />
          </>
        )}
      </button>

      <p className="mono-sm mt-4 text-ash">
        No marketing list. No third-party tracking. Replies come from a person.
      </p>

      {(state.kind === "notice" || state.kind === "error") && (
        <div
          role="alert"
          className={cn(
            "mt-5 border p-3.5",
            state.kind === "notice"
              ? "border-lavender/30 bg-lavender/[0.06]"
              : "border-[#ff6b8a]/30 bg-[#ff6b8a]/[0.05]",
          )}
        >
          <p className="mono-sm text-fog">
            {state.kind === "notice" ? "Not connected yet" : "Submission failed"}
          </p>
          <p className="body-copy mt-2 text-[12.5px]">{state.message}</p>
          <a
            href="mailto:hello@vibecheck.dev?subject=VibeCheck%20early%20access"
            className="mono mt-3 inline-flex items-center gap-2 text-lavender hover:text-fog"
          >
            <Mail className="h-3.5 w-3.5" aria-hidden="true" />
            hello@vibecheck.dev
          </a>
        </div>
      )}
    </form>
  );
}
