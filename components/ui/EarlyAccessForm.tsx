"use client";

import { useRef, useState } from "react";
import { ArrowRight, LoaderCircle, Mail } from "lucide-react";
import { cn } from "@/lib/cn";

const NAME_MIN = 2;
const NAME_MAX = 100;
const DESCRIPTION_MAX = 2000;
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

type State =
  | { kind: "idle" }
  | { kind: "submitting" }
  | { kind: "success" }
  | { kind: "notice"; message: string }
  | { kind: "error" };

type Fields = {
  name: string;
  email: string;
  role: string;
  message: string;
  company: string;
};

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

function validate(fields: Fields) {
  const errors: Record<string, string> = {};
  const name = fields.name.trim();
  const email = fields.email.trim().toLowerCase();

  if (name.length < NAME_MIN) {
    errors.name = "Please add your name (at least 2 characters).";
  } else if (name.length > NAME_MAX) {
    errors.name = `Name must be ${NAME_MAX} characters or fewer.`;
  }

  if (!EMAIL.test(email)) {
    errors.email = "Enter a valid email address.";
  }

  if (fields.message.trim().length > DESCRIPTION_MAX) {
    errors.projectDescription = `Project description must be ${DESCRIPTION_MAX} characters or fewer.`;
  }

  return errors;
}

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
  const [fields, setFields] = useState<Fields>({
    name: "",
    email: "",
    role: "",
    message: "",
    company: "",
  });
  const [errors, setErrors] = useState<Record<string, string>>({});
  // A ref, not state: two submits in the same tick would both read a stale
  // `state.kind` and fire two requests.
  const inFlight = useRef(false);

  const update =
    (key: keyof Fields) =>
    (
      event: React.ChangeEvent<
        HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement
      >,
    ) => {
      const value = event.target.value;
      setFields((current) => ({ ...current, [key]: value }));
      setErrors((current) => {
        if (!current[key] && !(key === "message" && current.projectDescription)) {
          return current;
        }
        const next = { ...current };
        delete next[key];
        if (key === "message") delete next.projectDescription;
        return next;
      });
    };

  const busy = state.kind === "submitting";

  const onSubmit = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    // Guard against a second submit while the first is in flight.
    if (inFlight.current) return;

    const nextErrors = validate(fields);
    setErrors(nextErrors);
    if (Object.keys(nextErrors).length > 0) return;

    inFlight.current = true;
    setState({ kind: "submitting" });

    try {
      const response = await fetch("/api/early-access", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          name: fields.name.trim(),
          email: fields.email.trim().toLowerCase(),
          buildType: fields.role.trim(),
          projectDescription: fields.message.trim(),
          company: fields.company,
        }),
      });

      const data: {
        status?: string;
        message?: string;
        errors?: Record<string, string>;
      } = await response.json().catch(() => ({}));

      // Success is only claimed on an explicit ok from the server, which only
      // responds after Supabase accepted the insert.
      if (response.ok && data.status === "ok") {
        setState({ kind: "success" });
        return;
      }

      if (data.status === "invalid" && data.errors) {
        setErrors(data.errors);
        setState({ kind: "idle" });
        return;
      }

      if (data.status === "not_configured") {
        setState({
          kind: "notice",
          message:
            "The early-access database is not configured for this environment, so nothing was stored. Email hello@vibecheck.dev and you will be added manually.",
        });
        return;
      }

      setState({ kind: "error" });
    } catch {
      setState({ kind: "error" });
    } finally {
      inFlight.current = false;
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
          You&apos;re on the list. We&apos;ll be in touch.
        </p>
        <p className="body-copy mt-3 text-[13.5px]">
          Early access is small and deliberate. Expect a direct reply from the
          team, not a drip campaign.
        </p>
      </div>
    );
  }

  return (
    <form onSubmit={onSubmit} noValidate className={cn("panel p-6 sm:p-8", className)}>
      <div className="flex items-center justify-between gap-4">
        <p className="mono text-lavender">Get early access</p>
        <span className="mono-sm text-ash">Private beta · limited</span>
      </div>

      <div className={cn("mt-6 grid gap-4", variant === "full" && "sm:grid-cols-2")}>
        <div>
          <label htmlFor={`${idPrefix}-name`} className="mono-sm block text-ash">
            Name
          </label>
          <input
            id={`${idPrefix}-name`}
            name="name"
            autoComplete="name"
            maxLength={NAME_MAX}
            required
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
            required
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
            Build type <span className="normal-case tracking-normal">(optional)</span>
          </label>
          <select
            id={`${idPrefix}-role`}
            name="role"
            value={fields.role}
            onChange={update("role")}
            className="mt-2 h-11 w-full appearance-none border border-hairline bg-[#0b0a11] px-3 font-sans text-[14px] text-fog outline-none transition-colors focus:border-lavender/60"
          >
            <option value="">Select one</option>
            {roles.map((role) => (
              <option key={role} value={role}>
                {role}
              </option>
            ))}
          </select>
        </div>

        {variant === "full" && (
          <div className="sm:col-span-2">
            <div className="flex items-baseline justify-between gap-4">
              <label htmlFor={`${idPrefix}-message`} className="mono-sm block text-ash">
                Project description{" "}
                <span className="normal-case tracking-normal">(optional)</span>
              </label>
              <span className="mono-sm text-ash">
                {fields.message.length}/{DESCRIPTION_MAX}
              </span>
            </div>
            <textarea
              id={`${idPrefix}-message`}
              name="message"
              rows={3}
              maxLength={DESCRIPTION_MAX}
              value={fields.message}
              onChange={update("message")}
              aria-invalid={Boolean(errors.projectDescription)}
              aria-describedby={
                errors.projectDescription ? `${idPrefix}-message-error` : undefined
              }
              className={cn(
                "mt-2 w-full resize-y border border-hairline bg-[#0b0a11] px-3 py-2.5 font-sans text-[14px] text-fog outline-none transition-colors placeholder:text-[#4f4b5e] focus:border-lavender/60",
                errors.projectDescription && "border-[#ff6b8a]/60",
              )}
              placeholder="A sentence is plenty."
            />
            {errors.projectDescription && (
              <p id={`${idPrefix}-message-error`} className="mt-1.5 text-[11px] text-[#ff9bb0]">
                {errors.projectDescription}
              </p>
            )}
          </div>
        )}

        {/* Honeypot — hidden from people and assistive tech, tempting to bots. */}
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

      <button
        type="submit"
        disabled={busy}
        aria-busy={busy}
        className="btn btn-primary mt-6 w-full disabled:cursor-not-allowed disabled:opacity-60"
      >
        {busy ? (
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

      {state.kind === "notice" && (
        <div
          role="alert"
          className="mt-5 border border-lavender/30 bg-lavender/[0.06] p-3.5"
        >
          <p className="mono-sm text-fog">Not connected yet</p>
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

      {state.kind === "error" && (
        <div
          role="alert"
          className="mt-5 border border-[#ff6b8a]/30 bg-[#ff6b8a]/[0.05] p-3.5"
        >
          <p className="mono-sm text-fog">
            We couldn&apos;t submit your request. Please try again.
          </p>
          <p className="body-copy mt-2 text-[12.5px]">
            If it keeps failing, email{" "}
            <a
              href="mailto:hello@vibecheck.dev?subject=VibeCheck%20early%20access"
              className="text-lavender hover:text-fog"
            >
              hello@vibecheck.dev
            </a>{" "}
            and you will be added manually.
          </p>
        </div>
      )}
    </form>
  );
}
