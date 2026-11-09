"use client";

import { useState, type ReactNode } from "react";

type Props = {
  title: string;
  description: ReactNode;
  children: ReactNode;
  footer?: ReactNode;
};

export function AuthCard({ title, description, children, footer }: Props) {
  return (
    <section className="panel p-7 sm:p-8">
      <div className="mb-6">
        <p className="eyebrow-plain mb-3">VibeCheck account</p>
        <h1 className="display-sub text-fog">{title}</h1>
        <p className="body-copy mt-2 text-[13.5px]">{description}</p>
      </div>
      {children}
      {footer ? (
        <div className="mt-6 border-t border-hairline pt-5">{footer}</div>
      ) : null}
    </section>
  );
}

export function Field({
  label,
  ...props
}: { label: string } & React.InputHTMLAttributes<HTMLInputElement>) {
  return (
    <label className="block">
      <span className="mono-sm mb-2 block text-ash">{label}</span>
      <input
        {...props}
        className="h-11 w-full border border-hairline bg-void px-3 font-mono text-[13px] text-fog outline-none transition-colors placeholder:text-ash focus:border-lavender/60 disabled:opacity-60"
      />
    </label>
  );
}

export function Submit({
  children,
  pending,
}: {
  children: ReactNode;
  pending: boolean;
}) {
  return (
    <button
      type="submit"
      disabled={pending}
      className="btn btn-primary w-full disabled:cursor-not-allowed disabled:opacity-60"
    >
      {pending ? "Working…" : children}
    </button>
  );
}

export function Alert({ children }: { children: ReactNode }) {
  return (
    <p
      role="alert"
      className="mb-4 border border-red-500/30 bg-red-500/10 px-3 py-2 font-mono text-[11.5px] leading-relaxed text-red-200"
    >
      {children}
    </p>
  );
}

export function Notice({ children }: { children: ReactNode }) {
  return (
    <p className="mb-4 border border-lavender/25 bg-violet/10 px-3 py-2 font-mono text-[11.5px] leading-relaxed text-lavender">
      {children}
    </p>
  );
}

export function useAsyncAction() {
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState(false);

  async function run(fn: () => Promise<string | null>) {
    setPending(true);
    setError(null);
    try {
      const message = await fn();
      if (message) setError(message);
      else setDone(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Something went wrong.");
    } finally {
      setPending(false);
    }
  }

  return { pending, error, done, run };
}
