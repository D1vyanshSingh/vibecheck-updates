"use client";

import { useActionState } from "react";

import { Alert } from "@/components/auth/AuthCard";
import { createProjectAction, type ActionResult } from "@/lib/actions";

const TYPES = [
  { value: "web_app", label: "Web application" },
  { value: "api", label: "API / service" },
  { value: "full_stack", label: "Full stack" },
  { value: "static_site", label: "Static site" },
  { value: "mobile_backend", label: "Mobile backend" },
];

export function NewProjectForm() {
  const [state, formAction, pending] = useActionState<ActionResult | null, FormData>(
    createProjectAction,
    null,
  );

  return (
    <form action={formAction} className="space-y-5">
      {state && !state.ok && state.message ? <Alert>{state.message}</Alert> : null}

      <div>
        <label htmlFor="name" className="mono-sm mb-2 block text-ash">
          Project name
        </label>
        <input
          id="name"
          name="name"
          required
          minLength={2}
          maxLength={120}
          placeholder="Customer portal"
          className="h-11 w-full border border-hairline bg-void px-3 text-[14px] text-fog outline-none placeholder:text-ash focus:border-lavender/60"
        />
      </div>

      <div>
        <label htmlFor="description" className="mono-sm mb-2 block text-ash">
          Description (optional)
        </label>
        <textarea
          id="description"
          name="description"
          rows={3}
          maxLength={2000}
          placeholder="What the application does and what matters about it."
          className="w-full border border-hairline bg-void px-3 py-2 text-[13.5px] leading-relaxed text-fog outline-none placeholder:text-ash focus:border-lavender/60"
        />
      </div>

      <div>
        <label htmlFor="project_type" className="mono-sm mb-2 block text-ash">
          Type
        </label>
        <select
          id="project_type"
          name="project_type"
          defaultValue="web_app"
          className="h-11 w-full border border-hairline bg-void px-3 font-mono text-[12.5px] text-fog"
        >
          {TYPES.map((t) => (
            <option key={t.value} value={t.value}>
              {t.label}
            </option>
          ))}
        </select>
      </div>

      <div className="grid gap-4 sm:grid-cols-2">
        <div>
          <label htmlFor="website_url" className="mono-sm mb-2 block text-ash">
            Website URL (optional)
          </label>
          <input
            id="website_url"
            name="website_url"
            type="url"
            placeholder="https://app.example.com"
            className="h-11 w-full border border-hairline bg-void px-3 font-mono text-[12px] text-fog outline-none placeholder:text-ash focus:border-lavender/60"
          />
        </div>
        <div>
          <label htmlFor="repository_url" className="mono-sm mb-2 block text-ash">
            Repository URL (optional)
          </label>
          <input
            id="repository_url"
            name="repository_url"
            type="url"
            placeholder="https://github.com/org/repo"
            className="h-11 w-full border border-hairline bg-void px-3 font-mono text-[12px] text-fog outline-none placeholder:text-ash focus:border-lavender/60"
          />
        </div>
      </div>

      <div className="flex items-center gap-3 border-t border-hairline pt-5">
        <button
          type="submit"
          disabled={pending}
          className="btn btn-primary disabled:opacity-60"
        >
          {pending ? "Creating…" : "Create project"}
        </button>
        <span className="font-mono text-[10.5px] text-ash">
          Sources and assessments are added after creation.
        </span>
      </div>
    </form>
  );
}
