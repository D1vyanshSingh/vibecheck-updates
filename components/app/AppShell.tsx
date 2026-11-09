"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useState } from "react";
import {
  Activity,
  BarChart3,
  Boxes,
  BrainCircuit,
  FileText,
  Flag,
  GitBranch,
  LayoutDashboard,
  Menu,
  Network,
  Plug,
  ScanLine,
  Settings,
  ShieldCheck,
  Users,
  Wrench,
  X,
} from "lucide-react";

import { switchWorkspaceAction, signOutAction } from "@/lib/actions";
import type { Role, WorkspaceMembership } from "@/lib/data/context";
import { cn } from "@/lib/cn";

const NAV = [
  { href: "/app", label: "Overview", icon: LayoutDashboard },
  { href: "/app/projects", label: "Projects", icon: Boxes },
  { href: "/app/scans", label: "Assessments", icon: ScanLine },
  { href: "/app/findings", label: "Findings", icon: Flag },
  { href: "/app/verification", label: "Verification", icon: ShieldCheck },
  { href: "/app/remediation", label: "Remediation", icon: Wrench },
  { href: "/app/ai-intelligence", label: "AI intelligence", icon: BrainCircuit },
  { href: "/app/omniroute", label: "OmniRoute", icon: Activity },
  { href: "/app/application-map", label: "Application map", icon: Network },
  { href: "/app/benchmarks", label: "Benchmarks", icon: BarChart3 },
  { href: "/app/reports", label: "Reports", icon: FileText },
  { href: "/app/integrations", label: "Integrations", icon: Plug },
  { href: "/app/settings", label: "Settings", icon: Settings },
] as const;

export function AppShell({
  workspaces,
  activeWorkspaceId,
  role,
  email,
  children,
}: {
  workspaces: Array<{ id: string; name: string; kind: string }>;
  activeWorkspaceId: string | null;
  role: Role | null;
  email: string;
  children: React.ReactNode;
}) {
  const pathname = usePathname();
  const [open, setOpen] = useState(false);

  const isActive = (href: string) =>
    href === "/app" ? pathname === "/app" : pathname.startsWith(href);

  return (
    <div className="flex min-h-screen bg-void">
      {/* Sidebar */}
      <aside
        className={cn(
          "fixed inset-y-0 left-0 z-50 flex w-[248px] flex-col border-r border-hairline bg-abyss transition-transform duration-200 md:translate-x-0",
          open ? "translate-x-0" : "-translate-x-full",
        )}
      >
        <div className="flex h-[64px] items-center justify-between border-b border-hairline px-4">
          <Link href="/app" className="flex items-center gap-2">
            <span className="font-display text-[17px] font-semibold tracking-[-0.03em] text-fog">
              VIBECHECK
            </span>
          </Link>
          <button
            type="button"
            onClick={() => setOpen(false)}
            className="text-ash md:hidden"
            aria-label="Close navigation"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="border-b border-hairline p-3">
          {workspaces.length > 0 ? (
            <form action={switchWorkspaceAction} className="flex gap-1">
              <label className="sr-only" htmlFor="workspace_id">
                Active workspace
              </label>
              <select
                id="workspace_id"
                name="workspace_id"
                defaultValue={activeWorkspaceId ?? undefined}
                className="h-9 min-w-0 flex-1 border border-hairline bg-void px-2 font-mono text-[11.5px] text-fog"
              >
                {workspaces.map((w) => (
                  <option key={w.id} value={w.id}>
                    {w.name}
                    {w.kind === "agency" ? " · agency" : ""}
                  </option>
                ))}
              </select>
              <button
                type="submit"
                className="h-9 border border-hairline px-2 font-mono text-[9px] uppercase tracking-[0.14em] text-lavender hover:border-lavender/50"
              >
                Use
              </button>
            </form>
          ) : (
            <p className="mono-sm px-1 py-1.5 text-ash">No workspace yet</p>
          )}
          <p className="mono-sm mt-2 px-1 text-ash">
            {role ? `Role · ${role}` : "Not a member"}
          </p>
        </div>

        <nav className="flex-1 overflow-y-auto p-2" aria-label="Console">
          <ul className="space-y-0.5">
            {NAV.map((item) => {
              const Icon = item.icon;
              const active = isActive(item.href);
              return (
                <li key={item.href}>
                  <Link
                    href={item.href}
                    onClick={() => setOpen(false)}
                    aria-current={active ? "page" : undefined}
                    className={cn(
                      "flex items-center gap-2.5 px-2.5 py-2 text-[12.5px] transition-colors",
                      active
                        ? "bg-violet/12 text-fog"
                        : "text-muted hover:bg-white/[0.03] hover:text-fog",
                    )}
                  >
                    <Icon
                      className={cn(
                        "h-3.5 w-3.5",
                        active ? "text-lavender" : "text-ash",
                      )}
                      aria-hidden="true"
                    />
                    {item.label}
                  </Link>
                </li>
              );
            })}
          </ul>
        </nav>

        <div className="border-t border-hairline p-3">
          <p className="mono-sm truncate text-ash" title={email}>
            {email}
          </p>
          <div className="mt-2 flex items-center justify-between">
            <Link
              href="/app/settings"
              className="mono-sm text-muted hover:text-fog"
            >
              Account
            </Link>
            <form action={signOutAction}>
              <button
                type="submit"
                className="mono-sm text-ash transition-colors hover:text-fog"
              >
                Sign out
              </button>
            </form>
          </div>
        </div>
      </aside>

      {open ? (
        <button
          type="button"
          aria-label="Close navigation overlay"
          onClick={() => setOpen(false)}
          className="fixed inset-0 z-40 bg-black/60 md:hidden"
        />
      ) : null}

      {/* Content */}
      <div className="flex min-w-0 flex-1 flex-col md:pl-[248px]">
        <header className="sticky top-0 z-30 flex h-[64px] items-center justify-between border-b border-hairline bg-void/90 px-4 backdrop-blur md:px-8">
          <div className="flex items-center gap-3">
            <button
              type="button"
              onClick={() => setOpen(true)}
              className="text-fog md:hidden"
              aria-label="Open navigation"
            >
              <Menu className="h-5 w-5" />
            </button>
            <span className="mono text-ash">Security console</span>
          </div>
          <div className="flex items-center gap-4">
            <Link href="/" className="mono-sm text-ash hover:text-fog">
              Marketing site
            </Link>
            <Link
              href="/app/projects/new"
              className="hidden h-8 items-center border border-violet/40 bg-violet/15 px-3 font-mono text-[10px] uppercase tracking-[0.14em] text-lavender hover:bg-violet/25 sm:flex"
            >
              New project
            </Link>
          </div>
        </header>
        <main className="flex-1 px-4 py-7 md:px-8 md:py-9">{children}</main>
      </div>
    </div>
  );
}
