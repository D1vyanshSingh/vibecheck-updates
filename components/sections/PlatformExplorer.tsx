"use client";

import {
  BadgeCheck,
  Code2,
  Database,
  KeyRound,
  PackageSearch,
  Settings2,
  Sparkles,
  Wrench,
} from "lucide-react";
import { MagnificationDock, type DockItem } from "@/components/ui/MagnificationDock";

const items: DockItem[] = [
  { icon: <Code2 />, label: "Code security", href: "#code-security" },
  { icon: <KeyRound />, label: "Secret exposure", href: "#secrets" },
  { icon: <PackageSearch />, label: "Dependency risk", href: "#dependencies" },
  { icon: <Database />, label: "Data & access", href: "#data-access" },
  { icon: <Settings2 />, label: "Configuration", href: "#configuration" },
  { icon: <Sparkles />, label: "Explanations", href: "#explanations" },
  { icon: <Wrench />, label: "Remediation", href: "#remediation" },
  { icon: <BadgeCheck />, label: "Verification", href: "#verification" },
];

export function PlatformExplorer() {
  return (
    <div className="border-y border-hairline bg-void/60 py-5">
      <div className="shell">
        <div className="mb-4 flex items-center justify-between gap-4">
          <p className="mono-sm text-ash">Module explorer</p>
          <p className="mono-sm hidden text-ash sm:block">Hover to magnify · click to jump</p>
        </div>
        <MagnificationDock items={items} label="Platform modules" />
      </div>
    </div>
  );
}
