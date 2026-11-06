"use client";

import { useEffect, useRef, useState, type ReactNode } from "react";
import { cn } from "@/lib/cn";

type Mode = "loading" | "live" | "static";

/**
 * TubesBackground — lazy, disposable WebGL layer for the hero.
 *
 * - canvas is pointer-events-none and listens on window, so no CTA is blocked;
 * - clicking never randomises the palette (deliberately removed);
 * - prefers-reduced-motion, missing WebGL and unmount all fall back cleanly;
 * - only one scene instance may exist per mount (guarded by the ref).
 */
export function TubesBackground({
  children,
  className,
}: {
  children?: ReactNode;
  className?: string;
}) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [mode, setMode] = useState<Mode>("loading");

  useEffect(() => {
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
      setMode("static");
      return;
    }

    let disposed = false;
    let handle: { dispose: () => void } | null = null;
    let timer: number | undefined;

    const start = async () => {
      const canvas = canvasRef.current;
      if (!canvas || disposed) return;

      try {
        const { createTubesScene } = await import("./tubes-engine");
        if (disposed) return;

        const narrow = window.innerWidth < 768;
        handle = createTubesScene(canvas, {
          density: narrow ? 2 : 3,
          quality: narrow ? "low" : "high",
        });

        if (!handle) {
          setMode("static");
          return;
        }
        setMode("live");
      } catch {
        if (!disposed) setMode("static");
      }
    };

    // Defer until the main thread is quiet so text paints first.
    const schedule = () => {
      timer = window.setTimeout(start, 220);
    };

    if (document.readyState === "complete") schedule();
    else window.addEventListener("load", schedule, { once: true });

    return () => {
      disposed = true;
      if (timer) window.clearTimeout(timer);
      window.removeEventListener("load", schedule);
      handle?.dispose();
      handle = null;
    };
  }, []);

  return (
    <div className={cn("absolute inset-0 overflow-hidden bg-void", className)}>
      {/* Static fallback: same composition, no WebGL. */}
      <div
        aria-hidden="true"
        className={cn(
          "absolute inset-0 transition-opacity duration-700",
          mode === "live" ? "opacity-0" : "opacity-100",
        )}
      >
        <div className="absolute inset-0 bg-[radial-gradient(60%_50%_at_70%_45%,rgba(112,43,255,0.28),transparent_70%)]" />
        <div className="absolute inset-0 bg-[radial-gradient(38%_34%_at_24%_70%,rgba(151,79,255,0.16),transparent_72%)]" />
        <div className="grid-field absolute inset-0 opacity-60" />
      </div>

      <canvas
        ref={canvasRef}
        aria-hidden="true"
        role="presentation"
        className={cn(
          "pointer-events-none absolute inset-0 block h-full w-full transition-opacity duration-700",
          mode === "live" ? "opacity-100" : "opacity-0",
        )}
      />

      {/* Readability scrims — keep type legible over the 3D. */}
      <div
        aria-hidden="true"
        className="pointer-events-none absolute inset-0 bg-[linear-gradient(180deg,rgba(8,8,13,0.92)_0%,rgba(8,8,13,0.35)_28%,rgba(8,8,13,0.12)_55%,rgba(8,8,13,0.86)_100%)]"
      />
      <div
        aria-hidden="true"
        className="pointer-events-none absolute inset-0 bg-[linear-gradient(90deg,rgba(8,8,13,0.94)_0%,rgba(8,8,13,0.72)_38%,rgba(8,8,13,0.04)_68%)]"
      />

      {children}
    </div>
  );
}
