"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useRef, useState } from "react";
import { ArrowUpRight, Menu, X } from "lucide-react";
import { VibeCheckLogo } from "@/components/brand/VibeCheckLogo";
import { primaryNav, secondaryNav } from "@/lib/content";
import { cn } from "@/lib/cn";

export function SiteHeader() {
  const pathname = usePathname();
  const [open, setOpen] = useState(false);
  const [scrolled, setScrolled] = useState(false);
  const panelRef = useRef<HTMLDivElement>(null);
  const toggleRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 12);
    onScroll();
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  useEffect(() => {
    setOpen(false);
  }, [pathname]);

  useEffect(() => {
    if (!open) return;
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        setOpen(false);
        toggleRef.current?.focus();
      }
    };
    document.addEventListener("keydown", onKey);
    const previous = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      document.removeEventListener("keydown", onKey);
      document.body.style.overflow = previous;
    };
  }, [open]);

  const isActive = (href: string) =>
    pathname === href || (href !== "/" && pathname.startsWith(href + "/"));

  return (
    <header
      className={cn(
        "fixed inset-x-0 top-0 z-[100] border-b transition-colors duration-500",
        scrolled || open
          ? "border-hairline bg-[rgba(8,8,13,0.82)] backdrop-blur-xl"
          : "border-hairline-soft bg-[rgba(8,8,13,0.45)] backdrop-blur-md",
      )}
    >
      <div className="shell flex h-[72px] items-center justify-between gap-6">
        <Link
          href="/"
          aria-label="VibeCheck home"
          className="group flex items-center"
          onClick={() => setOpen(false)}
        >
          <VibeCheckLogo size="md" />
        </Link>

        <nav aria-label="Primary" className="hidden lg:block">
          <ul className="flex items-center gap-6 xl:gap-8">
            {primaryNav.map((item) => (
              <li key={item.href}>
                <Link
                  href={item.href}
                  aria-current={isActive(item.href) ? "page" : undefined}
                  className={cn(
                    "mono link-underline relative py-2 transition-colors duration-300",
                    isActive(item.href)
                      ? "text-fog"
                      : "text-muted hover:text-fog",
                  )}
                >
                  {item.label}
                  {isActive(item.href) && (
                    <span className="absolute -bottom-0.5 left-1/2 h-1 w-1 -translate-x-1/2 bg-violet-bright" />
                  )}
                </Link>
              </li>
            ))}
          </ul>
        </nav>

        <div className="hidden items-center gap-5 lg:flex xl:gap-6">
          {secondaryNav.map((item) => (
            <Link
              key={item.href}
              href={item.href}
              aria-current={isActive(item.href) ? "page" : undefined}
              className={cn(
                "mono link-underline py-2 transition-colors",
                isActive(item.href) ? "text-fog" : "text-muted hover:text-fog",
              )}
            >
              {item.label}
            </Link>
          ))}
          <Link href="/about#early-access" className="btn btn-primary h-[38px] text-[10px]">
            Get Early Access
            <ArrowUpRight className="h-3.5 w-3.5" aria-hidden="true" />
          </Link>
        </div>

        <button
          ref={toggleRef}
          type="button"
          onClick={() => setOpen((value) => !value)}
          aria-expanded={open}
          aria-controls="mobile-nav"
          aria-label={open ? "Close menu" : "Open menu"}
          className="flex h-10 w-10 items-center justify-center border border-hairline text-fog transition-colors hover:border-lavender/40 lg:hidden"
        >
          {open ? <X className="h-4.5 w-4.5" /> : <Menu className="h-4.5 w-4.5" />}
        </button>
      </div>

      <div
        id="mobile-nav"
        ref={panelRef}
        hidden={!open}
        className="border-t border-hairline bg-[rgba(8,8,13,0.97)] lg:hidden"
      >
        <nav aria-label="Mobile" className="shell py-6">
          <ul className="flex flex-col">
            {[...primaryNav, ...secondaryNav].map((item, index) => (
              <li key={item.href} className="border-b border-hairline-soft last:border-b-0">
                <Link
                  href={item.href}
                  onClick={() => setOpen(false)}
                  className="flex items-center justify-between py-4"
                >
                  <span className="flex items-baseline gap-4">
                    <span className="mono-sm text-ash">
                      {String(index + 1).padStart(2, "0")}
                    </span>
                    <span
                      className={cn(
                        "font-display text-[22px] tracking-[-0.03em]",
                        isActive(item.href) ? "text-lavender" : "text-fog",
                      )}
                    >
                      {item.label}
                    </span>
                  </span>
                  <ArrowUpRight className="h-4 w-4 text-ash" aria-hidden="true" />
                </Link>
              </li>
            ))}
          </ul>
          <Link
            href="/about#early-access"
            onClick={() => setOpen(false)}
            className="btn btn-primary mt-6 w-full"
          >
            Get Early Access
          </Link>
          <p className="mono-sm mt-4 text-center text-ash">
            Private development · Secure what you build.
          </p>
        </nav>
      </div>
    </header>
  );
}
