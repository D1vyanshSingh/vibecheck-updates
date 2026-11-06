"use client";

import Link from "next/link";
import { useEffect, useRef } from "react";
import { ArrowRight, ArrowUpRight } from "lucide-react";
import { TubesBackground } from "@/components/3d/TubesBackground";
import { OrbitalCore } from "@/components/3d/OrbitalCore";
import { VibeCheckMark } from "@/components/brand/VibeCheckLogo";

export function Hero() {
  const rootRef = useRef<HTMLElement>(null);
  const topLineRef = useRef<HTMLSpanElement>(null);
  const bottomLineRef = useRef<HTMLSpanElement>(null);
  const coreRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const motionQuery = window.matchMedia("(prefers-reduced-motion: reduce)");
    if (motionQuery.matches) return;

    let cleanup: (() => void) | undefined;
    let cancelled = false;

    const init = async () => {
      const gsapModule = await import("gsap");
      const scrollTriggerModule = await import("gsap/ScrollTrigger");
      if (cancelled) return;

      const gsap = gsapModule.gsap ?? gsapModule.default;
      const ScrollTrigger =
        scrollTriggerModule.ScrollTrigger ?? scrollTriggerModule.default;

      gsap.registerPlugin(ScrollTrigger);

      const ctx = gsap.context(() => {
        const top = topLineRef.current;
        const bottom = bottomLineRef.current;
        const core = coreRef.current;
        if (!top || !bottom || !core) return;

        gsap.set([top, bottom], { transformOrigin: "50% 50%" });

        gsap
          .timeline({
            scrollTrigger: {
              trigger: rootRef.current,
              start: "top top",
              end: "72% top",
              scrub: 0.7,
              invalidateOnRefresh: true,
            },
          })
          .to(top, { yPercent: -34, xPercent: 4, ease: "none" }, 0)
          .to(bottom, { yPercent: 34, xPercent: 4, ease: "none" }, 0)
          .to(core, { yPercent: -26, scale: 1.08, ease: "none" }, 0)
          .to(core, { opacity: 0.35, ease: "none" }, 0.45);

        ScrollTrigger.refresh();
      }, rootRef);

      cleanup = () => ctx.revert();
    };

    void init();

    return () => {
      cancelled = true;
      cleanup?.();
    };
  }, []);

  return (
    <section
      ref={rootRef}
      aria-labelledby="hero-headline"
      className="relative isolate overflow-hidden bg-void pt-[72px]"
    >
      <TubesBackground className="-z-10" />

      <div className="shell relative flex min-h-[calc(100svh-72px)] flex-col justify-between pb-8 pt-6">
        {/* top technical rail */}
        <div className="flex items-center justify-between gap-6 border-b border-hairline-soft pb-4">
          <p className="mono-sm flex items-center gap-2 text-ash">
            <VibeCheckMark size={13} />
            Security verification infrastructure
          </p>
          <p className="mono-sm hidden items-center gap-2 text-ash sm:flex">
            <span className="h-1 w-1 bg-violet-bright" />
            Private development · v0.1
          </p>
        </div>

        <div className="grid items-center gap-y-10 py-10 lg:grid-cols-[minmax(0,48%)_minmax(0,1fr)] lg:gap-x-8 lg:py-6">
          {/* copy stack */}
          <div className="relative z-20 max-w-[36rem]">
            <p className="eyebrow">Secure what you build</p>

            <h1 id="hero-headline" className="display display-hero mt-6 text-fog">
              Your AI builds fast.
              <br />
              We make sure
              <br />
              <span className="relative inline-block">
                it&rsquo;s secure.
                <svg
                  aria-hidden="true"
                  viewBox="0 0 320 12"
                  preserveAspectRatio="none"
                  className="absolute -bottom-1 left-0 h-[7px] w-full text-violet-bright/70"
                >
                  <path
                    d="M1 8.2C58 3.4 122 2.6 180 4.6c42 1.4 88 3.2 139 1.2"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="1.2"
                  />
                </svg>
              </span>
            </h1>

            <p className="lede mt-7 max-w-[42ch]">
              Discover, understand and verify security weaknesses in the
              applications you build.
            </p>

            <div className="mt-9 flex flex-col gap-3 sm:flex-row sm:items-center">
              <Link href="/about#early-access" className="btn btn-primary">
                Get early access
                <ArrowUpRight className="h-3.5 w-3.5" aria-hidden="true" />
              </Link>
              <Link href="/platform" className="btn btn-outline group">
                Explore the platform
                <ArrowRight
                  className="h-3.5 w-3.5 transition-transform duration-300 group-hover:translate-x-0.5"
                  aria-hidden="true"
                />
              </Link>
            </div>

            <p className="mono-sm mt-6 text-ash">
              No pricing published · No credit card · A person replies
            </p>
          </div>

          {/* split wordmark bracket */}
          <div className="relative z-10 flex items-center justify-center lg:justify-end">
            <div className="relative w-full max-w-[34rem] select-none lg:max-w-none">
              <div className="relative text-right">
                <span
                  ref={topLineRef}
                  className="wordmark-line wordmark-line--top block text-[clamp(3.6rem,19vw,6.6rem)] lg:text-[clamp(4rem,9.6vw,9.5rem)]"
                >
                  Vibe
                </span>

                <div
                  className="pointer-events-none absolute inset-x-0 top-1/2 z-[2] flex -translate-y-1/2 justify-center"
                >
                  <div ref={coreRef} className="wordmark-core">
                    <OrbitalCore className="h-[clamp(8.5rem,34vw,12rem)] w-[clamp(8.5rem,34vw,12rem)] lg:h-[clamp(11rem,20vw,17rem)] lg:w-[clamp(11rem,20vw,17rem)]" />
                  </div>
                </div>

                <span
                  ref={bottomLineRef}
                  className="wordmark-line wordmark-line--bottom block text-[clamp(3.6rem,19vw,6.6rem)] lg:text-[clamp(4rem,9.6vw,9.5rem)]"
                >
                  Check
                </span>
              </div>

              <div className="mt-5 flex items-end justify-between gap-4 border-t border-hairline-soft pt-3">
                <p className="mono-sm max-w-[16rem] text-ash">
                  Core object / orbital verification
                </p>
                <p className="mono-sm text-ash">001 — 07</p>
              </div>
            </div>
          </div>
        </div>

        {/* bottom rail */}
        <div className="flex flex-col gap-4 border-t border-hairline-soft pt-4 sm:flex-row sm:items-center sm:justify-between">
          <p className="mono-sm max-w-[34rem] text-ash">
            Analysis surface / code · secrets · dependencies · data access ·
            configuration
          </p>
          <div className="flex items-center gap-4">
            <span className="mono-sm text-ash">Scroll</span>
            <span aria-hidden="true" className="relative block h-8 w-px bg-hairline">
              <span className="absolute inset-x-0 top-0 h-3 animate-[vc-scroll_2.6s_ease-in-out_infinite] bg-lavender/80" />
            </span>
          </div>
        </div>
      </div>
    </section>
  );
}
