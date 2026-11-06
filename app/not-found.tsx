import Link from "next/link";
import { ArrowRight } from "lucide-react";

export default function NotFound() {
  return (
    <section className="relative flex min-h-[80svh] items-center overflow-hidden bg-void pt-[72px]">
      <div aria-hidden="true" className="grid-field absolute inset-0 opacity-50" />
      <div className="shell relative py-20">
        <p className="mono text-violet-bright">404 — route not found</p>
        <h1 className="display mt-6 max-w-[18ch] text-[clamp(2.4rem,6vw,4.5rem)] text-fog">
          This path was never built.
        </h1>
        <p className="lede mt-6 max-w-[46ch]">
          Which is the one kind of missing route we can do something about. The
          navigation above will take you somewhere real.
        </p>
        <div className="mt-9 flex flex-col gap-3 sm:flex-row">
          <Link href="/" className="btn btn-primary">
            Back to home
            <ArrowRight className="h-3.5 w-3.5" aria-hidden="true" />
          </Link>
          <Link href="/platform" className="btn btn-outline">
            Explore the platform
          </Link>
        </div>
      </div>
    </section>
  );
}
