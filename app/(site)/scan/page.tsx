import type { Metadata } from "next";

import { PageHeader } from "@/components/sections/PageHeader";
import { ScanConsole } from "@/components/scan/ScanConsole";

export const metadata: Metadata = {
  title: "URL scanner",
  description:
    "Enter a URL and VibeCheck scans the host behind it: exposed services, TLS, security headers and known fingerprints, returned as a live report and a branded PDF.",
  alternates: { canonical: "/scan" },
};

export default function ScanPage() {
  return (
    <>
      <PageHeader
        code="09"
        eyebrow="URL scanner"
        title="Put a URL in. Get the report out."
        description="The scanner reads what a host actually answers on its web ports — banners, certificates and headers — then applies the checks and writes a report. Findings state their confidence, and an empty result is never presented as proof of safety."
        meta={[
          { label: "Target", value: "Any http(s) URL or hostname" },
          { label: "Scope", value: "Web ports only" },
          { label: "Output", value: "Live report + PDF" },
          { label: "Engine", value: "vulnscan · native" },
        ]}
      />

      <section aria-labelledby="scan-heading" className="section">
        <div className="shell">
          <div className="flex flex-wrap items-end justify-between gap-4">
            <div>
              <p className="mono text-ash">Run an assessment</p>
              <h2
                id="scan-heading"
                className="display display-section mt-4 max-w-[18ch] text-fog"
              >
                One URL. One report.
              </h2>
            </div>
            <p className="mono-sm max-w-[30rem] text-ash">
              Scans run from this machine against the host you name. Authorised
              targets only.
            </p>
          </div>

          <div className="mt-10">
            <ScanConsole />
          </div>
        </div>
      </section>
    </>
  );
}
