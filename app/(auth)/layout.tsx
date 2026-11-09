import Link from "next/link";
import { VibeCheckLogo } from "@/components/brand/VibeCheckLogo";

export default function AuthLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <div className="flex min-h-screen flex-col bg-void">
      <header className="shell flex h-[72px] items-center justify-between border-b border-hairline">
        <Link href="/" aria-label="VibeCheck home">
          <VibeCheckLogo size="sm" />
        </Link>
        <Link
          href="/"
          className="mono text-ash transition-colors hover:text-fog"
        >
          Back to site
        </Link>
      </header>
      <main className="flex flex-1 items-center justify-center px-5 py-14">
        <div className="w-full max-w-[420px]">{children}</div>
      </main>
      <footer className="shell flex h-14 items-center justify-between border-t border-hairline">
        <span className="mono-sm text-ash">Private development · v0.1</span>
        <span className="mono-sm text-ash">Secure what you build.</span>
      </footer>
    </div>
  );
}
