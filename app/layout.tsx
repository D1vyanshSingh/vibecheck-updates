import type { Metadata, Viewport } from "next";
import { Space_Grotesk, Inter, JetBrains_Mono } from "next/font/google";
import "./globals.css";

const spaceGrotesk = Space_Grotesk({
  subsets: ["latin"],
  variable: "--font-space-grotesk",
  display: "swap",
  weight: ["400", "500", "600", "700"],
});

const inter = Inter({
  subsets: ["latin"],
  variable: "--font-inter",
  display: "swap",
});

const jetbrains = JetBrains_Mono({
  subsets: ["latin"],
  variable: "--font-jetbrains",
  display: "swap",
  weight: ["400", "500"],
});

const siteUrl = process.env.NEXT_PUBLIC_SITE_URL ?? "https://vibecheck.dev";

export const metadata: Metadata = {
  metadataBase: new URL(siteUrl),
  title: {
    default: "VibeCheck — Secure What You Build.",
    template: "%s — VibeCheck",
  },
  description:
    "VibeCheck is building security verification infrastructure for the AI-powered software development era. Discover, understand and verify security weaknesses in the applications you build.",
  applicationName: "VibeCheck",
  keywords: [
    "application security",
    "AI generated code security",
    "vibe coding security",
    "secret scanning",
    "dependency risk",
    "security verification",
    "VibeCheck",
  ],
  authors: [{ name: "VibeCheck" }],
  creator: "VibeCheck",
  openGraph: {
    type: "website",
    siteName: "VibeCheck",
    title: "VibeCheck — Secure What You Build.",
    description:
      "Security verification infrastructure for the AI-powered software development era. Currently in private development.",
    url: siteUrl,
  },
  twitter: {
    card: "summary_large_image",
    title: "VibeCheck — Secure What You Build.",
    description:
      "Discover, understand and verify security weaknesses in the applications you build.",
  },
  robots: { index: true, follow: true },
  alternates: { canonical: "/" },
  icons: {
    icon: [{ url: "/brand/favicon.svg", type: "image/svg+xml" }],
  },
};

export const viewport: Viewport = {
  themeColor: "#08080D",
  colorScheme: "dark",
  width: "device-width",
  initialScale: 1,
};

/**
 * Root layout: fonts, tokens and document shell only.
 * Chrome lives in the route groups — (site) keeps the marketing header and
 * footer, (app) gets the console shell, (auth) gets the centred card.
 */
export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html
      lang="en"
      className={`${spaceGrotesk.variable} ${inter.variable} ${jetbrains.variable}`}
    >
      <body className="min-h-screen bg-void font-sans antialiased">{children}</body>
    </html>
  );
}
