import { cn } from "@/lib/cn";

/**
 * VibeCheck mark — a V built from two converging strokes, bracketed by an
 * orbital ellipse, with the brand star at the orbit's apogee.
 * Drawn as clean vector geometry so it stays sharp at every size.
 */
export function VibeCheckMark({
  className,
  size = 28,
  glow = false,
}: {
  className?: string;
  size?: number;
  glow?: boolean;
}) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 48 48"
      fill="none"
      role="img"
      aria-label="VibeCheck mark"
      className={cn("shrink-0", className)}
    >
      <defs>
        <linearGradient id="vc-mark-stroke" x1="8" y1="6" x2="40" y2="42" gradientUnits="userSpaceOnUse">
          <stop offset="0" stopColor="#C9B5FF" />
          <stop offset="0.55" stopColor="#974FFF" />
          <stop offset="1" stopColor="#702BFF" />
        </linearGradient>
        <linearGradient id="vc-mark-orbit" x1="6" y1="10" x2="42" y2="34" gradientUnits="userSpaceOnUse">
          <stop offset="0" stopColor="#702BFF" stopOpacity="0.25" />
          <stop offset="0.5" stopColor="#C9B5FF" stopOpacity="0.95" />
          <stop offset="1" stopColor="#974FFF" stopOpacity="0.35" />
        </linearGradient>
        {glow && (
          <filter id="vc-mark-glow" x="-50%" y="-50%" width="200%" height="200%">
            <feGaussianBlur stdDeviation="2.2" result="b" />
            <feMerge>
              <feMergeNode in="b" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        )}
      </defs>

      <g filter={glow ? "url(#vc-mark-glow)" : undefined}>
        {/* orbit */}
        <ellipse
          cx="24"
          cy="23.5"
          rx="20"
          ry="9.4"
          transform="rotate(-31 24 23.5)"
          stroke="url(#vc-mark-orbit)"
          strokeWidth="1.35"
        />
        {/* V */}
        <path
          d="M13.5 12.5 L23.9 37.4 L34.4 12.5"
          stroke="url(#vc-mark-stroke)"
          strokeWidth="5"
          strokeLinecap="square"
          strokeLinejoin="miter"
        />
        <path d="M13.5 12.5 L19.1 12.5 L23.9 24.2 L28.8 12.5 L34.4 12.5" stroke="#08080D" strokeWidth="0.9" opacity="0.55" />
        {/* star at orbit apogee */}
        <path
          d="M37.4 4.6 C37.9 8.1 38.9 9.1 42.4 9.6 C38.9 10.1 37.9 11.1 37.4 14.6 C36.9 11.1 35.9 10.1 32.4 9.6 C35.9 9.1 36.9 8.1 37.4 4.6 Z"
          fill="#F5F3FF"
        />
      </g>
    </svg>
  );
}

/** Full horizontal lockup: mark + wordmark + tagline. */
export function VibeCheckLogo({
  className,
  showTagline = false,
  size = "md",
}: {
  className?: string;
  showTagline?: boolean;
  size?: "sm" | "md" | "lg";
}) {
  const markSize = size === "sm" ? 22 : size === "lg" ? 34 : 27;
  const text = size === "sm" ? "text-[15px]" : size === "lg" ? "text-[21px]" : "text-[17px]";

  return (
    <span className={cn("inline-flex items-center gap-2.5", className)}>
      <VibeCheckMark size={markSize} />
      <span className="flex flex-col leading-none">
        <span
          className={cn(
            "font-display font-semibold tracking-[-0.045em] text-fog",
            text,
          )}
        >
          VibeCheck<span className="text-violet-bright">.</span>
        </span>
        {showTagline && (
          <span className="mono-sm mt-1 text-ash">Secure what you build.</span>
        )}
      </span>
    </span>
  );
}
