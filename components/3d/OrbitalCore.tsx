import { cn } from "@/lib/cn";

/**
 * OrbitalCore — the brand object that sits in the gap of the split wordmark.
 * Deliberately CSS + SVG rather than a second WebGL context: it stays crisp at
 * every size, costs almost nothing on mobile, and matches the logo geometry
 * (V monogram inside an orbit, star at the apogee).
 */
export function OrbitalCore({ className }: { className?: string }) {
  return (
    <div
      aria-hidden="true"
      className={cn("orbital-core pointer-events-none relative", className)}
    >
      <div className="absolute inset-[12%] rounded-full bg-[radial-gradient(circle,rgba(112,43,255,0.55)_0%,rgba(112,43,255,0.14)_45%,transparent_72%)] blur-2xl" />

      <svg viewBox="0 0 200 200" className="relative h-full w-full overflow-visible">
        <defs>
          <linearGradient id="core-front-left" x1="46" y1="86" x2="100" y2="174" gradientUnits="userSpaceOnUse">
            <stop offset="0" stopColor="#974FFF" />
            <stop offset="1" stopColor="#3D128F" />
          </linearGradient>
          <linearGradient id="core-front-right" x1="154" y1="86" x2="100" y2="174" gradientUnits="userSpaceOnUse">
            <stop offset="0" stopColor="#702BFF" />
            <stop offset="1" stopColor="#1E0846" />
          </linearGradient>
          <linearGradient id="core-top-left" x1="100" y1="26" x2="52" y2="92" gradientUnits="userSpaceOnUse">
            <stop offset="0" stopColor="#E3D8FF" />
            <stop offset="0.6" stopColor="#A87BFF" />
            <stop offset="1" stopColor="#702BFF" />
          </linearGradient>
          <linearGradient id="core-top-right" x1="100" y1="26" x2="148" y2="92" gradientUnits="userSpaceOnUse">
            <stop offset="0" stopColor="#C9B5FF" />
            <stop offset="1" stopColor="#5B21C9" />
          </linearGradient>
          <linearGradient id="core-orbit" x1="14" y1="120" x2="186" y2="80" gradientUnits="userSpaceOnUse">
            <stop offset="0" stopColor="#702BFF" stopOpacity="0" />
            <stop offset="0.35" stopColor="#C9B5FF" stopOpacity="0.85" />
            <stop offset="0.7" stopColor="#974FFF" stopOpacity="0.5" />
            <stop offset="1" stopColor="#C9B5FF" stopOpacity="0" />
          </linearGradient>
          <radialGradient id="core-glow" cx="0.5" cy="0.5" r="0.5">
            <stop offset="0" stopColor="#C9B5FF" stopOpacity="0.9" />
            <stop offset="1" stopColor="#702BFF" stopOpacity="0" />
          </radialGradient>
          <filter id="core-blur" x="-30%" y="-30%" width="160%" height="160%">
            <feGaussianBlur stdDeviation="6" />
          </filter>
        </defs>

        <circle cx="100" cy="100" r="62" fill="url(#core-glow)" opacity="0.35" filter="url(#core-blur)" />

        {/* orbit geometry */}
        <g className="orbital-core__rings" strokeLinecap="round">
          <ellipse
            cx="100"
            cy="102"
            rx="88"
            ry="30"
            transform="rotate(-26 100 102)"
            fill="none"
            stroke="url(#core-orbit)"
            strokeWidth="1.1"
          />
          <ellipse
            cx="100"
            cy="102"
            rx="74"
            ry="22"
            transform="rotate(34 100 102)"
            fill="none"
            stroke="#974FFF"
            strokeOpacity="0.22"
            strokeWidth="0.9"
            strokeDasharray="2 7"
          />
        </g>

        {/* gem facets */}
        <g className="orbital-core__body">
          <polygon points="100,24 46,88 100,84" fill="url(#core-top-left)" opacity="0.95" />
          <polygon points="100,24 154,88 100,84" fill="url(#core-top-right)" opacity="0.9" />
          <polygon points="46,88 100,178 100,84" fill="url(#core-front-left)" opacity="0.9" />
          <polygon points="154,88 100,178 100,84" fill="url(#core-front-right)" opacity="0.92" />
          <polyline
            points="46,88 100,24 154,88 100,178 46,88"
            fill="none"
            stroke="#E3D8FF"
            strokeOpacity="0.4"
            strokeWidth="0.8"
          />
          <line x1="100" y1="24" x2="100" y2="178" stroke="#F5F3FF" strokeOpacity="0.16" strokeWidth="0.7" />

          {/* V etched on the front */}
          <path
            d="M84 96 L100 136 L116 96"
            fill="none"
            stroke="#F5F3FF"
            strokeOpacity="0.82"
            strokeWidth="3.4"
            strokeLinejoin="miter"
          />
        </g>

        {/* star at apogee */}
        <g className="orbital-core__star">
          <path
            d="M164 30 C164.8 36.4 166.6 38.2 173 39 C166.6 39.8 164.8 41.6 164 48 C163.2 41.6 161.4 39.8 155 39 C161.4 38.2 163.2 36.4 164 30 Z"
            fill="#F5F3FF"
          />
          <circle cx="40" cy="132" r="2.1" fill="#C9B5FF" />
          <circle cx="152" cy="150" r="1.5" fill="#974FFF" />
        </g>
      </svg>
    </div>
  );
}
