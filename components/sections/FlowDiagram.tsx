import { cn } from "@/lib/cn";

/**
 * FlowDiagram — code, data, auth and deployment as one inspected surface.
 * Pure SVG + CSS animation; no layout thrash, no canvas.
 */
export function FlowDiagram({ className }: { className?: string }) {
  return (
    <div className={cn("relative w-full", className)}>
      <svg
        viewBox="0 0 560 420"
        role="img"
        aria-label="Diagram: code, data, authentication and deployment feeding a single verification surface"
        className="h-auto w-full"
      >
        <defs>
          <linearGradient id="flow-line" x1="0" y1="0" x2="1" y2="0">
            <stop offset="0" stopColor="#702BFF" stopOpacity="0.1" />
            <stop offset="0.5" stopColor="#C9B5FF" stopOpacity="0.7" />
            <stop offset="1" stopColor="#702BFF" stopOpacity="0.1" />
          </linearGradient>
          <radialGradient id="flow-node-bg" cx="0.5" cy="0.5" r="0.5">
            <stop offset="0" stopColor="#702BFF" stopOpacity="0.28" />
            <stop offset="1" stopColor="#702BFF" stopOpacity="0" />
          </radialGradient>
        </defs>

        {/* construction grid */}
        <g stroke="#ffffff" strokeOpacity="0.05">
          {Array.from({ length: 12 }).map((_, index) => (
            <line key={`v${index}`} x1={index * 50 + 10} y1="0" x2={index * 50 + 10} y2="420" />
          ))}
          {Array.from({ length: 9 }).map((_, index) => (
            <line key={`h${index}`} x1="0" y1={index * 50 + 10} x2="560" y2={index * 50 + 10} />
          ))}
        </g>

        {/* connectors */}
        <g fill="none" stroke="url(#flow-line)" strokeWidth="1">
          <path className="diagram-flow" d="M120 96 C 210 96, 210 208, 280 208" />
          <path className="diagram-flow" d="M120 186 C 200 186, 200 208, 280 208" />
          <path className="diagram-flow" d="M120 286 C 200 286, 200 208, 280 208" />
          <path className="diagram-flow" d="M120 356 C 220 356, 210 208, 280 208" />
        </g>

        {/* source nodes */}
        {[
          { y: 96, label: "CODE", detail: "routes · handlers" },
          { y: 186, label: "DATA", detail: "schema · policies" },
          { y: 286, label: "AUTH", detail: "sessions · roles" },
          { y: 356, label: "DEPLOY", detail: "env · config" },
        ].map((node) => (
          <g key={node.label}>
            <rect
              x="34"
              y={node.y - 22}
              width="86"
              height="44"
              fill="#11101A"
              stroke="#ffffff"
              strokeOpacity="0.14"
            />
            <text
              x="77"
              y={node.y - 3}
              textAnchor="middle"
              fill="#F5F3FF"
              fontSize="10"
              letterSpacing="2.2"
              fontFamily="var(--font-jetbrains), monospace"
            >
              {node.label}
            </text>
            <text
              x="77"
              y={node.y + 13}
              textAnchor="middle"
              fill="#6C677D"
              fontSize="7.5"
              letterSpacing="1.2"
              fontFamily="var(--font-jetbrains), monospace"
            >
              {node.detail}
            </text>
            <circle cx="120" cy={node.y} r="2" fill="#C9B5FF" />
          </g>
        ))}

        {/* verification surface */}
        <g>
          <circle cx="280" cy="208" r="92" fill="url(#flow-node-bg)" />
          <circle cx="280" cy="208" r="70" fill="none" stroke="#C9B5FF" strokeOpacity="0.24" />
          <circle
            cx="280"
            cy="208"
            r="56"
            fill="none"
            stroke="#974FFF"
            strokeOpacity="0.34"
            strokeDasharray="2 6"
          />
          <g className="node-pulse">
            <circle cx="280" cy="208" r="38" fill="#151222" stroke="#C9B5FF" strokeOpacity="0.45" />
          </g>
          <text
            x="280"
            y="204"
            textAnchor="middle"
            fill="#F5F3FF"
            fontSize="10"
            letterSpacing="2"
            fontFamily="var(--font-jetbrains), monospace"
          >
            VIBECHECK
          </text>
          <text
            x="280"
            y="220"
            textAnchor="middle"
            fill="#A5A0B5"
            fontSize="7.5"
            letterSpacing="1.6"
            fontFamily="var(--font-jetbrains), monospace"
          >
            VERIFY SURFACE
          </text>
        </g>

        {/* outputs */}
        <g fill="none" stroke="url(#flow-line)" strokeWidth="1">
          <path className="diagram-flow" d="M352 190 C 420 190, 420 160, 470 160" />
          <path className="diagram-flow" d="M352 226 C 420 226, 420 256, 470 256" />
        </g>

        {[
          { y: 160, label: "FINDING", value: "evidence" },
          { y: 256, label: "RECORD", value: "verified" },
        ].map((node) => (
          <g key={node.label}>
            <rect
              x="470"
              y={node.y - 20}
              width="76"
              height="40"
              fill="#11101A"
              stroke="#ffffff"
              strokeOpacity="0.14"
            />
            <text
              x="508"
              y={node.y - 2}
              textAnchor="middle"
              fill="#C9B5FF"
              fontSize="9"
              letterSpacing="2"
              fontFamily="var(--font-jetbrains), monospace"
            >
              {node.label}
            </text>
            <text
              x="508"
              y={node.y + 12}
              textAnchor="middle"
              fill="#6C677D"
              fontSize="7.5"
              letterSpacing="1"
              fontFamily="var(--font-jetbrains), monospace"
            >
              {node.value}
            </text>
          </g>
        ))}

        {/* scale caption */}
        <g stroke="#ffffff" strokeOpacity="0.22">
          <line x1="34" y1="392" x2="134" y2="392" />
          <line x1="34" y1="388" x2="34" y2="396" />
          <line x1="134" y1="388" x2="134" y2="396" />
        </g>
        <text
          x="34"
          y="408"
          fill="#6C677D"
          fontSize="7.5"
          letterSpacing="1.4"
          fontFamily="var(--font-jetbrains), monospace"
        >
          CONCEPTUAL MODEL — NOT A DEPLOYMENT DIAGRAM
        </text>
      </svg>
    </div>
  );
}

