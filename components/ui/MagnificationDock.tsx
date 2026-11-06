"use client";

import {
  AnimatePresence,
  motion,
  useMotionValue,
  useReducedMotion,
  useSpring,
  useTransform,
  type MotionValue,
} from "framer-motion";
import { useRef, useState, type ReactNode, type Ref } from "react";
import { cn } from "@/lib/cn";

export type DockItem = {
  icon: ReactNode;
  label: string;
  /** In-page anchor or route. Rendered as a real link, so it works without JS. */
  href?: string;
  onSelect?: () => void;
  id?: string;
};

type DockProps = {
  items: DockItem[];
  className?: string;
  distance?: number;
  panelHeight?: number;
  baseItemSize?: number;
  magnification?: number;
  label?: string;
};

type DockItemProps = {
  item: DockItem;
  mouseX: MotionValue<number>;
  distance: number;
  baseItemSize: number;
  magnification: number;
};

function DockItem({
  item,
  mouseX,
  distance,
  baseItemSize,
  magnification,
}: DockItemProps) {
  const ref = useRef<HTMLElement>(null);
  const hovered = useMotionValue(0);
  const reduce = useReducedMotion();

  const mouseDistance = useTransform(mouseX, (value) => {
    const rect = ref.current?.getBoundingClientRect();
    if (!rect) return distance * 2;
    return value - rect.x - rect.width / 2;
  });

  const targetSize = useTransform(
    mouseDistance,
    [-distance, 0, distance],
    [baseItemSize, magnification, baseItemSize],
  );
  const springSize = useSpring(targetSize, { mass: 0.1, stiffness: 170, damping: 14 });
  const size = reduce ? baseItemSize : springSize;

  const [tooltipOpen, setTooltipOpen] = useState(false);
  const isHashLink = item.href?.startsWith("#") ?? false;
  const linkTarget = isHashLink ? "_self" : undefined;

  const content = (
    <>
      <DockIcon hovered={hovered}>{item.icon}</DockIcon>
      <AnimatePresence>
        {tooltipOpen && (
          <motion.span
            role="tooltip"
            initial={{ opacity: 0, y: 4 }}
            animate={{ opacity: 1, y: -8 }}
            exit={{ opacity: 0, y: 0 }}
            transition={{ duration: 0.18 }}
            className="pointer-events-none absolute -top-9 left-1/2 z-20 w-max -translate-x-1/2 whitespace-nowrap border border-hairline bg-elevated px-2 py-1 font-mono text-[10px] uppercase tracking-[0.12em] text-lavender"
          >
            {item.label}
          </motion.span>
        )}
      </AnimatePresence>
    </>
  );

  const interaction = {
    onHoverStart: () => {
      hovered.set(1);
      setTooltipOpen(true);
    },
    onHoverEnd: () => {
      hovered.set(0);
      setTooltipOpen(false);
    },
    onFocus: () => {
      hovered.set(1);
      setTooltipOpen(true);
    },
    onBlur: () => {
      hovered.set(0);
      setTooltipOpen(false);
    },
    style: { width: size, height: size },
    className: cn(
      "dock-item relative flex shrink-0 items-center justify-center",
    ),
    "aria-label": item.label,
  };

  if (item.href) {
    return (
      <motion.a
        {...interaction}
        ref={ref as Ref<HTMLAnchorElement>}
        href={item.href}
        target={linkTarget}
        onClick={(event) => {
          if (item.onSelect) item.onSelect();
          if (!isHashLink || !item.href) return;

          // Deterministic in-page scroll: fragment navigation alone is not
          // reliable with a sticky header, so offset it explicitly.
          const target = document.querySelector<HTMLElement>(item.href);
          if (!target) return;
          event.preventDefault();
          const top = target.getBoundingClientRect().top + window.scrollY - 88;
          window.scrollTo({ top, behavior: reduce ? "auto" : "smooth" });
          history.replaceState(null, "", item.href);
        }}
      >
        {content}
      </motion.a>
    );
  }

  return (
    <motion.button
      {...interaction}
      ref={ref as Ref<HTMLButtonElement>}
      type="button"
      onClick={() => item.onSelect?.()}
    >
      {content}
    </motion.button>
  );
}

function DockIcon({
  children,
  hovered,
}: {
  children: ReactNode;
  hovered: MotionValue<number>;
}) {
  const scale = useTransform(hovered, [0, 1], [1, 1.08]);
  const rotate = useTransform(hovered, [0, 1], [0, -4]);

  return (
    <motion.span
      style={{ scale, rotate }}
      className="flex h-full w-full items-center justify-center [&_svg]:h-[18px] [&_svg]:w-[18px] md:[&_svg]:h-[19px] md:[&_svg]:w-[19px]"
    >
      {children}
    </motion.span>
  );
}

export function MagnificationDock({
  items,
  className,
  distance = 170,
  panelHeight = 60,
  baseItemSize = 44,
  magnification = 62,
  label = "Section navigation",
}: DockProps) {
  const reduce = useReducedMotion();
  const mouseX = useMotionValue(Number.POSITIVE_INFINITY);
  const isHovered = useMotionValue(0);

  const heightRow = useTransform(isHovered, [0, 1], [panelHeight, panelHeight + 12]);
  const springHeight = useSpring(heightRow, { mass: 0.1, stiffness: 180, damping: 18 });
  const height = reduce ? panelHeight : springHeight;

  return (
    <div className={cn("w-full", className)}>
      {/* Desktop: magnification dock */}
      <motion.div
        style={{ height }}
        className="hidden justify-center overflow-visible md:flex"
      >
        <motion.div
          role="toolbar"
          aria-label={label}
          onMouseMove={(event) => {
            isHovered.set(1);
            mouseX.set(event.pageX);
          }}
          onMouseLeave={() => {
            isHovered.set(0);
            mouseX.set(Number.POSITIVE_INFINITY);
          }}
          className="dock-panel flex items-center gap-2 px-2.5"
        >
          {items.map((item) => (
            <DockItem
              key={item.label}
              item={item}
              mouseX={mouseX}
              distance={distance}
              baseItemSize={baseItemSize}
              magnification={magnification}
            />
          ))}
        </motion.div>
      </motion.div>

      {/* Mobile: touch-friendly controls, no magnification. */}
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 md:hidden">
        {items.map((item) => {
          const content = (
            <>
              <span className="text-lavender [&_svg]:h-4 [&_svg]:w-4">{item.icon}</span>
              <span className="font-mono text-[10px] uppercase leading-tight tracking-[0.12em] text-muted">
                {item.label}
              </span>
            </>
          );
          const classes =
            "flex min-h-[46px] items-center gap-2.5 border border-hairline bg-surface px-3 py-2.5 text-left transition-colors hover:border-lavender/40";

          return item.href ? (
            <a key={item.label} href={item.href} className={classes}>
              {content}
            </a>
          ) : (
            <button
              key={item.label}
              type="button"
              onClick={() => item.onSelect?.()}
              className={classes}
            >
              {content}
            </button>
          );
        })}
      </div>
    </div>
  );
}
