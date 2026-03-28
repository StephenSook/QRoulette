"use client";

import { useRef, useEffect, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { LayoutGrid, QrCode, PlusSquare, BarChart3 } from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";

const navItems = [
  { href: "/", label: "HOME", icon: LayoutGrid },
  { href: "/scanner", label: "SCANNER", icon: QrCode },
  { href: "/generate", label: "GENERATE", icon: PlusSquare },
  { href: "/vault", label: "VAULT", icon: BarChart3 },
];

function PulseBeamNav({ activeIndex }: { activeIndex: number }) {
  const svgRef = useRef<SVGSVGElement>(null);
  const [dims, setDims] = useState({ w: 400, h: 60 });

  useEffect(() => {
    const update = () => {
      if (svgRef.current?.parentElement) {
        const rect = svgRef.current.parentElement.getBoundingClientRect();
        setDims({ w: rect.width, h: 60 });
      }
    };
    update();
    window.addEventListener("resize", update);
    return () => window.removeEventListener("resize", update);
  }, []);

  const spacing = dims.w / 4;
  const centerY = 8;

  // Generate beam paths from active item to each other item
  const beams = navItems.map((_, i) => {
    const fromX = activeIndex * spacing + spacing / 2;
    const toX = i * spacing + spacing / 2;

    if (i === activeIndex) return null;

    const midX = (fromX + toX) / 2;
    const curveY = centerY + 20 + Math.abs(i - activeIndex) * 8;

    return {
      path: `M${fromX},${centerY} Q${midX},${curveY} ${toX},${centerY}`,
      index: i,
      distance: Math.abs(i - activeIndex),
    };
  }).filter(Boolean) as { path: string; index: number; distance: number }[];

  return (
    <svg
      ref={svgRef}
      className="absolute inset-0 pointer-events-none"
      width={dims.w}
      height={dims.h}
      viewBox={`0 0 ${dims.w} ${dims.h}`}
      fill="none"
    >
      <defs>
        {beams.map((beam, i) => (
          <motion.linearGradient
            key={`grad-${beam.index}`}
            id={`nav-grad-${beam.index}`}
            gradientUnits="userSpaceOnUse"
            initial={{
              x1: "0%",
              x2: "0%",
              y1: "80%",
              y2: "100%",
            }}
            animate={{
              x1: ["0%", "100%", "100%"],
              x2: ["0%", "80%", "80%"],
              y1: ["80%", "0%", "0%"],
              y2: ["100%", "20%", "20%"],
            }}
            transition={{
              duration: 2 + beam.distance * 0.3,
              repeat: Infinity,
              repeatType: "loop" as const,
              ease: "linear",
              repeatDelay: 1.5 + beam.distance * 0.5,
              delay: i * 0.8,
            }}
          >
            <stop offset="0%" stopColor="#00ff88" stopOpacity="0" />
            <stop offset="20%" stopColor="#00ff88" stopOpacity="1" />
            <stop offset="50%" stopColor="#00cc6a" stopOpacity="1" />
            <stop offset="80%" stopColor="#3b82f6" stopOpacity="0.8" />
            <stop offset="100%" stopColor="#8b5cf6" stopOpacity="0" />
          </motion.linearGradient>
        ))}

        {/* Glow filter */}
        <filter id="nav-glow">
          <feGaussianBlur stdDeviation="2" result="blur" />
          <feMerge>
            <feMergeNode in="blur" />
            <feMergeNode in="SourceGraphic" />
          </feMerge>
        </filter>
      </defs>

      {/* Base paths (dim) */}
      {beams.map((beam) => (
        <path
          key={`base-${beam.index}`}
          d={beam.path}
          stroke="rgba(0, 255, 136, 0.06)"
          strokeWidth="1"
          fill="none"
        />
      ))}

      {/* Animated gradient paths */}
      {beams.map((beam) => (
        <path
          key={`pulse-${beam.index}`}
          d={beam.path}
          stroke={`url(#nav-grad-${beam.index})`}
          strokeWidth="2"
          strokeLinecap="round"
          fill="none"
          filter="url(#nav-glow)"
        />
      ))}

      {/* Connection nodes at each nav item */}
      {navItems.map((_, i) => {
        const cx = i * spacing + spacing / 2;
        const isActive = i === activeIndex;
        return (
          <g key={`node-${i}`}>
            {/* Outer glow ring for active */}
            {isActive && (
              <motion.circle
                cx={cx}
                cy={centerY}
                r={8}
                fill="none"
                stroke="#00ff88"
                strokeWidth={1}
                opacity={0.3}
                animate={{ r: [8, 12, 8], opacity: [0.3, 0.1, 0.3] }}
                transition={{ duration: 2, repeat: Infinity, ease: "easeInOut" }}
              />
            )}
            {/* Node dot */}
            <motion.circle
              cx={cx}
              cy={centerY}
              r={isActive ? 4 : 2.5}
              fill={isActive ? "#00ff88" : "rgba(30, 41, 59, 0.8)"}
              stroke={isActive ? "#00ff88" : "rgba(100, 116, 139, 0.4)"}
              strokeWidth={1}
              animate={
                isActive
                  ? { filter: ["drop-shadow(0 0 3px #00ff88)", "drop-shadow(0 0 8px #00ff88)", "drop-shadow(0 0 3px #00ff88)"] }
                  : {}
              }
              transition={isActive ? { duration: 2, repeat: Infinity, ease: "easeInOut" } : {}}
            />
          </g>
        );
      })}
    </svg>
  );
}

export function BottomNav() {
  const pathname = usePathname();

  const activeIndex = navItems.findIndex((item) =>
    item.href === "/" ? pathname === "/" : pathname.startsWith(item.href)
  );

  return (
    <nav className="fixed bottom-0 left-0 right-0 z-50 bg-background/90 backdrop-blur-md border-t border-card-border">
      <div className="relative max-w-lg mx-auto">
        {/* Pulse beam SVG layer */}
        <PulseBeamNav activeIndex={activeIndex >= 0 ? activeIndex : 0} />

        {/* Nav items */}
        <div className="relative z-10 flex items-center justify-around px-4 py-3">
          {navItems.map((item, i) => {
            const isActive =
              item.href === "/"
                ? pathname === "/"
                : pathname.startsWith(item.href);
            return (
              <Link
                key={item.href}
                href={item.href}
                className="relative flex flex-col items-center gap-1 text-xs tracking-widest transition-colors"
              >
                {/* Active glow backdrop */}
                <AnimatePresence>
                  {isActive && (
                    <motion.div
                      layoutId="nav-active-bg"
                      className="absolute -inset-2 -top-3 rounded-xl bg-accent-green/5 border border-accent-green/10"
                      initial={{ opacity: 0, scale: 0.8 }}
                      animate={{ opacity: 1, scale: 1 }}
                      exit={{ opacity: 0, scale: 0.8 }}
                      transition={{ type: "spring", stiffness: 300, damping: 25 }}
                    />
                  )}
                </AnimatePresence>

                <item.icon
                  className={`relative z-10 w-5 h-5 transition-colors duration-200 ${
                    isActive ? "text-accent-green" : "text-muted"
                  }`}
                />
                <span
                  className={`relative z-10 transition-colors duration-200 ${
                    isActive ? "text-accent-green" : "text-muted"
                  }`}
                >
                  {item.label}
                </span>
              </Link>
            );
          })}
        </div>
      </div>
    </nav>
  );
}
