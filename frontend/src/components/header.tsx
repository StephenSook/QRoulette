"use client";

import { useEffect, useState, useCallback, useRef } from "react";
import { Shield, User, Scan, Settings, LogOut, ChevronRight } from "lucide-react";
import Link from "next/link";

// Fixed initial pattern to avoid hydration mismatch (no Math.random on first render)
const INITIAL_PATTERN: boolean[][] = [
  [true, false, true, true, false],
  [false, true, false, false, true],
  [true, true, false, true, false],
  [false, false, true, true, true],
  [true, false, true, false, true],
];

function generateQRPattern(): boolean[][] {
  return Array.from({ length: 5 }, () =>
    Array.from({ length: 5 }, () => Math.random() > 0.4)
  );
}

function MiniQRShield() {
  const [pattern, setPattern] = useState<boolean[][]>(INITIAL_PATTERN);
  const [transitioning, setTransitioning] = useState(false);

  const cyclePattern = useCallback(() => {
    setTransitioning(true);
    setTimeout(() => {
      setPattern(generateQRPattern());
      setTransitioning(false);
    }, 300);
  }, []);

  useEffect(() => {
    // Start cycling after mount (client-side only)
    const timeout = setTimeout(cyclePattern, 1500);
    const interval = setInterval(cyclePattern, 3000);
    return () => {
      clearTimeout(timeout);
      clearInterval(interval);
    };
  }, [cyclePattern]);

  const cellSize = 2.2;
  const gridSize = 5;
  const totalSize = cellSize * gridSize;
  const offsetX = (28 - totalSize) / 2;
  const offsetY = (28 - totalSize) / 2 + 2;

  return (
    <div className="relative cyber-shield">
      <Shield className="w-7 h-7 text-accent-green" strokeWidth={2.5} />
      <svg
        className="absolute inset-0 w-7 h-7"
        viewBox="0 0 28 28"
        style={{
          transition: "opacity 0.3s ease",
          opacity: transitioning ? 0 : 1,
        }}
      >
        {pattern.map((row, y) =>
          row.map((cell, x) => (
            <rect
              key={`${x}-${y}`}
              x={offsetX + x * cellSize}
              y={offsetY + y * cellSize}
              width={cellSize - 0.4}
              height={cellSize - 0.4}
              rx={0.3}
              fill={cell ? "#00ff88" : "transparent"}
              opacity={cell ? 0.9 : 0}
              style={{
                transition: `opacity 0.4s ease ${(x + y) * 0.03}s`,
              }}
            />
          ))
        )}
        <rect x={offsetX - 0.3} y={offsetY - 0.3} width={cellSize + 0.6} height={cellSize + 0.6} rx={0.4} fill="none" stroke="#00ff88" strokeWidth={0.5} opacity={0.6} />
        <rect x={offsetX + (gridSize - 1) * cellSize - 0.3} y={offsetY - 0.3} width={cellSize + 0.6} height={cellSize + 0.6} rx={0.4} fill="none" stroke="#00ff88" strokeWidth={0.5} opacity={0.6} />
        <rect x={offsetX - 0.3} y={offsetY + (gridSize - 1) * cellSize - 0.3} width={cellSize + 0.6} height={cellSize + 0.6} rx={0.4} fill="none" stroke="#00ff88" strokeWidth={0.5} opacity={0.6} />
      </svg>
    </div>
  );
}

function ProfileButton() {
  const [isHovered, setIsHovered] = useState(false);
  const [glowHue, setGlowHue] = useState(0);
  const [toast, setToast] = useState<string | null>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const animRef = useRef<number>(0);

  const showToast = (msg: string) => {
    setToast(msg);
    setTimeout(() => setToast(null), 2000);
  };

  // Rotating hue for the glow
  useEffect(() => {
    if (!isHovered) return;
    let frame = 0;
    const tick = () => {
      frame++;
      setGlowHue((frame * 2) % 360);
      animRef.current = requestAnimationFrame(tick);
    };
    animRef.current = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(animRef.current);
  }, [isHovered]);

  return (
    <div
      ref={containerRef}
      className="relative"
      onMouseEnter={() => setIsHovered(true)}
      onMouseLeave={() => setIsHovered(false)}
    >
      {/* Glow ring behind button */}
      <div
        className="absolute -inset-1.5 rounded-xl transition-opacity duration-300"
        style={{
          opacity: isHovered ? 1 : 0,
          background: `conic-gradient(from ${glowHue}deg, #00ff88, #00cc6a, #3b82f6, #8b5cf6, #00ff88)`,
          filter: "blur(6px)",
        }}
      />
      <div
        className="absolute -inset-0.5 rounded-xl transition-opacity duration-300"
        style={{
          opacity: isHovered ? 1 : 0,
          background: `conic-gradient(from ${glowHue}deg, #00ff88, #00cc6a, #3b82f6, #8b5cf6, #00ff88)`,
        }}
      />

      {/* Button */}
      <button
        className="relative w-9 h-9 rounded-lg bg-card border border-card-border flex items-center justify-center transition-all duration-300"
        style={{
          borderColor: isHovered ? "transparent" : undefined,
          boxShadow: isHovered
            ? `0 0 20px rgba(0, 255, 136, 0.3), inset 0 0 12px rgba(0, 255, 136, 0.05)`
            : "none",
        }}
      >
        <User
          className="w-4 h-4 transition-colors duration-300"
          style={{ color: isHovered ? "#00ff88" : "#64748b" }}
        />
      </button>

      {/* Dropdown */}
      <div
        className="absolute right-0 top-full mt-2 w-56 transition-all duration-300 origin-top-right"
        style={{
          opacity: isHovered ? 1 : 0,
          transform: isHovered ? "scale(1) translateY(0)" : "scale(0.95) translateY(-4px)",
          pointerEvents: isHovered ? "auto" : "none",
        }}
      >
        {/* Glow border on dropdown */}
        <div
          className="absolute -inset-[1px] rounded-xl"
          style={{
            background: `conic-gradient(from ${glowHue}deg, rgba(0,255,136,0.4), rgba(59,130,246,0.3), rgba(139,92,246,0.3), rgba(0,255,136,0.4))`,
            filter: "blur(1px)",
          }}
        />

        <div className="relative bg-card/95 backdrop-blur-xl rounded-xl border border-card-border overflow-hidden">
          {/* User info */}
          <div className="px-4 py-3 border-b border-card-border">
            <div className="flex items-center gap-3">
              <div
                className="w-8 h-8 rounded-full flex items-center justify-center"
                style={{
                  background: `conic-gradient(from ${glowHue}deg, #00ff88, #00cc6a, #3b82f6, #00ff88)`,
                }}
              >
                <div className="w-[26px] h-[26px] rounded-full bg-card flex items-center justify-center">
                  <span className="text-xs font-bold text-accent-green">S</span>
                </div>
              </div>
              <div>
                <p className="text-xs font-bold tracking-wider">OPERATOR</p>
                <p className="text-[10px] text-muted tracking-widest">
                  CLEARANCE: ALPHA
                </p>
              </div>
            </div>
          </div>

          {/* Menu items */}
          <div className="py-1">
            {[
              { icon: Scan, label: "SCAN HISTORY", count: "142", toast: "Scan history — connecting to database" },
              { icon: Settings, label: "PROTOCOLS", count: null, toast: "Protocols — connecting soon" },
              { icon: LogOut, label: "DISCONNECT", count: null, toast: "Session management — connecting soon" },
            ].map((item) => (
              <button
                key={item.label}
                onClick={() => showToast(item.toast)}
                className="w-full px-4 py-2.5 flex items-center justify-between hover:bg-accent-green/5 transition-colors group active:bg-accent-green/10"
              >
                <div className="flex items-center gap-2.5">
                  <item.icon className="w-3.5 h-3.5 text-muted group-hover:text-accent-green transition-colors" />
                  <span className="text-[11px] tracking-[0.15em] text-muted group-hover:text-foreground transition-colors">
                    {item.label}
                  </span>
                </div>
                <div className="flex items-center gap-1.5">
                  {item.count && (
                    <span className="text-[10px] text-accent-green font-mono">
                      {item.count}
                    </span>
                  )}
                  <ChevronRight className="w-3 h-3 text-muted/40 group-hover:text-accent-green/60 transition-colors" />
                </div>
              </button>
            ))}
          </div>

          {/* Footer */}
          <div className="px-4 py-2 border-t border-card-border">
            <div className="flex items-center justify-between">
              <span className="text-[9px] text-muted tracking-widest">
                SESSION_ID: QR-7X92
              </span>
              <div className="flex items-center gap-1">
                <div className="w-1.5 h-1.5 rounded-full bg-accent-green animate-pulse" />
                <span className="text-[9px] text-accent-green tracking-widest">
                  LIVE
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Toast */}
      {toast && (
        <div className="absolute right-0 top-full mt-1 z-[60] px-3 py-2 bg-card/95 backdrop-blur border border-card-border rounded-lg shadow-lg animate-fade-in">
          <p className="text-[10px] text-muted tracking-widest whitespace-nowrap">
            {toast}
          </p>
        </div>
      )}
    </div>
  );
}

export function Header() {
  return (
    <header className="sticky top-0 z-50 flex items-center justify-between px-5 py-4 bg-background/80 backdrop-blur-md border-b border-card-border">
      <Link href="/" className="flex items-center gap-2.5 group cyber-logo-glitch">
        <MiniQRShield />
        <div className="relative">
          <span className="text-lg font-black tracking-[0.15em] uppercase cyber-logo-text">
            QRoulette
          </span>
          <div className="absolute -bottom-0.5 left-0 h-[1px] w-full overflow-hidden">
            <div
              className="h-full bg-gradient-to-r from-transparent via-accent-green to-transparent opacity-60"
              style={{
                animation: "cyber-text-scroll 4s linear infinite",
                backgroundSize: "200% 100%",
              }}
            />
          </div>
        </div>
      </Link>

      <ProfileButton />
    </header>
  );
}
