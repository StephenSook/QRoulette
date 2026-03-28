"use client";

import { useEffect, useRef, useCallback } from "react";

interface Column {
  x: number;
  y: number;
  speed: number;
  chars: string[];
  opacity: number;
  fontSize: number;
}

interface Beam {
  y: number;
  speed: number;
  width: number;
  opacity: number;
  length: number;
  x: number;
}

interface Particle {
  x: number;
  y: number;
  radius: number;
  opacity: number;
  pulseSpeed: number;
  pulsePhase: number;
}

const BINARY_CHARS = "01";
const GREEN = { r: 0, g: 255, b: 136 }; // #00ff88

export function CyberBackground() {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const animFrameRef = useRef<number>(0);
  const columnsRef = useRef<Column[]>([]);
  const beamsRef = useRef<Beam[]>([]);
  const particlesRef = useRef<Particle[]>([]);
  const timeRef = useRef(0);

  const createColumn = useCallback((width: number, height: number): Column => {
    const fontSize = 12 + Math.random() * 5;
    const charCount = Math.floor(height / fontSize) + 5;
    return {
      x: Math.random() * width,
      y: -Math.random() * height * 2,
      speed: 0.3 + Math.random() * 1.2,
      chars: Array.from({ length: charCount }, () =>
        BINARY_CHARS[Math.floor(Math.random() * BINARY_CHARS.length)]
      ),
      opacity: 0.06 + Math.random() * 0.14,
      fontSize,
    };
  }, []);

  const createBeam = useCallback((width: number, height: number): Beam => {
    return {
      y: Math.random() * height,
      speed: 0.5 + Math.random() * 2,
      width: 1 + Math.random() * 2,
      opacity: 0.02 + Math.random() * 0.06,
      length: width * (0.2 + Math.random() * 0.6),
      x: -200 + Math.random() * width * 0.3,
    };
  }, []);

  const createParticle = useCallback((width: number, height: number): Particle => {
    return {
      x: Math.random() * width,
      y: Math.random() * height,
      radius: 1 + Math.random() * 3,
      opacity: 0.1 + Math.random() * 0.3,
      pulseSpeed: 0.01 + Math.random() * 0.03,
      pulsePhase: Math.random() * Math.PI * 2,
    };
  }, []);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext("2d", { alpha: true });
    if (!ctx) return;

    let disposed = false;

    const resize = () => {
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      const w = window.innerWidth;
      const h = document.documentElement.scrollHeight || window.innerHeight;
      canvas.width = w * dpr;
      canvas.height = h * dpr;
      canvas.style.width = `${w}px`;
      canvas.style.height = `${h}px`;
      ctx.scale(dpr, dpr);

      // Initialize elements
      const colCount = Math.floor(w / 25);
      columnsRef.current = Array.from({ length: colCount }, () =>
        createColumn(w, h)
      );
      beamsRef.current = Array.from({ length: 8 }, () =>
        createBeam(w, h)
      );
      particlesRef.current = Array.from({ length: 20 }, () =>
        createParticle(w, h)
      );
    };

    resize();

    const ro = new ResizeObserver(() => {
      if (!disposed) resize();
    });
    ro.observe(document.body);

    function drawBinaryRain(ctx: CanvasRenderingContext2D, w: number, h: number) {
      columnsRef.current.forEach((col) => {
        ctx.font = `${col.fontSize}px "Geist Mono", monospace`;

        col.chars.forEach((char, i) => {
          const charY = col.y + i * col.fontSize;
          if (charY < -col.fontSize || charY > h + col.fontSize) return;

          // Head character is brighter
          const isHead = i === col.chars.length - 1;
          const distFromHead = col.chars.length - 1 - i;
          const fadeFactor = Math.max(0, 1 - distFromHead / (col.chars.length * 0.6));

          const alpha = isHead
            ? col.opacity * 4
            : col.opacity * fadeFactor * 1.5;

          ctx.fillStyle = `rgba(${GREEN.r}, ${GREEN.g}, ${GREEN.b}, ${alpha})`;
          ctx.fillText(char, col.x, charY);

          // Randomly change characters
          if (Math.random() < 0.01) {
            col.chars[i] = BINARY_CHARS[Math.floor(Math.random() * BINARY_CHARS.length)];
          }
        });

        col.y += col.speed;

        // Reset when off screen
        if (col.y - col.chars.length * col.fontSize > h) {
          col.y = -col.chars.length * col.fontSize - Math.random() * h * 0.5;
          col.x = Math.random() * w;
        }
      });
    }

    function drawBeams(ctx: CanvasRenderingContext2D, w: number, h: number) {
      beamsRef.current.forEach((beam) => {
        const gradient = ctx.createLinearGradient(
          beam.x, beam.y,
          beam.x + beam.length, beam.y
        );
        gradient.addColorStop(0, `rgba(${GREEN.r}, ${GREEN.g}, ${GREEN.b}, 0)`);
        gradient.addColorStop(0.3, `rgba(${GREEN.r}, ${GREEN.g}, ${GREEN.b}, ${beam.opacity})`);
        gradient.addColorStop(0.7, `rgba(${GREEN.r}, ${GREEN.g}, ${GREEN.b}, ${beam.opacity})`);
        gradient.addColorStop(1, `rgba(${GREEN.r}, ${GREEN.g}, ${GREEN.b}, 0)`);

        ctx.beginPath();
        ctx.strokeStyle = gradient;
        ctx.lineWidth = beam.width;
        ctx.moveTo(beam.x, beam.y);
        ctx.lineTo(beam.x + beam.length, beam.y);
        ctx.stroke();

        beam.x += beam.speed;

        if (beam.x > w + 100) {
          beam.x = -beam.length - Math.random() * 200;
          beam.y = Math.random() * h;
          beam.opacity = 0.02 + Math.random() * 0.06;
        }
      });
    }

    function drawParticles(ctx: CanvasRenderingContext2D, t: number) {
      particlesRef.current.forEach((p) => {
        const pulse = Math.sin(t * p.pulseSpeed + p.pulsePhase);
        const alpha = p.opacity * (0.5 + pulse * 0.5);
        const r = p.radius * (0.8 + pulse * 0.2);

        // Glow
        const grd = ctx.createRadialGradient(p.x, p.y, 0, p.x, p.y, r * 6);
        grd.addColorStop(0, `rgba(${GREEN.r}, ${GREEN.g}, ${GREEN.b}, ${alpha * 0.6})`);
        grd.addColorStop(0.4, `rgba(${GREEN.r}, ${GREEN.g}, ${GREEN.b}, ${alpha * 0.2})`);
        grd.addColorStop(1, `rgba(${GREEN.r}, ${GREEN.g}, ${GREEN.b}, 0)`);

        ctx.beginPath();
        ctx.fillStyle = grd;
        ctx.arc(p.x, p.y, r * 6, 0, Math.PI * 2);
        ctx.fill();

        // Core
        ctx.beginPath();
        ctx.fillStyle = `rgba(${GREEN.r}, ${GREEN.g}, ${GREEN.b}, ${alpha})`;
        ctx.arc(p.x, p.y, r, 0, Math.PI * 2);
        ctx.fill();
      });
    }

    function drawGrid(ctx: CanvasRenderingContext2D, w: number, h: number, t: number) {
      const gridSize = 60;
      const scrollOffset = (t * 0.15) % gridSize;

      ctx.strokeStyle = `rgba(${GREEN.r}, ${GREEN.g}, ${GREEN.b}, 0.015)`;
      ctx.lineWidth = 0.5;

      // Vertical lines
      for (let x = -gridSize + scrollOffset; x < w + gridSize; x += gridSize) {
        ctx.beginPath();
        ctx.moveTo(x, 0);
        ctx.lineTo(x, h);
        ctx.stroke();
      }

      // Horizontal lines
      for (let y = -gridSize + scrollOffset * 0.5; y < h + gridSize; y += gridSize) {
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(w, y);
        ctx.stroke();
      }
    }

    function animate() {
      if (disposed) return;

      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      const w = canvas!.width / dpr;
      const h = canvas!.height / dpr;

      ctx!.clearRect(0, 0, w, h);

      timeRef.current += 1;
      const t = timeRef.current;

      drawGrid(ctx!, w, h, t);
      drawBinaryRain(ctx!, w, h);
      drawBeams(ctx!, w, h);
      drawParticles(ctx!, t);

      animFrameRef.current = requestAnimationFrame(animate);
    }

    animFrameRef.current = requestAnimationFrame(animate);

    return () => {
      disposed = true;
      if (animFrameRef.current) cancelAnimationFrame(animFrameRef.current);
      ro.disconnect();
    };
  }, [createColumn, createBeam, createParticle]);

  return (
    <canvas
      ref={canvasRef}
      className="pointer-events-none fixed inset-0 z-0"
      style={{ opacity: 0.6 }}
      aria-hidden="true"
    />
  );
}
