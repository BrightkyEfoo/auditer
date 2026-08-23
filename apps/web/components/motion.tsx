"use client";

import { useEffect, useRef, useState, type ReactNode, type ElementType } from "react";
import { cn } from "@/lib/cn";

/**
 * The whole motion vocabulary of the site, in one file. THREE gestures, no more:
 *
 *   1. reveal   — enter on scroll (fade + 22px rise), plays once, never replays.
 *   2. parallax — depth on scroll, transform-only.
 *   3. scramble — technical values decode into place.
 *
 * Everything is transform/opacity so nothing hits layout, everything is driven
 * by ONE shared observer and ONE shared rAF loop (a per-element listener at
 * this density is what makes marketing pages jank), and everything degrades to
 * the final state under prefers-reduced-motion.
 */

function reducedMotion(): boolean {
  return (
    typeof window !== "undefined" &&
    window.matchMedia("(prefers-reduced-motion: reduce)").matches
  );
}

/* ── 1. Reveal ──────────────────────────────────────────────────────────── */

let revealObserver: IntersectionObserver | null = null;

function observeReveal(el: HTMLElement): () => void {
  if (typeof IntersectionObserver === "undefined") {
    el.setAttribute("data-shown", "");
    return () => {};
  }
  revealObserver ??= new IntersectionObserver(
    (entries) => {
      for (const e of entries) {
        if (!e.isIntersecting) continue;
        e.target.setAttribute("data-shown", "");
        revealObserver!.unobserve(e.target); // once seen, never replayed
      }
    },
    // Fire slightly before the element is fully in view, and ignore the bottom
    // 10% so an element does not animate while the user is already past it.
    { rootMargin: "0px 0px -10% 0px", threshold: 0.12 },
  );
  revealObserver.observe(el);
  return () => revealObserver?.unobserve(el);
}

export function Reveal({
  children,
  delay = 0,
  as: Tag = "div",
  className,
}: {
  children: ReactNode;
  /** Stagger within a group. Keep to 60-90ms steps; beyond that it reads as lag. */
  delay?: number;
  as?: ElementType;
  className?: string;
}) {
  const ref = useRef<HTMLElement>(null);
  useEffect(() => (ref.current ? observeReveal(ref.current) : undefined), []);
  return (
    <Tag
      ref={ref}
      data-reveal=""
      style={{ ["--reveal-delay" as string]: `${delay}ms` }}
      className={className}
    >
      {children}
    </Tag>
  );
}

/* ── 2. Parallax ────────────────────────────────────────────────────────── */

interface Layer {
  el: HTMLElement;
  speed: number;
}

const layers = new Set<Layer>();
let rafId = 0;

function tick() {
  const h = window.innerHeight;
  for (const { el, speed } of layers) {
    const r = el.getBoundingClientRect();
    // Progress of the element's centre through the viewport: -1 (below the
    // fold) → 0 (centred) → 1 (above it). Symmetric, so a layer sits at its
    // authored position exactly when it is centred.
    const p = (r.top + r.height / 2 - h / 2) / h;
    el.style.transform = `translate3d(0, ${(p * speed * 100).toFixed(2)}px, 0)`;
  }
  rafId = requestAnimationFrame(tick);
}

function registerLayer(layer: Layer): () => void {
  layers.add(layer);
  if (!rafId) rafId = requestAnimationFrame(tick);
  return () => {
    layers.delete(layer);
    if (layers.size === 0 && rafId) {
      cancelAnimationFrame(rafId);
      rafId = 0;
    }
  };
}

export function Parallax({
  children,
  /** Negative rises against the scroll (foreground), positive lags (background). */
  speed = -0.12,
  className,
}: {
  children: ReactNode;
  speed?: number;
  className?: string;
}) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!ref.current || reducedMotion()) return;
    return registerLayer({ el: ref.current, speed });
  }, [speed]);
  return (
    <div ref={ref} className={cn("will-change-transform", className)}>
      {children}
    </div>
  );
}

/* ── 3. Scramble ────────────────────────────────────────────────────────── */

const GLYPHS = "ABCDEFGHJKLMNPQRSTUVWXYZ0123456789/#$%&*+=<>";

/**
 * Decodes text into place when it first scrolls into view. Reserved for
 * technical values (scores, counts, status words) — scrambling prose would be
 * decoration, scrambling a measurement reads as the instrument settling.
 */
export function Scramble({
  text,
  className,
  durationMs = 620,
}: {
  text: string;
  className?: string;
  durationMs?: number;
}) {
  const ref = useRef<HTMLSpanElement>(null);
  const [out, setOut] = useState(text);

  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    if (reducedMotion() || typeof IntersectionObserver === "undefined") {
      setOut(text);
      return;
    }
    let raf = 0;
    let start = 0;
    const io = new IntersectionObserver(
      (entries) => {
        if (!entries[0]?.isIntersecting) return;
        io.disconnect();
        const step = (ts: number) => {
          start ||= ts;
          const p = Math.min(1, (ts - start) / durationMs);
          // Characters lock in left-to-right; the tail keeps churning.
          const locked = Math.floor(p * text.length);
          setOut(
            text
              .split("")
              .map((c, i) =>
                i < locked || c === " "
                  ? c
                  : GLYPHS[(Math.floor(ts / 30) + i * 7) % GLYPHS.length],
              )
              .join(""),
          );
          if (p < 1) raf = requestAnimationFrame(step);
          else setOut(text);
        };
        raf = requestAnimationFrame(step);
      },
      { threshold: 0.5 },
    );
    io.observe(el);
    return () => {
      io.disconnect();
      cancelAnimationFrame(raf);
    };
  }, [text, durationMs]);

  return (
    <span ref={ref} className={className} aria-label={text}>
      <span aria-hidden>{out}</span>
    </span>
  );
}

/* ── Scroll-progress readout ────────────────────────────────────────────── */

/** Page scroll as a percentage, shown in the fixed HUD. Instrument, not chrome. */
export function ScrollReadout({ className }: { className?: string }) {
  const [pct, setPct] = useState(0);
  useEffect(() => {
    const onScroll = () => {
      const max = document.documentElement.scrollHeight - window.innerHeight;
      setPct(max > 0 ? Math.round((window.scrollY / max) * 100) : 0);
    };
    onScroll();
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);
  return <span className={className}>{String(pct).padStart(3, "0")}</span>;
}
