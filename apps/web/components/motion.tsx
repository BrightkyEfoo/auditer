"use client";

import { useEffect, useRef, useState, type ReactNode, type ElementType } from "react";
import { cn } from "@/lib/cn";

/**
 * The motion vocabulary of the site. THREE gestures, no more:
 *
 *   1. reveal   — enter on scroll, once, never replayed.
 *   2. parallax — depth on scroll, transform-only.
 *   3. scramble — technical values decode into place.
 *
 * Everything here is CSS-first. The previous implementation drove parallax from
 * a shared requestAnimationFrame loop that (a) never stopped, so it burned a
 * frame callback forever on a page nobody was scrolling, and (b) called
 * getBoundingClientRect() per layer per frame, forcing a synchronous layout
 * every single frame. That is precisely what a performance audit flags, and
 * shipping it on a product that sells code audits was not defensible.
 *
 * Scroll-driven CSS animations replace it outright: `animation-timeline: view()`
 * runs off the main thread, costs zero JavaScript, and is at ~85% support.
 * Where it is missing (Firefox stable at time of writing), layers simply sit
 * still — a missing depth effect is a non-event, unlike a janky one.
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

/**
 * Display type that rises out of its own clipping box, one line at a time.
 *
 * Split by LINE, never by word or character. Splitting words into letters
 * breaks JAWS, Narrator and VoiceOver (they skip the content or spell it out),
 * breaks machine translation, breaks in-page find, and breaks copy-paste — it
 * engages WCAG 2.5.3 and 4.1.2. Lines carry the same "the type is being set"
 * feeling with none of that, because each line stays one intact text node.
 */
export function LineReveal({
  lines,
  className,
  step = 90,
}: {
  lines: ReactNode[];
  className?: string;
  step?: number;
}) {
  const ref = useRef<HTMLSpanElement>(null);
  useEffect(() => (ref.current ? observeReveal(ref.current) : undefined), []);
  return (
    <span ref={ref} className={cn("block", className)}>
      {lines.map((l, i) => (
        <span key={i} className="line-mask">
          <span style={{ ["--line-delay" as string]: `${i * step}ms` }}>{l}</span>
        </span>
      ))}
    </span>
  );
}

/* ── 2. Parallax ────────────────────────────────────────────────────────── */

/**
 * Depth on scroll, driven entirely by the compositor.
 *
 * `speed` maps to the CSS custom property the keyframes read, so the only work
 * React does is render one element with two inline properties. Negative rises
 * against the scroll (foreground), positive lags (background).
 */
export function Parallax({
  children,
  speed = -0.12,
  className,
}: {
  children: ReactNode;
  speed?: number;
  className?: string;
}) {
  return (
    <div
      data-parallax=""
      style={{ ["--par-shift" as string]: `${(speed * 100).toFixed(1)}px` }}
      className={cn("will-change-transform", className)}
    >
      {children}
    </div>
  );
}

/* ── 3. Scramble ────────────────────────────────────────────────────────── */

const GLYPHS = "ABCDEFGHJKLMNPQRSTUVWXYZ0123456789/#$%&*+=<>";

/**
 * Decodes text into place when it first scrolls into view. Reserved for
 * technical values (scores, counts, status words) — scrambling prose would be
 * decoration; scrambling a measurement reads as the instrument settling.
 *
 * The scrambled glyphs live in an aria-hidden span behind a real aria-label, so
 * assistive technology is handed the final value and never the churn.
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

/**
 * A measured value that counts up to itself. Used where a number IS the point —
 * a score, a total. Unlike Scramble it stays numeric throughout, so it reads as
 * a needle settling rather than as an effect.
 */
export function CountUp({
  to,
  durationMs = 900,
  className,
}: {
  to: number;
  durationMs?: number;
  className?: string;
}) {
  const ref = useRef<HTMLSpanElement>(null);
  const [n, setN] = useState(to);

  useEffect(() => {
    const el = ref.current;
    if (!el || reducedMotion() || typeof IntersectionObserver === "undefined") return;
    setN(0);
    let raf = 0;
    let start = 0;
    const io = new IntersectionObserver(
      (entries) => {
        if (!entries[0]?.isIntersecting) return;
        io.disconnect();
        const step = (ts: number) => {
          start ||= ts;
          const p = Math.min(1, (ts - start) / durationMs);
          // Same ease-out curve as every entrance in the system.
          setN(Math.round(to * (1 - Math.pow(1 - p, 3))));
          if (p < 1) raf = requestAnimationFrame(step);
        };
        raf = requestAnimationFrame(step);
      },
      { threshold: 0.6 },
    );
    io.observe(el);
    return () => {
      io.disconnect();
      cancelAnimationFrame(raf);
    };
  }, [to, durationMs]);

  return (
    <span ref={ref} className={className} aria-label={String(to)}>
      <span aria-hidden>{n}</span>
    </span>
  );
}

/* ── Scroll-progress readout ────────────────────────────────────────────── */

/**
 * Page scroll as a percentage. Writes straight to the DOM node through a ref
 * instead of through state: the previous version called setState on every
 * scroll event, which re-rendered React once per scrolled frame and shows up
 * directly in INP. The value is chrome, not data — nothing downstream needs to
 * react to it.
 */
export function ScrollReadout({ className }: { className?: string }) {
  const ref = useRef<HTMLSpanElement>(null);

  useEffect(() => {
    let raf = 0;
    const write = () => {
      raf = 0;
      const max = document.documentElement.scrollHeight - window.innerHeight;
      const pct = max > 0 ? Math.round((window.scrollY / max) * 100) : 0;
      if (ref.current) ref.current.textContent = String(pct).padStart(3, "0");
    };
    const onScroll = () => {
      // Coalesce bursts of scroll events into one write per frame.
      if (!raf) raf = requestAnimationFrame(write);
    };
    write();
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => {
      window.removeEventListener("scroll", onScroll);
      if (raf) cancelAnimationFrame(raf);
    };
  }, []);

  return (
    <span ref={ref} className={className}>
      000
    </span>
  );
}
