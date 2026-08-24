"use client";

import { useEffect, useState } from "react";

/**
 * A boot sequence over the hero readout, played once per session.
 *
 * This is the site's one non-substitutable moment: it cannot be lifted onto
 * another product, because every line is a fact about how this one works. A
 * loading spinner says "wait"; a status sequence says "here is the machine you
 * are about to use", and it does it before the visitor has read a single word
 * of marketing copy.
 *
 * Three constraints keep it from becoming an obstacle:
 *   - it plays ONCE per session (sessionStorage), never on every navigation;
 *   - it is capped at well under a second, and the panel behind it is already
 *     rendered — nothing is being waited for, so nothing is being blocked;
 *   - it never runs under prefers-reduced-motion, and it never runs before
 *     hydration, so a visitor without JavaScript simply sees the panel.
 */

const SEQUENCE = [
  "INIT SANDBOX runsc",
  "MOTEURS 08/08",
  "BASES CVE 2026-08-23",
  "BARÈME v1.1.0",
  "SORTIE RÉSEAU COUPÉE",
] as const;

const STEP_MS = 110;
const HOLD_MS = 220;
const KEY = "auditer:boot";

export function BootSequence() {
  // Starts false so the server and the first client render agree: the overlay
  // only ever appears as a post-hydration effect.
  const [playing, setPlaying] = useState(false);
  const [shown, setShown] = useState(0);

  useEffect(() => {
    if (typeof window === "undefined") return;
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    if (sessionStorage.getItem(KEY)) return;
    sessionStorage.setItem(KEY, "1");

    setPlaying(true);
    const timers: ReturnType<typeof setTimeout>[] = [];
    SEQUENCE.forEach((_, i) => {
      timers.push(setTimeout(() => setShown(i + 1), i * STEP_MS));
    });
    timers.push(
      setTimeout(() => setPlaying(false), SEQUENCE.length * STEP_MS + HOLD_MS),
    );
    return () => timers.forEach(clearTimeout);
  }, []);

  if (!playing) return null;

  return (
    <div
      aria-hidden
      className="pointer-events-none absolute inset-0 z-10 flex flex-col justify-center gap-1.5 bg-slate px-5"
    >
      {SEQUENCE.slice(0, shown).map((line) => (
        <p key={line} className="font-mono text-label uppercase text-mute">
          <span className="text-acid">›</span> {line}{" "}
          <span className="text-acid-dim">ok</span>
        </p>
      ))}
      {/* The cursor sits on the line still being written, so the sequence reads
          as output rather than as a list that appeared. */}
      {shown < SEQUENCE.length && (
        <p className="font-mono text-label uppercase text-mute">
          <span className="text-acid">›</span>{" "}
          <span className="inline-block h-3 w-2 animate-pulse-dot bg-acid align-middle" />
        </p>
      )}
    </div>
  );
}
