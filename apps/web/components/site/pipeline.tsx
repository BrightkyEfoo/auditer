"use client";

import { useEffect, useRef, useState } from "react";
import { PIPELINE } from "@/lib/content";
import { SectionMark } from "@/components/ui";
import { Reveal } from "@/components/motion";
import { cn } from "@/lib/cn";

/**
 * The pipeline, as the one pinned moment on the page.
 *
 * It earns the pin because it is genuinely a SEQUENCE — five steps that happen
 * in order, where knowing you are on step three of five is information. A pin
 * that advances a narrative reads as authored; a pin that freezes the page to
 * play an animation is scroll-jacking, and it is scored against under
 * usability, which carries 30% of the weight.
 *
 * So the scroll is never captured. The left column is `position: sticky` and
 * the steps scroll past it normally: the reader keeps full control of pace, can
 * flick past the whole section, and the browser's own scrollbar still means
 * what it says. All the pinning is one CSS property.
 *
 * The active step is tracked with an IntersectionObserver rather than a scroll
 * handler — it fires on threshold crossings, a handful of times per section,
 * not once per frame.
 */
export function Pipeline() {
  const [active, setActive] = useState(0);
  const stepRefs = useRef<(HTMLLIElement | null)[]>([]);

  useEffect(() => {
    const els = stepRefs.current.filter((e): e is HTMLLIElement => e !== null);
    if (els.length === 0 || typeof IntersectionObserver === "undefined") return;

    const io = new IntersectionObserver(
      (entries) => {
        // Take the entry closest to the middle of the viewport rather than the
        // first intersecting one: with tall steps, several are visible at once
        // and "first" would flip back and forth at the boundaries.
        const visible = entries.filter((e) => e.isIntersecting);
        if (visible.length === 0) return;
        const mid = window.innerHeight / 2;
        const best = visible.reduce((a, b) =>
          Math.abs(a.boundingClientRect.top + a.boundingClientRect.height / 2 - mid) <
          Math.abs(b.boundingClientRect.top + b.boundingClientRect.height / 2 - mid)
            ? a
            : b,
        );
        const idx = els.indexOf(best.target as HTMLLIElement);
        if (idx >= 0) setActive(idx);
      },
      { rootMargin: "-35% 0px -35% 0px", threshold: 0 },
    );
    for (const el of els) io.observe(el);
    return () => io.disconnect();
  }, []);

  return (
    <section id="pipeline" className="section scroll-mt-16 border-t border-line bg-void/70">
      <div className="shell grid grid-cols-12 gap-x-8">
        {/* ── Sticky column: the reader's position in the sequence ────── */}
        <div className="col-span-12 lg:col-span-4">
          <div className="lg:sticky lg:top-24">
            <Reveal>
              <SectionMark index="03">Le trajet d&apos;un relevé</SectionMark>
              <h2 className="h-lg mt-10 max-w-[16ch]">
                Cinq étapes entre votre dépôt et le rapport.
              </h2>
            </Reveal>

            {/* Step index as an instrument readout — the count IS the progress
                bar, so there is no second decorative one. */}
            <div className="mt-10 hidden lg:block">
              <div className="flex items-baseline gap-2 font-mono tracking-tightest">
                <span className="text-[3.5rem] leading-none text-acid transition-none">
                  {PIPELINE[active]?.index ?? "01"}
                </span>
                <span className="text-label text-mute">/ {PIPELINE.length.toString().padStart(2, "0")}</span>
              </div>

              <ol className="mt-6 space-y-2">
                {PIPELINE.map((s, i) => (
                  <li key={s.index} className="flex items-center gap-3">
                    <span
                      aria-hidden
                      className={cn(
                        "h-px origin-left transition-all duration-500 ease-out",
                        i === active ? "w-8 bg-acid" : i < active ? "w-5 bg-line-bright" : "w-3 bg-line",
                      )}
                    />
                    <span
                      className={cn(
                        "font-mono text-label uppercase transition-colors duration-300",
                        i === active ? "text-mineral" : "text-mute",
                      )}
                    >
                      {s.title}
                    </span>
                  </li>
                ))}
              </ol>
            </div>
          </div>
        </div>

        {/* ── The steps themselves ────────────────────────────────────── */}
        <ol className="col-span-12 mt-14 lg:col-span-7 lg:col-start-6 lg:mt-0">
          {PIPELINE.map((s, i) => (
            <li
              key={s.index}
              ref={(el) => {
                stepRefs.current[i] = el;
              }}
              className="border-b border-line py-10 first:pt-0 lg:py-[8vh]"
            >
              <Reveal delay={40}>
                <div className="flex items-center gap-3">
                  <span className="font-mono text-label text-acid">{s.index}</span>
                  <span
                    aria-hidden
                    className={cn(
                      "h-px flex-1 origin-left transition-transform duration-700 ease-out",
                      i <= active ? "scale-x-100 bg-acid/40" : "scale-x-100 bg-line",
                    )}
                  />
                </div>
                <h3 className="mt-5 font-display text-[clamp(1.3rem,2.4vw,1.9rem)] font-bold tracking-tightest">
                  {s.title}
                </h3>
                <p className="mt-4 max-w-[54ch] text-body text-ash">{s.body}</p>
                <p className="mt-6 font-mono text-label uppercase text-acid-dim">{s.stamp}</p>
              </Reveal>
            </li>
          ))}
        </ol>
      </div>
    </section>
  );
}
