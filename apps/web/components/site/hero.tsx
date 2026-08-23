"use client";

import { ButtonLink } from "@/components/ui";
import { Parallax, Scramble, ScrollReadout } from "@/components/motion";

/**
 * Hero as a typographic poster with a real instrument readout beside it.
 *
 * The panel is not an abstract illustration: it is the shape of an actual
 * auditer report, F-ceiling included. Showing the product beats promising it,
 * and it kills the "vague promise + three feature cards" fold.
 */

const BREAKDOWN = [
  { label: "critique", n: 2, cls: "bg-critical", w: "18%" },
  { label: "élevé", n: 4, cls: "bg-high", w: "34%" },
  { label: "moyen", n: 7, cls: "bg-medium", w: "60%" },
  { label: "faible", n: 3, cls: "bg-low", w: "26%" },
];

export function Hero() {
  return (
    <section className="relative min-h-[100svh] overflow-hidden pb-16 pt-32 md:pt-40">
      {/* Ruled background. It lags behind the content on scroll, which is what
          gives the fold its depth — no blurred blobs involved. */}
      <div aria-hidden className="pointer-events-none absolute inset-0 -z-10">
        <Parallax speed={0.16} className="absolute inset-0 -top-32 h-[130%]">
          <div className="ruled h-full opacity-60" />
          <div className="absolute inset-x-0 bottom-0 h-1/2 bg-gradient-to-b from-transparent to-carbon" />
        </Parallax>
      </div>

      <div className="shell grid grid-cols-12 items-start gap-y-14">
        {/* ── Poster ─────────────────────────────────────────────────── */}
        <div className="col-span-12 lg:col-span-7">
          <p className="label flex flex-wrap items-center gap-x-3 gap-y-1 text-mute">
            <span className="text-acid">SYS.AUDITER</span>
            <span aria-hidden className="h-px w-6 bg-line-bright" />
            <span>Relevé complet</span>
            <span aria-hidden className="h-px w-6 bg-line-bright" />
            <span>07 piliers</span>
          </p>

          <h1 className="display mt-7">
            <span className="block">Votre code,</span>
            <span className="block pl-[8%] text-ash">mis sous</span>
            <span className="block text-acid">instrument.</span>
          </h1>

          <p className="lede mt-9">
            Secrets exposés, CVE, failles statiques, dette, hygiène du dépôt, pentest web et
            accessibilité. Huit moteurs open source dans une sandbox à noyau isolé, un score
            calculé par une formule versionnée, et une explication écrite pour être lue par un
            humain pressé.
          </p>

          <div className="mt-11 flex flex-wrap items-center gap-x-6 gap-y-4">
            <ButtonLink href="/inscription" variant="primary" size="lg">
              Créer un compte
            </ButtonLink>
            <a
              href="#piliers"
              className="ul-draw font-mono text-label uppercase text-ash transition-colors duration-[180ms] hover:text-mineral"
            >
              Voir ce qui est mesuré →
            </a>
          </div>

          <p className="mt-6 font-mono text-label uppercase text-mute">
            Sans carte bancaire · Le code source n&apos;est jamais conservé
          </p>
        </div>

        {/* ── Readout ────────────────────────────────────────────────── */}
        <div className="col-span-12 lg:col-span-5 lg:pl-[6%]">
          <Parallax speed={-0.07}>
            <div className="ticked relative border border-line-bright bg-slate">
              {/* Scan sweep — the one ambient animation on the page. */}
              <div aria-hidden className="pointer-events-none absolute inset-0 overflow-hidden">
                <div className="h-px w-full animate-sweep-y bg-acid/25" />
              </div>

              <header className="flex items-center justify-between border-b border-line px-5 py-3">
                <span className="label text-acid">Relevé A7F3</span>
                <span className="label text-mute">terminé · 4 min 12 s</span>
              </header>

              <dl className="grid grid-cols-2 gap-x-4 gap-y-3 border-b border-line px-5 py-4 font-mono text-label uppercase">
                <div>
                  <dt className="text-mute">Dépôt</dt>
                  <dd className="mt-1 normal-case tracking-normal text-mineral">acme/api-gateway</dd>
                </div>
                <div>
                  <dt className="text-mute">Commit</dt>
                  <dd className="mt-1 normal-case tracking-normal text-mineral">4f2a91c</dd>
                </div>
              </dl>

              <div className="flex items-end justify-between px-5 py-7">
                <div>
                  <span className="label text-mute">Score global</span>
                  <div className="mt-2 flex items-baseline gap-1.5">
                    <span className="font-display text-[3.5rem] font-bold leading-none tracking-tightest text-mineral">
                      <Scramble text="58" />
                    </span>
                    <span className="font-mono text-data text-mute">/100</span>
                  </div>
                </div>
                <div className="text-right">
                  <span className="label text-mute">Note</span>
                  <div className="mt-2 font-display text-[3.5rem] font-bold leading-none text-critical">
                    F
                  </div>
                </div>
              </div>

              <div className="space-y-2.5 border-t border-line px-5 py-5">
                {BREAKDOWN.map((b) => (
                  <div key={b.label} className="flex items-center gap-3">
                    <span className="label w-16 shrink-0 text-mute">{b.label}</span>
                    <span className="h-1.5 flex-1 bg-line">
                      <span className={`block h-full ${b.cls}`} style={{ width: b.w }} />
                    </span>
                    <span className="w-5 shrink-0 text-right font-mono text-data text-ash">{b.n}</span>
                  </div>
                ))}
              </div>

              <footer className="border-t border-line px-5 py-3.5">
                <p className="font-mono text-label uppercase leading-relaxed text-mute">
                  Plafond appliqué —{" "}
                  <span className="text-critical">1 critique ouvert force la note F</span>
                </p>
              </footer>
            </div>
          </Parallax>
        </div>
      </div>

      {/* Instrument strip at the bottom of the fold. */}
      <div className="shell mt-16 flex items-center justify-between border-t border-line pt-4 font-mono text-label uppercase text-mute">
        <span className="flex items-center gap-2">
          <span className="h-1.5 w-1.5 animate-pulse-dot bg-acid" aria-hidden />
          Défilement
        </span>
        <span className="hidden sm:inline">Isolation runsc · Sortie réseau coupée</span>
        <span>
          <ScrollReadout /> %
        </span>
      </div>
    </section>
  );
}
