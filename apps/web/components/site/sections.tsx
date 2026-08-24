import { ENGINES, PILLARS, GUARANTEES } from "@/lib/content";
import { SectionMark, ButtonLink, Chip } from "@/components/ui";
import { Reveal, Parallax } from "@/components/motion";

/* ── [01] Engines ───────────────────────────────────────────────────────── */

/**
 * Honest social proof for a product without customer logos yet: the engines it
 * actually runs. This list mirrors the engine registry exactly — padding it
 * with tools we do not execute would be the one lie a security product cannot
 * afford.
 */
export function Engines() {
  const row = [...ENGINES, ...ENGINES];
  return (
    <section className="border-y border-line bg-void py-7">
      <div className="shell mb-6 flex flex-wrap items-baseline gap-x-4 gap-y-1">
        <span className="label text-acid">Huit moteurs</span>
        <span className="font-mono text-label uppercase text-mute">
          open source, épinglés par empreinte, exécutés en sandbox
        </span>
      </div>
      <div className="marquee-hold relative overflow-hidden">
        <div className="marquee" aria-hidden>
          {row.map((tool, i) => (
            <span
              key={`${tool}-${i}`}
              className="flex shrink-0 items-center gap-6 whitespace-nowrap px-6 font-display text-[1.35rem] font-medium tracking-display text-ash"
            >
              {tool}
              <span className="h-1 w-1 bg-acid" />
            </span>
          ))}
        </div>
        {/* Fade the edges into the ground so the loop has no hard cut. */}
        <div className="pointer-events-none absolute inset-y-0 left-0 w-24 bg-gradient-to-r from-void to-transparent" />
        <div className="pointer-events-none absolute inset-y-0 right-0 w-24 bg-gradient-to-l from-void to-transparent" />
      </div>
      <p className="sr-only">Moteurs utilisés : {ENGINES.join(", ")}.</p>
    </section>
  );
}

/* ── [02] Pillars ───────────────────────────────────────────────────────── */

/**
 * A dense typographic index, not seven identical cards. Every row carries a
 * claim you could argue with — vague feature blurbs are what make SaaS pages
 * interchangeable.
 */
export function Pillars() {
  return (
    <section id="piliers" className="section scroll-mt-16">
      <div className="shell">
        <Reveal>
          <SectionMark index="02">Ce qui est mesuré</SectionMark>
        </Reveal>

        <Reveal delay={80}>
          <h2 className="h-xl mt-12 max-w-[18ch]">
            Sept piliers. Un seul relevé, une seule échelle.
          </h2>
          <p className="lede mt-6">
            Un rapport par outil, c&apos;est sept rapports à recouper. Ici tout converge vers un
            modèle de finding unique, dédupliqué entre les moteurs, noté sur la même règle.
          </p>
        </Reveal>

        <ul className="mt-16 border-t border-line">
          {PILLARS.map((p, i) => (
            <Reveal as="li" key={p.id} delay={i * 55}>
              <article className="group relative grid grid-cols-12 items-baseline gap-x-4 gap-y-3 border-b border-line py-8 transition-colors duration-[180ms] hover:bg-slate/60">
                {/* Three properties, one gesture: the rail traces down, the
                    index steps aside to let it through, and the ground lifts.
                    Juries single out hover states far more often than scroll
                    reveals — this is where the motion budget belongs. */}
                <span aria-hidden className="row-mark" />

                <span className="idx-shift col-span-2 font-mono text-label text-acid sm:col-span-1">
                  [{p.index}]
                </span>

                <h3 className="col-span-10 font-display text-[clamp(1.4rem,3vw,2rem)] font-bold leading-none tracking-tightest sm:col-span-4">
                  {p.name}
                </h3>

                <div className="col-span-12 sm:col-span-7 sm:pl-6">
                  <p className="text-lede font-medium text-mineral">{p.claim}</p>
                  <p className="mt-2.5 max-w-[62ch] text-data text-mute">{p.detail}</p>
                  <div className="mt-4 flex flex-wrap items-center gap-2">
                    {p.tools.map((t) => (
                      <Chip key={t}>{t}</Chip>
                    ))}
                    {p.network && <Chip tone="warn">cible vérifiée requise</Chip>}
                  </div>
                </div>
              </article>
            </Reveal>
          ))}
        </ul>
      </div>
    </section>
  );
}

/* ── [04] Engine ────────────────────────────────────────────────────────── */

/**
 * The strongest differentiator gets the most editorial weight: the AI is
 * downstream of the measurement, never upstream of the number. Split layout,
 * deliberately unaligned columns.
 */
export function Engine() {
  return (
    <section id="moteur" className="section scroll-mt-16">
      <div className="shell grid grid-cols-12 gap-y-14">
        <div className="col-span-12 lg:col-span-6">
          <Reveal>
            <SectionMark index="04">Moteur hybride</SectionMark>
          </Reveal>
          <Reveal delay={80}>
            <h2 className="h-xl mt-12 max-w-[14ch]">
              L&apos;IA explique. Elle ne décide <span className="text-acid">jamais</span> du
              score.
            </h2>
            <p className="lede mt-7">
              Un modèle qui note lui-même ce qu&apos;il a trouvé produit un chiffre différent à
              chaque exécution. Chez nous la détection appartient aux outils, la note à une
              formule, et le texte au modèle — dans cet ordre, sans exception.
            </p>
            <div className="mt-10">
              <ButtonLink href="/securite">Comment c&apos;est isolé</ButtonLink>
            </div>
          </Reveal>
        </div>

        <div className="col-span-12 lg:col-span-5 lg:col-start-8">
          <Parallax speed={-0.05}>
            <Reveal delay={120}>
              <div className="border border-line-bright bg-slate">
                <header className="border-b border-line px-5 py-3">
                  <span className="label text-mute">Ordre d&apos;exécution — verrouillé</span>
                </header>
                <ol className="divide-y divide-line">
                  {[
                    {
                      k: "Détection",
                      v: "Les moteurs open source produisent les faits. Un finding sans outil derrière lui n'existe pas.",
                    },
                    {
                      k: "Déduplication",
                      v: "Empreinte stable par finding, regroupement entre outils. Trois moteurs qui voient la même faille rendent une ligne.",
                    },
                    {
                      k: "Notation",
                      v: "Déduction pondérée par gravité, densité par millier de lignes, plafonds durs. Version du barème inscrite dans le relevé.",
                    },
                    {
                      k: "Rédaction",
                      v: "Le modèle explique l'exploitabilité et propose une remédiation, contraint par un schéma, sans accès au score.",
                    },
                  ].map((r, i) => (
                    <li key={r.k} className="px-5 py-4">
                      <div className="flex items-baseline gap-3">
                        <span className="font-mono text-label text-acid">
                          {String(i + 1).padStart(2, "0")}
                        </span>
                        <span className="font-display font-bold tracking-display text-mineral">
                          {r.k}
                        </span>
                      </div>
                      <p className="mt-2 pl-8 text-data text-mute">{r.v}</p>
                    </li>
                  ))}
                </ol>
                <footer className="border-t border-line px-5 py-3.5 font-mono text-label uppercase text-mute">
                  Un identifiant CVE inventé par le modèle est rejeté à la validation
                </footer>
              </div>
            </Reveal>
          </Parallax>
        </div>
      </div>
    </section>
  );
}

/* ── [05] Guarantees ────────────────────────────────────────────────────── */

/**
 * Security surfaces are treated as a product feature, on the marketing page,
 * with the mechanism named — not as a compliance footnote.
 */
export function Guarantees() {
  return (
    <section className="section border-t border-line bg-void">
      <div className="shell">
        <Reveal>
          <SectionMark index="05">Ce qu&apos;on vous garantit</SectionMark>
        </Reveal>

        <Reveal delay={80}>
          <h2 className="h-xl mt-12 max-w-[22ch]">
            Vous nous confiez du code privé. Voici exactement ce qu&apos;il devient.
          </h2>
        </Reveal>

        <div className="mt-16 grid grid-cols-1 gap-px bg-line md:grid-cols-2 lg:grid-cols-3">
          {GUARANTEES.map((g, i) => (
            <Reveal key={g.stamp} delay={i * 55} className="bg-void">
              <div className="h-full p-7">
                <span className="label text-acid">{g.stamp}</span>
                <h3 className="mt-5 font-display text-lede font-bold tracking-display">{g.title}</h3>
                <p className="mt-3 text-data text-mute">{g.body}</p>
              </div>
            </Reveal>
          ))}
        </div>

        <Reveal delay={120}>
          <p className="mt-10 max-w-[70ch] font-mono text-label uppercase leading-relaxed text-mute">
            Aucune de ces lignes n&apos;est une intention : chacune correspond à un mécanisme
            décrit sur la page{" "}
            <a href="/securite" className="ul-draw text-acid">
              sécurité
            </a>
            , avec le composant qui l&apos;applique.
          </p>
        </Reveal>
      </div>
    </section>
  );
}
