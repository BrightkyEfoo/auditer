import type { Metadata } from "next";
import { notFound } from "next/navigation";
import Link from "next/link";
import { LEGAL_DOCS, LEGAL_SLUGS } from "@/lib/legal";
import { SectionMark } from "@/components/ui";
import { Reveal } from "@/components/motion";

export function generateStaticParams() {
  return LEGAL_SLUGS.map((slug) => ({ slug }));
}

const SITE = process.env.WEB_URL ?? "https://auditer.brightkyefoo.cm";

export async function generateMetadata({
  params,
}: {
  params: Promise<{ slug: string }>;
}): Promise<Metadata> {
  const { slug } = await params;
  const doc = LEGAL_DOCS[slug];
  if (!doc) return {};
  return {
    title: doc.title,
    description: doc.summary,
    alternates: { canonical: `/legal/${slug}` },
    // Legal pages must be indexable and stable, but they are never the entry
    // point we optimise for.
    robots: { index: true, follow: true },
  };
}

/**
 * One renderer for every legal document. The documents themselves are pure
 * data (lib/legal.ts) so the wording can be reviewed without touching layout,
 * and so the "last updated" stamp cannot drift out of the page it describes.
 */
export default async function LegalPage({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  const doc = LEGAL_DOCS[slug];
  if (!doc) notFound();

  return (
    <article className="section">
      <div className="shell grid grid-cols-12 gap-y-12">
        <header className="col-span-12">
          {/* Fil d'Ariane VISIBLE d'abord, balisé ensuite. Un BreadcrumbList
              qui décrit un chemin absent de la page est du balisage qui ne
              correspond pas au contenu — précisément ce que les consignes de
              Google sanctionnent. Ici les deux disent la même chose. */}
          <nav aria-label="Fil d'Ariane" className="mb-8">
            <ol className="flex flex-wrap items-center gap-2 font-mono text-label uppercase text-mute">
              <li>
                <Link href="/" className="ul-draw hover:text-mineral">
                  Accueil
                </Link>
              </li>
              <li aria-hidden>/</li>
              <li className="text-ash">Légal</li>
              <li aria-hidden>/</li>
              {/* `aria-current` : la dernière miette est la page courante, et
                  n'est donc pas un lien. */}
              <li aria-current="page" className="text-mineral">
                {doc.title}
              </li>
            </ol>
          </nav>

          <script
            type="application/ld+json"
            dangerouslySetInnerHTML={{
              __html: JSON.stringify({
                "@context": "https://schema.org",
                "@type": "BreadcrumbList",
                itemListElement: [
                  { "@type": "ListItem", position: 1, name: "Accueil", item: SITE },
                  { "@type": "ListItem", position: 2, name: doc.title, item: `${SITE}/legal/${slug}` },
                ],
              }).replace(/</g, "\\u003c"),
            }}
          />

          <Reveal>
            <SectionMark index={doc.index}>Document légal</SectionMark>
            <h1 className="h-xl mt-10 max-w-[20ch]">{doc.title}</h1>
            <p className="lede mt-6">{doc.summary}</p>
            <p className="mt-8 flex flex-wrap gap-x-6 gap-y-2 border-t border-line pt-4 font-mono text-label uppercase text-mute">
              <span>Version {doc.version}</span>
              <span>Mise à jour : {doc.updated}</span>
              <span>Droit applicable : {doc.law}</span>
            </p>
          </Reveal>
        </header>

        {/* Sticky table of contents on the left, prose on the right. Long legal
            text without a map is text nobody reads. */}
        <nav aria-label="Sommaire" className="col-span-12 lg:col-span-3">
          <div className="lg:sticky lg:top-24">
            <p className="label text-mute">Sommaire</p>
            <ol className="mt-4 space-y-2">
              {doc.sections.map((s, i) => (
                <li key={s.heading}>
                  <a
                    href={`#s${i + 1}`}
                    className="ul-draw font-mono text-label uppercase text-ash transition-colors duration-[180ms] hover:text-mineral"
                  >
                    {String(i + 1).padStart(2, "0")} · {s.heading}
                  </a>
                </li>
              ))}
            </ol>
            <div className="mt-8 border-t border-line pt-4">
              <p className="label text-mute">Autres documents</p>
              <ul className="mt-3 space-y-2">
                {LEGAL_SLUGS.filter((s) => s !== slug && LEGAL_DOCS[s]).map((s) => (
                  <li key={s}>
                    <Link
                      href={`/legal/${s}`}
                      className="ul-draw text-data text-mute transition-colors duration-[180ms] hover:text-mineral"
                    >
                      {LEGAL_DOCS[s]!.title}
                    </Link>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </nav>

        <div className="col-span-12 lg:col-span-8 lg:col-start-5">
          {doc.sections.map((s, i) => (
            <section
              key={s.heading}
              id={`s${i + 1}`}
              className="scroll-mt-24 border-t border-line py-9 first:border-t-0 first:pt-0"
            >
              <div className="flex items-baseline gap-3">
                <span className="font-mono text-label text-acid">
                  {String(i + 1).padStart(2, "0")}
                </span>
                <h2 className="h-md">{s.heading}</h2>
              </div>
              <div className="mt-5 space-y-4 pl-0 sm:pl-8">
                {s.body.map((block, j) =>
                  Array.isArray(block) ? (
                    <ul key={j} className="space-y-2.5">
                      {block.map((li) => (
                        <li key={li} className="flex gap-3 text-body text-ash">
                          <span aria-hidden className="mt-2.5 h-px w-3 shrink-0 bg-acid" />
                          <span className="max-w-[70ch]">{li}</span>
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <p key={j} className="max-w-[72ch] text-body text-ash">
                      {block}
                    </p>
                  ),
                )}
              </div>
            </section>
          ))}

          <p className="mt-10 border-t border-line pt-5 font-mono text-label uppercase leading-relaxed text-mute">
            Question sur ce document ? Écrivez à{" "}
            <a href="mailto:legal@auditer.brightkyefoo.cm" className="ul-draw text-acid">
              legal@auditer.brightkyefoo.cm
            </a>
          </p>
        </div>
      </div>
    </article>
  );
}
