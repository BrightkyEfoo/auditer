import Link from "next/link";
import type { Metadata } from "next";
import { ButtonLink, Label, Wordmark } from "@/components/ui";

/**
 * Page 404.
 *
 * Placée à la racine de `app/` et non dans un groupe : c'est la seule position
 * que Next utilise pour les URL qui ne correspondent à AUCUN segment. Une
 * `not-found.tsx` rangée sous `(site)/` ne couvrirait que les chemins déjà
 * routés vers ce groupe, et une URL inventée retomberait sur la page par
 * défaut du framework.
 *
 * Le statut HTTP est bien 404 — Next le pose lui-même sur ce fichier. C'est le
 * point qui compte pour un crawler : une page d'erreur servie en 200 est une
 * « soft 404 », indexée comme du contenu et diluant le reste du site.
 */
export const metadata: Metadata = {
  title: "Page introuvable",
  // Une page d'erreur n'a rien à faire dans un index, et sa canonique
  // n'existerait pas : `noindex` est le seul traitement correct.
  robots: { index: false, follow: true },
};

/** Les seules destinations qui valent d'être proposées ici. Pas un plan du
 *  site : trois portes, choisies pour couvrir les trois raisons d'arriver sur
 *  une URL morte — on cherchait le produit, le prix, ou une garantie. */
const WAYS_OUT = [
  { href: "/", label: "Accueil", hint: "ce que fait auditer, en sept piliers" },
  { href: "/tarifs", label: "Tarifs", hint: "ce que coûte un relevé" },
  { href: "/securite", label: "Sécurité", hint: "le modèle de menace, en clair" },
];

export default function NotFound() {
  return (
    <main className="shell section flex min-h-[70vh] flex-col justify-center">
      <Link href="/" aria-label="auditer — accueil" className="w-fit">
        <Wordmark className="text-mineral" />
      </Link>

      <div className="mt-14 grid grid-cols-12 items-end gap-y-8">
        {/* Le code d'erreur est traité comme une mesure, pas comme une
            illustration : même échelle et même graisse que les scores du
            produit. La page d'erreur appartient au même instrument. */}
        <div className="col-span-12 lg:col-span-5">
          <Label className="text-acid">Erreur</Label>
          <p className="display mt-4 text-mineral tabular-nums">404</p>
        </div>

        <div className="col-span-12 lg:col-span-6 lg:col-start-7">
          <h1 className="h-lg text-mineral">Cette page n&apos;existe pas</h1>
          <p className="lede mt-5">
            L&apos;adresse demandée ne correspond à aucun document de ce site. Le lien qui
            vous a amené ici est peut-être périmé, ou l&apos;adresse a été saisie à la main.
          </p>
        </div>
      </div>

      <ul className="mt-16 border-t border-line">
        {WAYS_OUT.map((w, i) => (
          <li key={w.href}>
            <Link
              href={w.href}
              className="group relative flex items-baseline gap-5 border-b border-line py-5"
            >
              <span aria-hidden className="row-mark" />
              <span className="idx-shift font-mono text-label uppercase text-mute">
                [{String(i + 1).padStart(2, "0")}]
              </span>
              <span className="min-w-0 flex-1">
                <span className="ul-draw font-mono text-data text-mineral">{w.label}</span>
                <span className="mt-1 block font-mono text-label uppercase text-mute">
                  {w.hint}
                </span>
              </span>
              <span className="arrow-swap font-mono text-data text-acid" aria-hidden>
                <span>→</span>
                <span>→</span>
              </span>
            </Link>
          </li>
        ))}
      </ul>

      <div className="mt-12">
        <ButtonLink href="/inscription">Lancer un relevé</ButtonLink>
      </div>
    </main>
  );
}
