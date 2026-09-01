import Link from "next/link";
import { Wordmark, ButtonLink, Label } from "@/components/ui";
import { Reveal } from "@/components/motion";

const COLUMNS: Array<{ title: string; links: Array<{ href: string; label: string }> }> = [
  {
    title: "Produit",
    links: [
      { href: "/#piliers", label: "Les 7 piliers" },
      { href: "/#pipeline", label: "Le pipeline" },
      { href: "/#moteur", label: "Moteur hybride" },
      { href: "/tarifs", label: "Tarifs" },
    ],
  },
  {
    title: "Confiance",
    links: [
      { href: "/securite", label: "Sécurité" },
      { href: "/securite#isolation", label: "Isolation des scans" },
      { href: "/securite#donnees", label: "Traitement des données" },
      { href: "/legal/dpa", label: "Sous-traitance (RGPD)" },
    ],
  },
  {
    title: "Légal",
    links: [
      { href: "/legal/confidentialite", label: "Confidentialité" },
      { href: "/legal/cgu", label: "Conditions d'utilisation" },
      { href: "/legal/cookies", label: "Cookies" },
      { href: "/legal/mentions", label: "Mentions légales" },
    ],
  },
  {
    title: "Compte",
    links: [
      { href: "/inscription", label: "Créer un compte" },
      { href: "/connexion", label: "Connexion" },
      { href: "/tableau-de-bord", label: "Tableau de bord" },
    ],
  },
];

export function SiteFooter() {
  return (
    <footer className="border-t border-line bg-void/80">
      {/* The footer opens with the final call, at poster scale. It is a page,
          not a dump of links. */}
      <div className="shell border-b border-line py-[clamp(4rem,10vh,8rem)]">
        <Reveal>
          <p className="label mb-8 text-mute">[07] Dernière ligne</p>
          <h2 className="h-xl max-w-[16ch]">
            Le premier relevé prend
            <span className="text-acid"> quatre minutes</span>.
          </h2>
          <div className="mt-10 flex flex-wrap items-center gap-4">
            <ButtonLink href="/inscription" variant="primary" size="lg">
              Créer un compte
            </ButtonLink>
            <span className="font-mono text-label uppercase text-mute">
              Sans carte bancaire · 7 piliers inclus
            </span>
          </div>
        </Reveal>
      </div>

      <div className="shell grid grid-cols-2 gap-x-8 gap-y-10 py-16 md:grid-cols-5">
        <div className="col-span-2 md:col-span-1">
          <Wordmark className="text-mineral" />
          <p className="mt-4 max-w-[24ch] text-data text-mute">
            Le relevé complet de votre code. Sept piliers, un seul rapport.
          </p>
        </div>

        {COLUMNS.map((col) => (
          <nav key={col.title} aria-label={col.title}>
            <Label className="text-mute">{col.title}</Label>
            <ul className="mt-4 space-y-2.5">
              {col.links.map((l) => (
                <li key={l.href + l.label}>
                  <Link
                    href={l.href}
                    className="ul-draw text-data text-ash transition-colors duration-[180ms] hover:text-mineral"
                  >
                    {l.label}
                  </Link>
                </li>
              ))}
            </ul>
          </nav>
        ))}
      </div>

      {/* Instrument footer stamp: status, version, coordinates. */}
      <div className="shell flex flex-col gap-3 border-t border-line py-6 font-mono text-label uppercase text-mute sm:flex-row sm:items-center sm:justify-between">
        <span>© {new Date().getFullYear()} auditer</span>
        <span className="flex items-center gap-2">
          <span className="h-1.5 w-1.5 animate-pulse-dot bg-acid" aria-hidden />
          Statut : opérationnel
        </span>
        <span>Scoring v1 · Sandbox gVisor · Douala, CM</span>
      </div>
    </footer>
  );
}
