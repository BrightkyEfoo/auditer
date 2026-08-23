import type { Metadata } from "next";
import Link from "next/link";
import { SectionMark, ButtonLink, Chip } from "@/components/ui";
import { Reveal } from "@/components/motion";

export const metadata: Metadata = {
  title: "Tarifs",
  description:
    "auditer est gratuit pendant la phase actuelle : les sept piliers, sans carte bancaire. Ce qui deviendra payant, et quand, est annoncé ici.",
};

/**
 * Honest pricing for a product that does not bill yet. Inventing three tiers
 * with numbers we have not decided would be the fastest way to lose the trust
 * the rest of the site spends its time building.
 */
const PLANS = [
  {
    name: "Découverte",
    price: "Gratuit",
    status: "Disponible",
    tone: "acid" as const,
    pitch: "La phase actuelle. Tout est ouvert, rien n'est facturé.",
    features: [
      "Les 7 piliers, sans restriction",
      "Dépôts publics et privés",
      "GitHub App et OAuth GitLab",
      "Triage persistant entre les relevés",
      "Export du rapport",
      "Historique des relevés conservé 24 mois",
    ],
    cta: { href: "/inscription", label: "Créer un compte", variant: "primary" as const },
  },
  {
    name: "Équipe",
    price: "À venir",
    status: "En construction",
    tone: "neutral" as const,
    pitch:
      "Ce que nous construisons ensuite : plusieurs membres, relevés déclenchés à chaque push, seuils bloquants en CI.",
    features: [
      "Organisations à plusieurs membres et rôles",
      "Relevé automatique sur push et pull request",
      "Seuils de blocage en intégration continue",
      "Comparaison de relevés et suivi de tendance",
      "Rapports à votre marque",
    ],
    cta: { href: "/inscription", label: "Être prévenu", variant: "ghost" as const },
  },
  {
    name: "Entreprise",
    price: "Sur mesure",
    status: "Sur demande",
    tone: "neutral" as const,
    pitch:
      "Instance dédiée, exigences contractuelles, GitLab auto-hébergé. Ces cas se discutent, ils ne se configurent pas dans un formulaire.",
    features: [
      "Déploiement isolé ou sur votre infrastructure",
      "GitLab auto-hébergé",
      "Accord de sous-traitance négocié",
      "Rétention et localisation des données au contrat",
      "Interlocuteur dédié",
    ],
    cta: {
      href: "mailto:legal@auditer.brightkyefoo.cm",
      label: "Nous écrire",
      variant: "ghost" as const,
    },
  },
];

const FAQ = [
  {
    q: "Pourquoi c'est gratuit ?",
    a: "Parce que le produit est jeune et que nous avons davantage besoin de relevés réels que de revenus immédiats. Rien n'est bridé pour autant : les sept piliers tournent à l'identique pour tout le monde.",
  },
  {
    q: "Que se passera-t-il quand la facturation arrivera ?",
    a: "Les comptes existants seront prévenus au moins trente jours à l'avance, avec le détail de ce qui devient payant. Aucun relevé déjà produit ne sera rendu inaccessible.",
  },
  {
    q: "Mes dépôts privés sont-ils traités différemment ?",
    a: "Non. Public ou privé, le clone est éphémère, le scan est isolé et le code source n'est jamais écrit dans le stockage durable. La visibilité du dépôt ne change rien au traitement.",
  },
  {
    q: "Y a-t-il une limite au nombre de relevés ?",
    a: "Pas de quota formel pendant la phase actuelle. Les relevés sont mis en file d'attente et exécutés dans l'ordre ; un usage manifestement abusif peut être ralenti, ce qui n'est jamais arrivé à un utilisateur normal.",
  },
];

export default function PricingPage() {
  return (
    <>
      <section className="section">
        <div className="shell">
          <Reveal>
            <SectionMark index="T1">Tarifs</SectionMark>
            <h1 className="h-xl mt-10 max-w-[16ch]">
              Gratuit tant que le produit est jeune.
            </h1>
            <p className="lede mt-7">
              Pas de version bridée, pas de pilier réservé à une offre supérieure, pas de carte
              bancaire à l&apos;inscription. Quand la facturation arrivera, elle sera annoncée
              trente jours avant, sur cette page.
            </p>
          </Reveal>

          <div className="mt-16 grid grid-cols-1 gap-px bg-line lg:grid-cols-3">
            {PLANS.map((p, i) => (
              <Reveal key={p.name} delay={i * 70} className="bg-carbon">
                <div className="flex h-full flex-col p-8">
                  <div className="flex items-center justify-between">
                    <h2 className="font-display text-lede font-bold tracking-display">{p.name}</h2>
                    <Chip tone={p.tone}>{p.status}</Chip>
                  </div>

                  <p className="mt-8 font-display text-[2.5rem] font-bold leading-none tracking-tightest">
                    {p.price}
                  </p>
                  <p className="mt-4 min-h-[4.5rem] max-w-[34ch] text-data text-mute">{p.pitch}</p>

                  <ul className="mt-8 flex-1 space-y-3 border-t border-line pt-7">
                    {p.features.map((f) => (
                      <li key={f} className="flex gap-3 text-data text-ash">
                        <span aria-hidden className="mt-2 h-px w-3 shrink-0 bg-acid" />
                        <span>{f}</span>
                      </li>
                    ))}
                  </ul>

                  <div className="mt-9">
                    <ButtonLink href={p.cta.href} variant={p.cta.variant} className="w-full justify-center">
                      {p.cta.label}
                    </ButtonLink>
                  </div>
                </div>
              </Reveal>
            ))}
          </div>
        </div>
      </section>

      <section className="section border-t border-line bg-void">
        <div className="shell grid grid-cols-12 gap-y-10">
          <div className="col-span-12 lg:col-span-4">
            <Reveal>
              <SectionMark index="T2">Questions</SectionMark>
              <h2 className="h-md mt-10 max-w-[14ch]">Les questions qu&apos;on nous pose.</h2>
            </Reveal>
          </div>

          <dl className="col-span-12 border-t border-line lg:col-span-7 lg:col-start-6">
            {FAQ.map((f, i) => (
              <Reveal key={f.q} delay={i * 55}>
                <div className="border-b border-line py-7">
                  <dt className="flex items-baseline gap-3">
                    <span className="font-mono text-label text-acid">
                      {String(i + 1).padStart(2, "0")}
                    </span>
                    <span className="font-display text-lede font-bold tracking-display text-mineral">
                      {f.q}
                    </span>
                  </dt>
                  <dd className="mt-3 max-w-[66ch] pl-8 text-body text-ash">{f.a}</dd>
                </div>
              </Reveal>
            ))}
          </dl>

          <p className="col-span-12 font-mono text-label uppercase text-mute lg:col-span-7 lg:col-start-6">
            Une question qui n&apos;est pas là ?{" "}
            <Link href="mailto:legal@auditer.brightkyefoo.cm" className="ul-draw text-acid">
              Écrivez-nous
            </Link>
          </p>
        </div>
      </section>
    </>
  );
}
