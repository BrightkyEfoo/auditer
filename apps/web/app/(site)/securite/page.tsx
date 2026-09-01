import type { Metadata } from "next";
import Link from "next/link";
import { GUARANTEES } from "@/lib/content";
import { SectionMark, ButtonLink, Chip } from "@/components/ui";
import { Reveal } from "@/components/motion";

export const metadata: Metadata = {
  title: "Sécurité",
  alternates: { canonical: "/securite" },
  description:
    "Modèle de menace, isolation des scanners, traitement des données et ce que nous ne prétendons pas. Le détail des mécanismes, pas une page de conformité.",
};

/** Threat model stated plainly: what we assume hostile, and the answer to it. */
const THREATS = [
  {
    threat: "Un dépôt analysé contient du code hostile",
    answer:
      "Chaque moteur s'exécute dans son propre conteneur gVisor, détruit à la fin du scan. gVisor intercale un noyau applicatif entre le processus et l'hôte : les appels système ne touchent pas le noyau de la machine. Le conteneur tourne sans réseau, en lecture seule, sans aucune capacité Linux, sous un utilisateur non privilégié.",
  },
  {
    threat: "Un moteur open source est lui-même compromis",
    answer:
      "Nous partons du principe que l'exécution de code arbitraire est possible dans chaque sandbox, y compris via un moteur. C'est pourquoi l'isolation ne dépend pas de la confiance dans l'outil : mêmes contraintes pour tous, images épinglées par empreinte et non par étiquette mouvante, et le worker ne parle jamais au socket Docker de l'hôte — il passe par un proxy qui n'autorise que la création de conteneurs.",
  },
  {
    threat: "Un scan tente de joindre les métadonnées cloud ou le réseau interne",
    answer:
      "Les scanners statiques n'ont pas de réseau du tout. Les rares étapes qui en ont besoin sortent par un proxy qui bloque 169.254.169.254, l'ensemble des plages privées et la boucle locale, et journalise le reste. Même un modèle de détection malveillant ne peut pas atteindre ce qu'il vise.",
  },
  {
    threat: "Un dépôt tente de manipuler le modèle d'IA",
    answer:
      "Le contenu de votre dépôt est transmis au modèle encadré comme donnée non fiable, jamais comme instruction. Les modèles d'analyse n'ont accès à aucun outil à effet de bord ni au réseau. La sortie est contrainte par un schéma, et un identifiant CVE qui n'apparaît pas dans la sortie brute du scanner est rejeté à la validation.",
  },
  {
    threat: "Une organisation voit les données d'une autre",
    answer:
      "Le filtrage applicatif par organisation est doublé d'une politique PostgreSQL au niveau ligne, en refus par défaut. Un WHERE oublié dans une requête ne rend rien plutôt que de rendre les données du voisin.",
  },
  {
    threat: "Un scan de pentest vise une cible qui ne vous appartient pas",
    answer:
      "La propriété du domaine se prouve par un enregistrement DNS, et la vérification est imposée par le modèle de données, pas par l'interface. Au démarrage du scan les adresses IP sont ré-résolues puis épinglées, ce qui ferme la fenêtre de réattribution DNS. Sans preuve valide, la cible est physiquement inatteignable depuis nos sorties réseau.",
  },
];

/** Saying what we do NOT claim is what makes the rest credible. */
const NOT_CLAIMED = [
  "Nous ne sommes certifiés ni ISO 27001 ni SOC 2. Le jour où nous le serons, le rapport d'audit sera lié depuis cette page.",
  "Aucun outil ne trouve tout. L'absence de finding n'est pas une preuve d'absence de faille, et aucun rapport auditer ne le prétendra.",
  "La couverture CVE dépend de la fraîcheur des bases de vulnérabilités. La date et la provenance de la base utilisée sont inscrites dans chaque relevé.",
  "L'analyse automatique ne remplace pas un audit humain sur une application critique. Elle réduit la surface que l'humain doit couvrir.",
];

export default function SecurityPage() {
  return (
    <>
      <section className="section">
        <div className="shell">
          <Reveal>
            <SectionMark index="S1">Sécurité</SectionMark>
            <h1 className="h-xl mt-10 max-w-[18ch]">
              Nous partons du principe que chaque scan est hostile.
            </h1>
            <p className="lede mt-7">
              Analyser du code inconnu, c&apos;est exécuter des outils sur des données conçues par
              quelqu&apos;un d&apos;autre. La question n&apos;est pas de savoir si un dépôt tentera
              quelque chose, mais ce qui se passe quand il le fera. Voici les réponses,
              mécanisme par mécanisme.
            </p>
            <div className="mt-10 flex flex-wrap gap-3">
              <Chip tone="acid">runsc</Chip>
              <Chip tone="acid">cap-drop=ALL</Chip>
              <Chip tone="acid">network=none</Chip>
              <Chip tone="acid">rootfs read-only</Chip>
              <Chip tone="acid">RLS deny-by-default</Chip>
            </div>
          </Reveal>
        </div>
      </section>

      <section id="isolation" className="section scroll-mt-16 border-t border-line bg-void">
        <div className="shell">
          <Reveal>
            <SectionMark index="S2">Modèle de menace</SectionMark>
          </Reveal>
          <ul className="mt-14 border-t border-line">
            {THREATS.map((t, i) => (
              <Reveal as="li" key={t.threat} delay={i * 50}>
                <article className="grid grid-cols-12 gap-x-6 gap-y-4 border-b border-line py-8">
                  <div className="col-span-12 lg:col-span-5">
                    <div className="flex items-baseline gap-3">
                      <span className="font-mono text-label text-critical">
                        MEN.{String(i + 1).padStart(2, "0")}
                      </span>
                    </div>
                    <h2 className="mt-3 font-display text-lede font-bold tracking-display text-mineral">
                      {t.threat}
                    </h2>
                  </div>
                  <p className="col-span-12 max-w-[70ch] text-body text-ash lg:col-span-7">
                    {t.answer}
                  </p>
                </article>
              </Reveal>
            ))}
          </ul>
        </div>
      </section>

      <section id="donnees" className="section scroll-mt-16">
        <div className="shell">
          <Reveal>
            <SectionMark index="S3">Traitement des données</SectionMark>
            <h2 className="h-lg mt-12 max-w-[24ch]">
              Ce qui entre, ce qui reste, ce qui est détruit.
            </h2>
          </Reveal>

          <div className="mt-14 grid grid-cols-1 gap-px bg-line md:grid-cols-2 lg:grid-cols-3">
            {GUARANTEES.map((g, i) => (
              <Reveal key={g.stamp} delay={i * 45} className="bg-carbon">
                <div className="h-full p-7">
                  <span className="label text-acid">{g.stamp}</span>
                  <h3 className="mt-5 font-display text-lede font-bold tracking-display">
                    {g.title}
                  </h3>
                  <p className="mt-3 text-data text-mute">{g.body}</p>
                </div>
              </Reveal>
            ))}
          </div>

          <Reveal delay={100}>
            <p className="mt-10 max-w-[70ch] text-data text-mute">
              Le détail des durées de conservation, des sous-traitants et de vos droits figure
              dans la{" "}
              <Link href="/legal/confidentialite" className="ul-draw text-acid">
                politique de confidentialité
              </Link>
              . Pour un usage en entreprise, l&apos;
              <Link href="/legal/dpa" className="ul-draw text-acid">
                accord de sous-traitance
              </Link>{" "}
              décrit les engagements au titre de l&apos;article 28 du RGPD.
            </p>
          </Reveal>
        </div>
      </section>

      <section className="section border-t border-line bg-void">
        <div className="shell grid grid-cols-12 gap-y-10">
          <div className="col-span-12 lg:col-span-4">
            <Reveal>
              <SectionMark index="S4">Limites assumées</SectionMark>
              <h2 className="h-md mt-10 max-w-[16ch]">
                Ce que nous ne prétendons <span className="text-acid">pas</span>.
              </h2>
            </Reveal>
          </div>
          <ul className="col-span-12 space-y-5 lg:col-span-7 lg:col-start-6">
            {NOT_CLAIMED.map((n, i) => (
              <Reveal as="li" key={n} delay={i * 60}>
                <div className="flex gap-4 border-l border-line pl-5">
                  <p className="max-w-[68ch] text-body text-ash">{n}</p>
                </div>
              </Reveal>
            ))}
          </ul>
        </div>
      </section>

      <section className="section">
        <div className="shell">
          <Reveal>
            <div className="border border-line-bright bg-slate px-7 py-9">
              <SectionMark index="S5">Divulgation responsable</SectionMark>
              <h2 className="h-md mt-8 max-w-[26ch]">
                Vous avez trouvé une faille chez nous ? Dites-le-nous.
              </h2>
              <p className="lede mt-5">
                Accusé de réception sous 72 heures. Aucune poursuite contre un signalement de
                bonne foi, sans exfiltration de données ni dégradation du service.
              </p>
              <div className="mt-8">
                <ButtonLink href="mailto:legal@auditer.brightkyefoo.cm" variant="primary">
                  legal@auditer.brightkyefoo.cm
                </ButtonLink>
              </div>
            </div>
          </Reveal>
        </div>
      </section>
    </>
  );
}
