import Link from "next/link";
import { PageHead } from "@/components/app/shell";
import { ButtonLink, Label, Chip } from "@/components/ui";
import { getSession, apiGet } from "@/lib/session";
import { ACCOUNT_EXPORT_PATH, type Connection } from "@/lib/api";
import { DeleteAccount, RevokeConnection } from "./account-actions";

export const dynamic = "force-dynamic";

const PROVIDER_FR: Record<string, string> = {
  github_app: "GitHub",
  gitlab_oauth: "GitLab",
  gitlab_pat: "GitLab (jeton personnel)",
};

/**
 * What we hold, where it lives, and how to get rid of it — on one page.
 *
 * These durations must stay identical to the ones published in
 * apps/web/lib/legal.ts and to the RETENTION constants in
 * packages/retention/src/purge.ts. Three copies of a number is two too many,
 * but the middle one is a legal document and the last one is a purge: they are
 * checked against each other by hand, and all three files say so.
 *
 * The cadence in the right-hand column is likewise a claim about code: it holds
 * only as long as apps/worker/src/retention-scheduler.ts registers its nightly
 * BullMQ Job Scheduler.
 */
const RETENTION = [
  ["Code source cloné", "Jamais conservé — détruit à la fin du relevé"],
  ["Findings, rapports et relevés", "24 mois — purge automatique chaque nuit"],
  ["Journaux d'exécution des scanners", "90 jours — purge automatique chaque nuit"],
  ["Jetons d'accès aux dépôts", "Chiffrés, détruits à la révocation"],
  ["Compte", "Tant qu'il est actif — suppression immédiate"],
];

export default async function SettingsPage() {
  const session = await getSession();
  const connections = (await apiGet<Connection[]>("/connections")) ?? [];

  return (
    <>
      <PageHead
        index="04"
        title="Réglages"
        lede="Votre compte, vos accès aux dépôts, et ce que nous conservons."
      />

      <section className="border-b border-line px-6 py-8 lg:px-10">
        <h2 className="h-md">Compte</h2>
        <dl className="mt-6 grid grid-cols-1 gap-px border border-line bg-line sm:grid-cols-3">
          {[
            ["Adresse e-mail", session?.user?.email ?? "—"],
            ["Nom", session?.user?.name || "Non renseigné"],
            ["Organisation", session?.org?.name ?? "—"],
          ].map(([k, v]) => (
            <div key={k} className="bg-carbon px-5 py-4">
              <dt className="label text-mute">{k}</dt>
              <dd className="mt-2 truncate font-mono text-data text-mineral">{v}</dd>
            </div>
          ))}
        </dl>
        <p className="mt-4 font-mono text-label uppercase text-mute">
          La session est un cookie opaque ; nous n&apos;en stockons qu&apos;une empreinte SHA-256,
          jamais le jeton.
        </p>
      </section>

      <section className="border-b border-line px-6 py-8 lg:px-10">
        <div className="flex flex-wrap items-baseline justify-between gap-4">
          <h2 className="h-md">Accès aux dépôts</h2>
          <div className="flex gap-3">
            <ButtonLink href="/api/connections/github/install" size="sm">
              + GitHub
            </ButtonLink>
            <ButtonLink href="/api/connections/gitlab/connect" size="sm">
              + GitLab
            </ButtonLink>
          </div>
        </div>

        {connections.length === 0 ? (
          <p className="mt-6 border border-dashed border-line px-5 py-8 font-mono text-label uppercase text-mute">
            Aucun fournisseur connecté
          </p>
        ) : (
          <ul className="mt-6 border-t border-line">
            {connections.map((c) => {
              const label = `${PROVIDER_FR[c.provider] ?? c.provider}${
                c.externalAccountId ? ` · ${c.externalAccountId}` : ""
              }`;
              return (
                <li
                  key={c.id}
                  className="flex flex-wrap items-center justify-between gap-4 border-b border-line py-4"
                >
                  <div>
                    <p className="font-mono text-data text-mineral">{label}</p>
                    <p className="mt-0.5 font-mono text-label uppercase text-mute">
                      jeton chiffré AES-256-GCM · clé maîtresse en coffre
                    </p>
                  </div>
                  <div className="flex items-center gap-4">
                    <Chip tone={c.status === "active" ? "acid" : "warn"}>{c.status}</Chip>
                    <RevokeConnection connectionId={c.id} label={label} />
                  </div>
                </li>
              );
            })}
          </ul>
        )}

        <p className="mt-5 max-w-[70ch] text-data text-mute">
          Révoquer ici détruit le jeton chiffré que nous détenons et retire les dépôts importés
          par cet accès ainsi que leurs relevés. Cela ne désinstalle pas l&apos;application chez
          le fournisseur : pour couper l&apos;accès à la source, désinstallez aussi
          l&apos;application GitHub depuis votre compte ou votre organisation, ou retirez
          l&apos;autorisation dans GitLab.
        </p>
      </section>

      <section className="border-b border-line px-6 py-8 lg:px-10">
        <h2 className="h-md">Conservation des données</h2>
        <ul className="mt-6 border-t border-line">
          {RETENTION.map(([k, v]) => (
            <li
              key={k}
              className="flex flex-wrap items-baseline justify-between gap-x-6 gap-y-1 border-b border-line py-3.5"
            >
              <span className="font-mono text-data text-mineral">{k}</span>
              <span className="font-mono text-label uppercase text-mute">{v}</span>
            </li>
          ))}
        </ul>
        <p className="mt-5 max-w-[70ch] text-data text-mute">
          La purge tourne toutes les nuits à 03h30 UTC et applique exactement ces durées.
          Chaque suppression est consignée dans le journal d&apos;activité de votre
          organisation, avec le décompte de ce qui est parti, et ce journal figure dans votre
          export JSON. Passant une fois par jour, elle peut laisser une donnée survivre au
          plus vingt-quatre heures à son échéance. Le détail figure dans la{" "}
          <Link href="/legal/confidentialite" className="ul-draw text-acid">
            politique de confidentialité
          </Link>
          .
        </p>
      </section>

      <section className="border-b border-line px-6 py-8 lg:px-10">
        <h2 className="h-md">Exporter vos données</h2>
        <p className="mt-4 max-w-[70ch] text-data text-mute">
          Un fichier JSON contenant votre compte, votre organisation, vos connexions, vos
          dépôts, vos relevés, vos findings, vos rapports et vos décisions de triage. Les jetons
          d&apos;accès n&apos;y figurent pas, et votre code source non plus — il n&apos;est
          jamais conservé. C&apos;est le droit à la portabilité prévu par le RGPD.
        </p>
        <div className="mt-6">
          {/* Un lien, pas un bouton : la réponse est une pièce jointe, le
              navigateur l'enregistre directement. */}
          <ButtonLink href={ACCOUNT_EXPORT_PATH} download>
            Télécharger l&apos;export JSON
          </ButtonLink>
        </div>
      </section>

      <section className="px-6 py-8 lg:px-10">
        <Label className="text-critical">Zone sensible</Label>
        <h2 className="h-md mt-3">Supprimer le compte</h2>
        <p className="mt-4 max-w-[70ch] text-data text-mute">
          La suppression efface immédiatement le compte, l&apos;organisation, les dépôts
          importés, les relevés, les findings et les rapports, ainsi que les fichiers stockés
          qui s&apos;y rattachent. Les jetons d&apos;accès chiffrés sont détruits. Il n&apos;y a
          ni corbeille ni délai de grâce : rien ne sera restituable ensuite. Exportez vos
          données avant, si vous en avez besoin.
        </p>
        <p className="mt-3 max-w-[70ch] text-data text-mute">
          Seules survivent les attestations d&apos;autorisation des scans réseau que vous avez
          lancés : elles protègent les cibles de ces scans, qui sont des tiers, et expirent
          d&apos;elles-mêmes au bout de 24 mois.
        </p>

        {session?.user?.email ? (
          <DeleteAccount email={session.user.email} />
        ) : (
          <p className="mt-6 border border-dashed border-line px-5 py-6 font-mono text-label uppercase text-mute">
            session illisible — rechargez la page pour supprimer le compte
          </p>
        )}
      </section>
    </>
  );
}
