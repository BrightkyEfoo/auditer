import Link from "next/link";
import { PageHead } from "@/components/app/shell";
import { ButtonLink, Label, Chip } from "@/components/ui";
import { getSession, apiGet } from "@/lib/session";
import type { Connection } from "@/lib/api";

export const dynamic = "force-dynamic";

const PROVIDER_FR: Record<string, string> = {
  github_app: "GitHub",
  gitlab_oauth: "GitLab",
  gitlab_pat: "GitLab (jeton personnel)",
};

/** What we hold, where it lives, and how to get rid of it — on one page. */
const RETENTION = [
  ["Code source cloné", "Jamais conservé — détruit à la fin du relevé"],
  ["Findings et rapports", "24 mois"],
  ["Journaux d'exécution des scanners", "90 jours"],
  ["Jetons d'accès aux dépôts", "Chiffrés, jusqu'à révocation"],
  ["Compte", "Tant qu'il est actif, puis 30 jours"],
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
            {connections.map((c) => (
              <li
                key={c.id}
                className="flex flex-wrap items-center justify-between gap-4 border-b border-line py-4"
              >
                <div>
                  <p className="font-mono text-data text-mineral">
                    {PROVIDER_FR[c.provider] ?? c.provider}
                    {c.externalAccountId ? ` · ${c.externalAccountId}` : ""}
                  </p>
                  <p className="mt-0.5 font-mono text-label uppercase text-mute">
                    jeton chiffré AES-256-GCM · clé maîtresse en coffre
                  </p>
                </div>
                <Chip tone={c.status === "active" ? "acid" : "warn"}>{c.status}</Chip>
              </li>
            ))}
          </ul>
        )}

        <p className="mt-5 max-w-[70ch] text-data text-mute">
          La révocation se fait du côté du fournisseur : désinstallez l&apos;application GitHub
          depuis les réglages de votre compte ou de votre organisation, ou retirez
          l&apos;autorisation dans GitLab. L&apos;accès cesse immédiatement, et le jeton chiffré
          devient inutilisable.
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
        <p className="mt-5 text-data text-mute">
          Le détail figure dans la{" "}
          <Link href="/legal/confidentialite" className="ul-draw text-acid">
            politique de confidentialité
          </Link>
          .
        </p>
      </section>

      <section className="px-6 py-8 lg:px-10">
        <Label className="text-critical">Zone sensible</Label>
        <h2 className="h-md mt-3">Supprimer le compte</h2>
        <p className="mt-4 max-w-[70ch] text-data text-mute">
          La suppression efface le compte, l&apos;organisation, les dépôts importés, les relevés
          et les rapports. Les jetons d&apos;accès sont détruits immédiatement. L&apos;opération
          est irréversible et n&apos;est pas encore automatisée : écrivez-nous et nous
          l&apos;exécutons sous 30 jours, conformément à la politique de confidentialité.
        </p>
        <div className="mt-6">
          <ButtonLink
            href="mailto:privacy@auditer.brightkyefoo.cm?subject=Suppression%20de%20compte"
            variant="danger"
          >
            Demander la suppression
          </ButtonLink>
        </div>
      </section>
    </>
  );
}
