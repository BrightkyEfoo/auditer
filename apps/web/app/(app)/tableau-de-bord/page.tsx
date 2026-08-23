import Link from "next/link";
import { PageHead } from "@/components/app/shell";
import { Trend } from "@/components/app/trend";
import { RunRow } from "@/components/app/run-row";
import { ButtonLink, Empty, Label, Readout } from "@/components/ui";
import { apiGet } from "@/lib/session";
import { grade, gradeTone, type AuditRunSummary, type Overview } from "@/lib/api";

export const dynamic = "force-dynamic";

/**
 * The overview answers one question first — "am I okay?" — with one number,
 * then four counters, then the runs. Everything else is a click away. A wall of
 * charts on first load is how dashboards get abandoned.
 */
export default async function DashboardPage() {
  const [overview, runs] = await Promise.all([
    apiGet<Overview>("/overview"),
    apiGet<AuditRunSummary[]>("/audits"),
  ]);

  const score = overview?.lastRun?.riskScore ?? null;
  const hasRepos = (overview?.repos ?? 0) > 0;

  return (
    <>
      <PageHead
        index="01"
        title="Tableau de bord"
        lede="L'état de vos dépôts au dernier relevé de chacun."
        actions={
          hasRepos ? (
            <ButtonLink href="/depots" variant="primary">
              Lancer un relevé
            </ButtonLink>
          ) : undefined
        }
      />

      <div className="space-y-px bg-line">
        {/* ── The number ─────────────────────────────────────────────── */}
        <section className="bg-carbon px-6 py-9 lg:px-10">
          <div className="grid grid-cols-12 items-end gap-y-10">
            <div className="col-span-12 lg:col-span-5">
              <Label className="text-mute">Dernier score global</Label>
              <div className="mt-4 flex items-end gap-6">
                <span
                  className={`font-display text-[clamp(4rem,12vw,7rem)] font-bold leading-[0.8] tracking-tightest ${gradeTone(score)}`}
                >
                  {score ?? "—"}
                </span>
                <div className="pb-2">
                  <span className={`font-display text-[2.5rem] font-bold leading-none ${gradeTone(score)}`}>
                    {grade(score)}
                  </span>
                  <p className="mt-1 font-mono text-label uppercase text-mute">sur 100</p>
                </div>
              </div>
              <p className="mt-5 max-w-[44ch] text-data text-mute">
                {overview?.lastRun?.repository
                  ? `Relevé le plus récent — ${overview.lastRun.repository.fullName}.`
                  : "Aucun relevé terminé pour l'instant."}{" "}
                Un seul finding critique ouvert plafonne la note à F, quel que soit le reste.
              </p>
            </div>

            <div className="col-span-12 lg:col-span-6 lg:col-start-7">
              <Label className="text-mute">Tendance — 12 derniers relevés</Label>
              <div className="mt-4">
                <Trend points={overview?.trend ?? []} />
              </div>
            </div>
          </div>
        </section>

        {/* ── The four counters ──────────────────────────────────────── */}
        <section className="grid grid-cols-2 gap-px bg-line lg:grid-cols-4">
          <div className="bg-carbon px-6 py-7 lg:px-10">
            <Readout
              label="Critiques ouverts"
              value={overview?.openCritical ?? 0}
              tone={overview?.openCritical ? "text-critical" : "text-mineral"}
              hint="à corriger d'abord"
              className="border-l-0 pl-0"
            />
          </div>
          <div className="bg-carbon px-6 py-7 lg:px-10">
            <Readout
              label="Élevés ouverts"
              value={overview?.openHigh ?? 0}
              tone={overview?.openHigh ? "text-high" : "text-mineral"}
              hint="hors faux positifs triés"
              className="border-l-0 pl-0"
            />
          </div>
          <div className="bg-carbon px-6 py-7 lg:px-10">
            <Readout
              label="Dépôts suivis"
              value={overview?.repos ?? 0}
              hint="importés dans l'organisation"
              className="border-l-0 pl-0"
            />
          </div>
          <div className="bg-carbon px-6 py-7 lg:px-10">
            <Readout
              label="Score moyen"
              value={overview?.avgScore ?? "—"}
              tone={gradeTone(overview?.avgScore ?? null)}
              hint={`${overview?.runs ?? 0} relevé(s) au total`}
              className="border-l-0 pl-0"
            />
          </div>
        </section>
      </div>

      {/* ── Runs ───────────────────────────────────────────────────────── */}
      <section className="px-6 py-10 lg:px-10">
        <div className="flex items-baseline justify-between border-b border-line pb-4">
          <h2 className="h-md">Relevés récents</h2>
          {runs && runs.length > 0 && (
            <Link
              href="/audits"
              className="ul-draw font-mono text-label uppercase text-mute transition-colors duration-[180ms] hover:text-mineral"
            >
              Tout l&apos;historique →
            </Link>
          )}
        </div>

        {!hasRepos ? (
          <div className="mt-8">
            <Empty
              title="Aucun dépôt connecté"
              body="Connectez GitHub ou GitLab, importez un dépôt, et le premier relevé prend environ quatre minutes."
              action={
                <ButtonLink href="/depots" variant="primary">
                  Connecter un dépôt
                </ButtonLink>
              }
            />
          </div>
        ) : !runs || runs.length === 0 ? (
          <div className="mt-8">
            <Empty
              title="Aucun relevé lancé"
              body="Vos dépôts sont importés. Choisissez-en un et sélectionnez les piliers à mesurer."
              action={
                <ButtonLink href="/depots" variant="primary">
                  Lancer un relevé
                </ButtonLink>
              }
            />
          </div>
        ) : (
          <ul className="mt-2">
            {runs.slice(0, 6).map((r) => (
              <RunRow key={r.id} run={r} />
            ))}
          </ul>
        )}
      </section>
    </>
  );
}
