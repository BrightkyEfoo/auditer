import { PageHead } from "@/components/app/shell";
import { RunRow } from "@/components/app/run-row";
import { ButtonLink, Empty, Readout } from "@/components/ui";
import { apiGet } from "@/lib/session";
import { SEVERITIES } from "@/components/ui";
import type { AuditRunSummary } from "@/lib/api";

export const dynamic = "force-dynamic";

export default async function AuditsPage() {
  const runs = (await apiGet<AuditRunSummary[]>("/audits")) ?? [];

  const finished = runs.filter((r) => r.riskScore !== null);
  const totals = SEVERITIES.reduce(
    (acc, s) => ({ ...acc, [s]: runs.reduce((n, r) => n + (r.counts?.[s] ?? 0), 0) }),
    {} as Record<string, number>,
  );

  return (
    <>
      <PageHead
        index="03"
        title="Relevés"
        lede="Chaque exécution est un instantané figé : le score, les findings et la version du barème restent ceux du jour où il a tourné."
        actions={
          <ButtonLink href="/depots" variant="primary">
            Nouveau relevé
          </ButtonLink>
        }
      />

      {runs.length === 0 ? (
        <div className="px-6 py-12 lg:px-10">
          <Empty
            title="Aucun relevé"
            body="L'historique se remplit dès le premier relevé lancé. Il conserve les findings tels qu'ils étaient, même après correction."
            action={
              <ButtonLink href="/depots" variant="primary">
                Lancer un relevé
              </ButtonLink>
            }
          />
        </div>
      ) : (
        <>
          <section className="grid grid-cols-2 gap-px border-b border-line bg-line lg:grid-cols-4">
            <div className="bg-carbon px-6 py-7 lg:px-10">
              <Readout
                label="Relevés"
                value={runs.length}
                hint={`${finished.length} terminé(s)`}
                className="border-l-0 pl-0"
              />
            </div>
            <div className="bg-carbon px-6 py-7 lg:px-10">
              <Readout
                label="Critiques cumulés"
                value={totals.critical ?? 0}
                tone={totals.critical ? "text-critical" : undefined}
                hint="tous relevés confondus"
                className="border-l-0 pl-0"
              />
            </div>
            <div className="bg-carbon px-6 py-7 lg:px-10">
              <Readout
                label="Élevés cumulés"
                value={totals.high ?? 0}
                tone={totals.high ? "text-high" : undefined}
                hint="tous relevés confondus"
                className="border-l-0 pl-0"
              />
            </div>
            <div className="bg-carbon px-6 py-7 lg:px-10">
              <Readout
                label="Findings au total"
                value={SEVERITIES.reduce((n, s) => n + (totals[s] ?? 0), 0)}
                hint="avant déduplication inter-relevés"
                className="border-l-0 pl-0"
              />
            </div>
          </section>

          <section className="px-6 py-8 lg:px-10">
            <ul className="border-t border-line">
              {runs.map((r) => (
                <RunRow key={r.id} run={r} />
              ))}
            </ul>
            <p className="mt-6 font-mono text-label uppercase text-mute">
              50 relevés les plus récents
            </p>
          </section>
        </>
      )}
    </>
  );
}
