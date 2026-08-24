"use client";

import { useState } from "react";
import { Button, ButtonLink, Label, Chip } from "@/components/ui";
import { api, type ReportDocument } from "@/lib/api";
import { cn } from "@/lib/cn";

/**
 * The four deliverables of one run, as a section rather than a dropdown.
 *
 * A mission produces four documents because the five readers of an audit do not
 * read the same thing, and the one that gets SHOWN to third parties — the
 * attestation — is a different object from the one the developers work through.
 * Hiding that behind a format picker would bury the part of the product a
 * customer actually pays for.
 *
 * Each row states who it is for, because choosing the wrong document is the
 * easy mistake here: handing a client the technical report means handing them a
 * map of the defects in their own system.
 */

interface Doc {
  id: ReportDocument;
  name: string;
  reader: string;
  note: string;
  caution?: string;
}

const DOCS: Doc[] = [
  {
    id: "technique",
    name: "Rapport technique",
    reader: "Développeur, responsable technique",
    note: "Périmètre déclaré, méthodologie par pilier, findings avec reproduction et remédiation.",
    caution: "Contient des informations exploitables — à ne pas diffuser hors de l'équipe.",
  },
  {
    id: "dirigeant",
    name: "Note de direction",
    reader: "Dirigeant non technique",
    note: "Deux pages. Le verdict, la tendance contre le relevé précédent, les décisions à prendre.",
  },
  {
    id: "attestation",
    name: "Attestation d'audit",
    reader: "Vos clients, un appel d'offres, un auditeur",
    note: "Une page signée. Prouve l'audit sans divulguer le moindre détail exploitable.",
  },
  {
    id: "progression",
    name: "Rapport de progression",
    reader: "Tous",
    note: "Ce qui a été corrigé, ce qui est nouveau, ce qui traîne et depuis combien de temps.",
  },
];

type State = { status: "idle" | "busy" | "failed"; path?: string };

export function Deliverables({ runId }: { runId: string }) {
  const [state, setState] = useState<Record<string, State>>({});

  async function generate(doc: ReportDocument) {
    setState((s) => ({ ...s, [doc]: { status: "busy" } }));
    try {
      await api.exportReport(runId, doc);
      // The export endpoint only enqueues; poll until the worker has written
      // the artifact. Returning at 202 is what previously left every export
      // announced but unreachable.
      for (let i = 0; i < 40; i++) {
        await new Promise((r) => setTimeout(r, 1500));
        const rep = await api.getReport(runId).catch(() => null);
        if (rep?.downloadPath && rep.document === doc) {
          setState((s) => ({ ...s, [doc]: { status: "idle", path: rep.downloadPath! } }));
          return;
        }
        if (rep?.status === "failed") break;
      }
      setState((s) => ({ ...s, [doc]: { status: "failed" } }));
    } catch {
      setState((s) => ({ ...s, [doc]: { status: "failed" } }));
    }
  }

  return (
    <section className="border-t border-line px-6 py-10 lg:px-10">
      <div className="flex flex-wrap items-baseline justify-between gap-4">
        <h2 className="h-md">Livrables</h2>
        <p className="font-mono text-label uppercase text-mute">
          Un relevé, quatre documents — un par lecteur
        </p>
      </div>

      <ul className="mt-8 border-t border-line">
        {DOCS.map((d) => {
          const st = state[d.id] ?? { status: "idle" as const };
          return (
            <li
              key={d.id}
              className="group relative grid grid-cols-12 items-start gap-x-6 gap-y-4 border-b border-line py-6"
            >
              <span aria-hidden className="row-mark" />

              <div className="col-span-12 pl-4 lg:col-span-7">
                <div className="flex flex-wrap items-center gap-3">
                  <h3 className="font-display text-lede font-bold tracking-display">{d.name}</h3>
                  {d.id === "attestation" && <Chip tone="acid">partageable</Chip>}
                  {d.caution && <Chip tone="warn">confidentiel</Chip>}
                </div>
                <Label className="mt-2 block text-mute">Pour : {d.reader}</Label>
                <p className="mt-3 max-w-[60ch] text-data text-mute">{d.note}</p>
                {d.caution && (
                  <p className="mt-2 max-w-[60ch] font-mono text-label uppercase leading-relaxed text-high">
                    {d.caution}
                  </p>
                )}
              </div>

              <div className="col-span-12 flex items-center gap-3 pl-4 lg:col-span-5 lg:justify-end lg:pl-0">
                {st.path ? (
                  <>
                    <ButtonLink href={st.path} variant="primary" download>
                      Télécharger
                    </ButtonLink>
                    <Button variant="quiet" onClick={() => generate(d.id)}>
                      Régénérer
                    </Button>
                  </>
                ) : (
                  <Button
                    onClick={() => generate(d.id)}
                    disabled={st.status === "busy"}
                    variant={d.id === "attestation" ? "primary" : "ghost"}
                    className={cn(st.status === "failed" && "border-critical/50 text-critical")}
                  >
                    {st.status === "busy"
                      ? "rédaction en cours…"
                      : st.status === "failed"
                        ? "Réessayer"
                        : "Générer"}
                  </Button>
                )}
              </div>
            </li>
          );
        })}
      </ul>

      <p className="mt-6 max-w-[72ch] font-mono text-label uppercase leading-relaxed text-mute">
        L&apos;attestation prouve que l&apos;audit a eu lieu sans montrer ce qu&apos;il a trouvé.
        C&apos;est le seul des quatre que vous pouvez remettre à un tiers sans accord de
        confidentialité.
      </p>
    </section>
  );
}
