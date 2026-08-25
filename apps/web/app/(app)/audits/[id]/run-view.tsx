"use client";

import { useEffect, useState, useCallback, useMemo } from "react";
import { useRouter } from "next/navigation";
import { PageHead } from "@/components/app/shell";
import {
  Button,
  ButtonLink,
  Chip,
  Empty,
  Label,
  SevMark,
  SEVERITIES,
  sevBg,
  sevText,
  inputClass,
} from "@/components/ui";
import {
  api,
  eventsUrl,
  ago,
  grade,
  gradeTone,
  SEVERITY_FR,
  STATUS_FR,
  TRIAGE_FR,
  type AuditRun,
  type Finding,
  type Report,
  type Scan,
} from "@/lib/api";
import { cn } from "@/lib/cn";
import { Deliverables } from "@/components/app/deliverables";
import { RunTrace, type TraceEntry } from "@/components/app/run-trace";

const STEPS = ["queued", "cloning", "scanning", "analyzing", "reporting", "done"] as const;
const TERMINAL = new Set(["done", "completed_with_errors", "failed", "canceled"]);
const TRIAGE_OPTIONS = ["open", "false_positive", "ignored", "accepted"];

/** États d'un moteur dont l'issue est connue — ils comptent dans l'avancement. */
const SCAN_TERMINAL = new Set(["success", "partial", "failed", "skipped"]);

/** Le message que le moteur a laissé en échouant, quand il y en a un. */
function reasonOf(error: unknown): string | undefined {
  if (!error || typeof error !== "object") return undefined;
  const m = (error as { message?: unknown }).message;
  return typeof m === "string" && m ? m.slice(0, 300) : undefined;
}

/** Champs réellement renseignés. Un spread naïf écraserait une valeur connue
 *  par un `undefined` porté par la mise à jour — c'est ainsi qu'une durée ou un
 *  code de sortie déjà affiché disparaît en cours de relevé. */
function defined<T extends object>(o: T): Partial<T> {
  return Object.fromEntries(Object.entries(o).filter(([, v]) => v !== undefined)) as Partial<T>;
}

/**
 * Fusionner des lignes moteur dans la trace, en clé (pilier, outil).
 *
 * Deux sources écrivent ici — les lignes persistées et le flux — et elles se
 * recouvrent. La clé était auparavant « même outil ET statut en cours », ce qui
 * supposait qu'un moteur n'apparaisse qu'une fois lancé. Depuis que le plan est
 * inscrit en base, un moteur existe AVANT de démarrer : cette règle ne trouvait
 * plus rien à remplacer et empilait un doublon par événement.
 *
 * Une ligne dont l'issue est connue ne recule jamais : un rejeu après coupure
 * peut redonner un « en cours » déjà périmé, et il ne doit pas effacer le
 * résultat que le lecteur a sous les yeux.
 */
function mergeScanRows(current: TraceEntry[], incoming: TraceEntry[]): TraceEntry[] {
  const next = [...current];
  for (const row of incoming) {
    const idx = next.findIndex(
      (x) => x.kind === "scan" && x.pillar === row.pillar && x.tool === row.tool,
    );
    if (idx < 0) {
      next.push(row);
      continue;
    }
    const prev = next[idx];
    if (!prev) {
      next.push(row);
      continue;
    }
    if (SCAN_TERMINAL.has(prev.status ?? "") && !SCAN_TERMINAL.has(row.status ?? "")) continue;
    // `prev` porte déjà `kind` et `at` ; `defined` ne fait que recouvrir des
    // champs facultatifs, d'où l'assertion — le résultat reste une entrée
    // complète, TypeScript perd juste cette information en fusionnant un
    // Partial.
    next[idx] = { ...prev, ...defined(row) } as TraceEntry;
  }
  return next;
}

/**
 * Reconstruire la trace depuis les lignes persistées.
 *
 * C'est ce qui la rend indépendante du flux : rouvrir la page trois jours plus
 * tard affiche la même trace, moteur par moteur, avec durées et codes de sortie.
 * Les événements en direct ne font ensuite que la compléter.
 */
function traceFromScans(scans: Scan[]): TraceEntry[] {
  return scans.map((s) => ({
    kind: "scan" as const,
    at: s.startedAt ?? s.createdAt,
    tool: s.tool,
    pillar: s.pillar,
    status: s.status,
    durationMs:
      s.startedAt && s.finishedAt
        ? new Date(s.finishedAt).getTime() - new Date(s.startedAt).getTime()
        : undefined,
    exitCode: s.exitCode ?? undefined,
    image: s.imageDigest ?? undefined,
    reason: reasonOf(s.error),
    // Pas d'artefact, pas de lien : proposer un téléchargement qui rendrait 404
    // vaut moins que ne rien proposer.
    scanId: s.rawArtifactId ? s.id : undefined,
  }));
}

export function RunView({ runId }: { runId: string }) {
  const [run, setRun] = useState<AuditRun | null>(null);
  const [status, setStatus] = useState("queued");
  const [trace, setTrace] = useState<TraceEntry[]>([]);
  const [scans, setScans] = useState<Scan[]>([]);
  const [canceling, setCanceling] = useState(false);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [sevFilter, setSevFilter] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [hideTriaged, setHideTriaged] = useState(false);

  const refreshFindings = useCallback(() => {
    api.listFindings(runId).then(setFindings).catch(() => {});
  }, [runId]);

  // Les scans persistés sont la trace de référence. On les relit au montage et
  // à la fin du relevé : le direct complète, il ne remplace pas.
  const refreshScans = useCallback(() => {
    api
      .listScans(runId)
      .then((rows) => {
        setScans(rows);
        setTrace((t) => mergeScanRows(t, traceFromScans(rows)));
      })
      .catch(() => {});
  }, [runId]);

  // Snapshot the run first, then tail live events. Doing it in that order means
  // a page opened after the run finished still shows the result instead of an
  // empty stream.
  useEffect(() => {
    api.getAudit(runId).then((r) => {
      setRun(r);
      setStatus(r.status);
      if (TERMINAL.has(r.status)) {
        refreshFindings();
      }
    });

    refreshScans();

    const es = new EventSource(eventsUrl(runId));
    es.addEventListener("status", (e) => {
      const d = JSON.parse((e as MessageEvent).data);
      setStatus(d.status);
      setTrace((t) => [
        ...t,
        { kind: "phase", at: d.at, message: STATUS_FR[d.status] ?? d.status },
      ]);
    });
    es.addEventListener("scan", (e) => {
      const d = JSON.parse((e as MessageEvent).data) as TraceEntry & { at: string };
      setTrace((t) => mergeScanRows(t, [{ ...d, kind: "scan" }]));
      // Un moteur qui vient de finir a désormais une ligne complète en base —
      // durée exacte, code de sortie, journal conservé. On la relit plutôt que
      // de se contenter de l'événement, qui ne connaît pas l'artefact.
      if (d.status && d.status !== "running") refreshScans();
    });
    es.addEventListener("log", (e) => {
      const d = JSON.parse((e as MessageEvent).data);
      setTrace((t) => [...t, { kind: "note", at: d.at, message: d.message }]);
    });
    es.addEventListener("done", (e) => {
      setStatus(JSON.parse((e as MessageEvent).data).status);
      api.getAudit(runId).then(setRun);
      refreshFindings();
      // Relire les lignes persistées une dernière fois : elles portent les
      // durées et codes de sortie définitifs.
      refreshScans();
      es.close();
    });

    // NE PAS fermer le flux sur erreur.
    //
    // `es.onerror = () => es.close()` coupait la seule reprise dont on dispose :
    // EventSource se reconnecte tout seul, avec l'en-tête `Last-Event-ID`, et
    // l'api rejoue désormais ce qui a été manqué. Fermer au premier hoquet
    // réseau transformait une coupure d'une seconde en trace définitivement
    // amputée — et c'est le comportement qu'avait la page.
    //
    // On laisse donc le navigateur retenter. Le seul cas où l'on ferme pour de
    // bon est le relevé terminé (ci-dessus) ou le démontage (ci-dessous), sans
    // quoi une page quittée laisserait une connexion à se rouvrir dans le vide.
    es.onerror = () => {
      // Rien : la reconnexion est prise en charge par le navigateur.
    };
    return () => es.close();
  }, [runId, refreshFindings, refreshScans]);

  async function triage(f: Finding, s: string) {
    // Optimistic: triage is org-scoped and keyed on the fingerprint, so the
    // write is idempotent and a failed round-trip costs nothing but a re-click.
    setFindings((cur) =>
      cur.map((x) => (x.fingerprint === f.fingerprint ? { ...x, triageStatus: s } : x)),
    );
    await api.setTriage(f.fingerprint, s).catch(() => refreshFindings());
  }


  const counts = useMemo(
    () =>
      SEVERITIES.reduce(
        (acc, s) => ({ ...acc, [s]: findings.filter((f) => f.severity === s).length }),
        {} as Record<string, number>,
      ),
    [findings],
  );
  const openCount = findings.filter((f) => f.triageStatus === "open").length;

  const shown = findings.filter((f) => {
    if (sevFilter && f.severity !== sevFilter) return false;
    if (hideTriaged && f.triageStatus !== "open") return false;
    const q = query.trim().toLowerCase();
    if (!q) return true;
    return (
      f.title.toLowerCase().includes(q) ||
      f.ruleId.toLowerCase().includes(q) ||
      f.vulnIds.some((v) => v.toLowerCase().includes(q))
    );
  });

  const running = !TERMINAL.has(status);

  // Avancement réel : moteurs dont l'issue est connue sur moteurs prévus. Le
  // dénominateur vient du plan inscrit en base au démarrage, pas d'une
  // estimation — « 4 sur 7 » est vérifiable ligne par ligne dans la trace.
  const engineTotal = scans.length;
  const engineDone = scans.filter((s) => SCAN_TERMINAL.has(s.status)).length;
  const percent = engineTotal > 0 ? Math.round((engineDone / engineTotal) * 100) : null;

  async function cancel() {
    setCanceling(true);
    try {
      await api.cancelAudit(runId);
    } catch {
      // L'arrêt a échoué : rendre le bouton plutôt que de laisser un état figé
      // qui laisserait croire qu'une demande est en vol.
      setCanceling(false);
    }
  }

  const stepIndex = STEPS.indexOf(
    (status === "completed_with_errors" ? "done" : status) as (typeof STEPS)[number],
  );

  return (
    <>
      <PageHead
        index="03"
        title={run?.pillars?.length ? `Relevé — ${run.pillars.join(" · ")}` : "Relevé"}
        lede={
          run
            ? `Lancé ${ago(run.createdAt)}${run.scoringVersion ? ` · barème v${run.scoringVersion}` : ""} · ${runId}`
            : undefined
        }
        actions={
          <div className="flex items-center gap-3">
            {running && (
              <Button variant="quiet" size="sm" disabled={canceling} onClick={cancel}>
                {canceling ? "arrêt demandé…" : "Arrêter"}
              </Button>
            )}
            <DeleteRun runId={runId} />
          </div>
        }
      />

      {/* ── Progress ───────────────────────────────────────────────────── */}
      <section className="border-b border-line px-6 py-7 lg:px-10">
        {percent !== null && (
          <div className="mb-7">
            <div className="flex flex-wrap items-end justify-between gap-x-6 gap-y-2">
              <div className="flex items-end gap-4">
                <span
                  className={cn(
                    "font-display text-[clamp(3rem,9vw,5.5rem)] font-bold leading-[0.8] tracking-tightest tabular-nums",
                    running ? "text-acid" : "text-mineral",
                  )}
                >
                  {percent}
                  <span className="text-[0.4em] align-super">%</span>
                </span>
                <p className="pb-2 font-mono text-data text-mute">
                  {engineDone} moteur{engineDone > 1 ? "s" : ""} sur {engineTotal}
                </p>
              </div>
              {canceling && running && (
                <p className="pb-2 font-mono text-label uppercase text-high">
                  arrêt demandé — le moteur en cours va à son terme
                </p>
              )}
            </div>

            <div
              role="progressbar"
              aria-valuenow={percent}
              aria-valuemin={0}
              aria-valuemax={100}
              aria-label="Moteurs terminés"
              className="mt-4 h-1.5 w-full bg-line"
            >
              <div
                className={cn(
                  "h-full transition-[width] duration-500 ease-out",
                  running ? "bg-acid" : "bg-line-bright",
                )}
                style={{ width: `${percent}%` }}
              />
            </div>

            {/* Ce pourcentage compte des MOTEURS, pas des phases. Le dire évite
                qu'un lecteur lise 100 % pendant l'agrégation et le rapport, et
                conclue que le relevé est fini alors qu'il travaille encore. */}
            <p className="mt-2 font-mono text-label uppercase text-mute">
              part des moteurs exécutés · l&apos;analyse et le rapport suivent
            </p>
          </div>
        )}

        <ol className="flex flex-wrap items-center gap-x-2 gap-y-3">
          {STEPS.map((s, i) => {
            const state = i < stepIndex ? "done" : i === stepIndex ? "active" : "todo";
            return (
              <li key={s} className="flex items-center gap-2">
                <span
                  className={cn(
                    "border px-3 py-1 font-mono text-label uppercase transition-colors duration-300",
                    state === "done" && "border-line-bright text-ash",
                    state === "active" && "border-acid bg-acid text-void",
                    state === "todo" && "border-line text-mute",
                  )}
                >
                  {STATUS_FR[s] ?? s}
                </span>
                {i < STEPS.length - 1 && (
                  <span
                    aria-hidden
                    className={cn("h-px w-5", i < stepIndex ? "bg-acid" : "bg-line")}
                  />
                )}
              </li>
            );
          })}
          {status === "failed" && (
            <li className="border border-critical bg-critical/10 px-3 py-1 font-mono text-label uppercase text-critical">
              échec
            </li>
          )}
          {status === "completed_with_errors" && (
            <li className="border border-high bg-high/10 px-3 py-1 font-mono text-label uppercase text-high">
              terminé avec erreurs
            </li>
          )}
        </ol>

        {/* Kept after the run ends, not only while it is live: the trace is how
            anyone answers "why did this pillar find nothing" afterwards. */}
        <RunTrace entries={trace} runId={runId} />
      </section>

      {/* ── Score ──────────────────────────────────────────────────────── */}
      {run?.riskScore != null && (
        <section className="grid grid-cols-12 items-end gap-y-8 border-b border-line px-6 py-9 lg:px-10">
          <div className="col-span-12 lg:col-span-4">
            <Label className="text-mute">Score du relevé</Label>
            <div className="mt-4 flex items-end gap-5">
              <span
                className={cn(
                  "font-display text-[clamp(3.5rem,10vw,6rem)] font-bold leading-[0.8] tracking-tightest",
                  gradeTone(run.riskScore),
                )}
              >
                {run.riskScore}
              </span>
              <div className="pb-2">
                <span className={cn("font-display text-[2rem] font-bold leading-none", gradeTone(run.riskScore))}>
                  {grade(run.riskScore)}
                </span>
                <p className="mt-1 font-mono text-label uppercase text-mute">sur 100</p>
              </div>
            </div>
          </div>

          <div className="col-span-12 lg:col-span-7 lg:col-start-6">
            <Label className="text-mute">Répartition par gravité</Label>
            <div className="mt-4 space-y-2.5">
              {SEVERITIES.map((s) => {
                const n = counts[s] ?? 0;
                const max = Math.max(1, ...SEVERITIES.map((x) => counts[x] ?? 0));
                return (
                  <div key={s} className="flex items-center gap-3">
                    <span className="label w-16 shrink-0 text-mute">{SEVERITY_FR[s]}</span>
                    <span className="h-1.5 flex-1 bg-line">
                      <span
                        className={cn("block h-full transition-[width] duration-500 ease-out", sevBg(s))}
                        style={{ width: `${(n / max) * 100}%` }}
                      />
                    </span>
                    <span className={cn("w-6 shrink-0 text-right font-mono text-data", n ? sevText(s) : "text-mute")}>
                      {n}
                    </span>
                  </div>
                );
              })}
            </div>
            {(counts.critical ?? 0) > 0 && (
              <p className="mt-5 border-l-2 border-critical bg-critical/5 px-4 py-2.5 font-mono text-label uppercase text-critical">
                Plafond appliqué — {counts.critical} critique(s) ouvert(s) forcent la note F
              </p>
            )}
          </div>
        </section>
      )}

      {/* ── Findings ───────────────────────────────────────────────────── */}
      <section className="px-6 py-8 lg:px-10">
        <div className="flex flex-wrap items-baseline justify-between gap-4">
          <h2 className="h-md">
            Findings <span className="font-mono text-lede text-mute">({findings.length})</span>
          </h2>
          <p className="font-mono text-label uppercase text-mute">
            {openCount} ouvert(s) · {findings.length - openCount} trié(s)
          </p>
        </div>

        <div className="mt-6 flex flex-wrap items-center gap-2">
          <FilterChip active={sevFilter === null} onClick={() => setSevFilter(null)}>
            toutes ({findings.length})
          </FilterChip>
          {SEVERITIES.map((s) => (
            <FilterChip
              key={s}
              active={sevFilter === s}
              onClick={() => setSevFilter(sevFilter === s ? null : s)}
              dot={s}
            >
              {SEVERITY_FR[s]} ({counts[s] ?? 0})
            </FilterChip>
          ))}
          <FilterChip active={hideTriaged} onClick={() => setHideTriaged((h) => !h)}>
            masquer les triés
          </FilterChip>
          <input
            className={cn(inputClass, "ml-auto w-full max-w-xs py-2")}
            placeholder="Filtrer par titre, règle, CVE…"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            aria-label="Filtrer les findings"
          />
        </div>

        <div className="mt-6">
          {shown.length === 0 ? (
            running ? (
              <p className="border border-dashed border-line px-5 py-10 text-center font-mono text-label uppercase text-mute">
                analyse en cours — les findings apparaissent au fil des moteurs
              </p>
            ) : findings.length === 0 ? (
              <Empty
                title="Aucun finding"
                body="Les moteurs sélectionnés n'ont rien relevé sur ce commit. Ce n'est pas une preuve d'absence de faille : c'est l'absence de détection par ces moteurs, à cette date."
              />
            ) : (
              <Empty title="Rien pour ce filtre" body="Élargissez la sélection de gravité ou videz la recherche." />
            )
          ) : (
            <ul className="border-t border-line">
              {shown.map((f) => (
                <FindingRow key={f.id} f={f} onTriage={triage} />
              ))}
            </ul>
          )}
        </div>
      </section>

      <Deliverables runId={runId} />
    </>
  );
}

/**
 * Erase a run and its findings — one of the four deletions the privacy policy
 * promises can be done from the interface.
 *
 * Two steps, in place, no `confirm()`: the run is still on screen while its
 * removal is being confirmed, which is the only moment the user can still weigh
 * what they are about to lose. A run in progress is cancelled by the api before
 * it is deleted, so the button does not need to be disabled while it runs.
 */
function DeleteRun({ runId }: { runId: string }) {
  const router = useRouter();
  const [armed, setArmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [failed, setFailed] = useState(false);

  async function remove() {
    setBusy(true);
    setFailed(false);
    try {
      await api.deleteAudit(runId);
      router.push("/audits");
      router.refresh();
    } catch {
      setFailed(true);
      setBusy(false);
      setArmed(false);
    }
  }

  if (!armed) {
    return (
      <Button variant="quiet" onClick={() => setArmed(true)}>
        {failed ? "Échec — réessayer" : "Supprimer ce relevé"}
      </Button>
    );
  }

  return (
    <span className="flex items-center gap-2">
      <span className="font-mono text-label uppercase text-high">
        effacer le relevé et ses findings ?
      </span>
      <Button variant="quiet" onClick={() => setArmed(false)} disabled={busy}>
        Annuler
      </Button>
      <Button variant="danger" onClick={remove} disabled={busy}>
        {busy ? "suppression…" : "Confirmer"}
      </Button>
    </span>
  );
}

function FilterChip({
  active,
  onClick,
  dot,
  children,
}: {
  active: boolean;
  onClick: () => void;
  dot?: string;
  children: React.ReactNode;
}) {
  return (
    <button
      onClick={onClick}
      aria-pressed={active}
      className={cn(
        "flex items-center gap-2 border px-3 py-1.5 font-mono text-label uppercase transition-colors duration-[180ms]",
        active ? "border-acid bg-acid text-void" : "border-line-bright text-ash hover:text-mineral",
      )}
    >
      {dot && <span className={cn("h-2 w-2", active ? "bg-void" : sevBg(dot))} />}
      {children}
    </button>
  );
}

function FindingRow({ f, onTriage }: { f: Finding; onTriage: (f: Finding, s: string) => void }) {
  const [open, setOpen] = useState(false);
  const triaged = f.triageStatus !== "open";

  return (
    <li className={cn("border-b border-line", triaged && "opacity-45")}>
      <button
        onClick={() => setOpen((o) => !o)}
        aria-expanded={open}
        className="group flex w-full items-center gap-4 py-4 text-left transition-colors duration-[180ms] hover:bg-slate/60"
      >
        <SevMark severity={f.severity} />
        <span className="min-w-0 flex-1">
          <span className="block truncate text-data text-mineral">{f.title}</span>
          <span className="mt-1 block font-mono text-label uppercase text-mute">
            {f.tool} · {f.ruleId}
            {f.vulnIds.length > 0 && <span className="text-ash"> · {f.vulnIds[0]}</span>}
            {f.sourceCount > 1 && <span> · {f.sourceCount} moteurs</span>}
            {triaged && <span className="text-acid"> · {TRIAGE_FR[f.triageStatus]}</span>}
          </span>
        </span>
        {f.cvssScore != null && (
          <span className={cn("hidden shrink-0 font-mono text-data sm:block", sevText(f.severity))}>
            CVSS {f.cvssScore}
          </span>
        )}
        <span
          aria-hidden
          className="shrink-0 font-mono text-label text-line-bright transition-colors duration-[180ms] group-hover:text-acid"
        >
          {open ? "−" : "+"}
        </span>
      </button>

      {open && (
        <div className="space-y-5 border-t border-line px-0 pb-7 pt-5 sm:pl-6">
          <p className="max-w-[80ch] text-data text-ash">{f.description}</p>

          {f.cwe.length > 0 && (
            <div className="flex flex-wrap gap-2">
              {f.cwe.map((c) => (
                <Chip key={c}>{c}</Chip>
              ))}
            </div>
          )}

          {f.evidence && (
            <div>
              <Label className="text-mute">Preuve — caviardée</Label>
              <pre className="mt-2 overflow-x-auto border border-line bg-void p-3 font-mono text-label text-ash">
                {f.evidence}
              </pre>
            </div>
          )}

          {f.aiExplanation && (
            <div className="border-l-2 border-acid bg-acid/5 px-4 py-4">
              <div className="flex flex-wrap items-center gap-3">
                <Label className="text-acid">Analyse rédigée</Label>
                {f.aiConfidence != null && (
                  <span className="font-mono text-label uppercase text-mute">
                    confiance {Math.round(f.aiConfidence * 100)} %
                  </span>
                )}
                {f.aiNeedsHuman && <Chip tone="warn">revue humaine conseillée</Chip>}
              </div>
              <p className="mt-3 max-w-[80ch] text-data text-ash">{f.aiExplanation}</p>
              {f.aiRemediation && (
                <p className="mt-3 max-w-[80ch] text-data text-mineral">
                  <span className="text-acid">Correctif — </span>
                  {f.aiRemediation}
                </p>
              )}
              <p className="mt-4 font-mono text-label uppercase text-mute">
                Texte rédigé par un modèle à partir de la sortie du moteur. Le score, lui, est
                calculé.
              </p>
            </div>
          )}

          <div>
            <Label className="text-mute">Triage — persiste d&apos;un relevé au suivant</Label>
            <div className="mt-3 flex flex-wrap gap-2">
              {TRIAGE_OPTIONS.map((s) => (
                <button
                  key={s}
                  onClick={() => onTriage(f, s)}
                  aria-pressed={f.triageStatus === s}
                  className={cn(
                    "border px-3 py-1.5 font-mono text-label uppercase transition-colors duration-[180ms]",
                    f.triageStatus === s
                      ? "border-acid bg-acid text-void"
                      : "border-line-bright text-ash hover:text-mineral",
                  )}
                >
                  {TRIAGE_FR[s]}
                </button>
              ))}
            </div>
          </div>
        </div>
      )}
    </li>
  );
}
