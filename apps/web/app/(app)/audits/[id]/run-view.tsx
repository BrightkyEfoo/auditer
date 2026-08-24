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
} from "@/lib/api";
import { cn } from "@/lib/cn";

const STEPS = ["queued", "cloning", "scanning", "analyzing", "reporting", "done"] as const;
const TERMINAL = new Set(["done", "completed_with_errors", "failed", "canceled"]);
const TRIAGE_OPTIONS = ["open", "false_positive", "ignored", "accepted"];

export function RunView({ runId }: { runId: string }) {
  const [run, setRun] = useState<AuditRun | null>(null);
  const [status, setStatus] = useState("queued");
  const [logs, setLogs] = useState<string[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [sevFilter, setSevFilter] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [hideTriaged, setHideTriaged] = useState(false);
  const [exported, setExported] = useState<"idle" | "busy" | "done" | "failed">("idle");
  const [report, setReport] = useState<Report | null>(null);

  const refreshFindings = useCallback(() => {
    api.listFindings(runId).then(setFindings).catch(() => {});
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
        // A report rendered during an earlier visit is still downloadable —
        // surface it instead of offering to generate it again.
        api
          .getReport(runId)
          .then((rep) => {
            if (rep.downloadPath) {
              setReport(rep);
              setExported("done");
            }
          })
          .catch(() => {});
      }
    });

    const es = new EventSource(eventsUrl(runId));
    es.addEventListener("status", (e) => {
      setStatus(JSON.parse((e as MessageEvent).data).status);
    });
    es.addEventListener("scan", (e) => {
      const d = JSON.parse((e as MessageEvent).data);
      setLogs((l) => [
        ...l,
        `${d.tool} — ${d.status}${d.findingCount != null ? ` (${d.findingCount})` : ""}`,
      ]);
    });
    es.addEventListener("log", (e) => {
      setLogs((l) => [...l, JSON.parse((e as MessageEvent).data).message]);
    });
    es.addEventListener("done", (e) => {
      setStatus(JSON.parse((e as MessageEvent).data).status);
      api.getAudit(runId).then(setRun);
      refreshFindings();
      es.close();
    });
    es.onerror = () => es.close();
    return () => es.close();
  }, [runId, refreshFindings]);

  async function triage(f: Finding, s: string) {
    // Optimistic: triage is org-scoped and keyed on the fingerprint, so the
    // write is idempotent and a failed round-trip costs nothing but a re-click.
    setFindings((cur) =>
      cur.map((x) => (x.fingerprint === f.fingerprint ? { ...x, triageStatus: s } : x)),
    );
    await api.setTriage(f.fingerprint, s).catch(() => refreshFindings());
  }

  /**
   * Render the report, then WAIT for it. The export endpoint only enqueues a
   * job, so returning at 202 and calling it done is what left every previous
   * export unreachable: the user was told "exported" and given nothing.
   */
  async function exportReport() {
    setExported("busy");
    try {
      await api.exportReport(runId);
      for (let i = 0; i < 40; i++) {
        await new Promise((r) => setTimeout(r, 1500));
        const rep = await api.getReport(runId).catch(() => null);
        if (rep?.downloadPath) {
          setReport(rep);
          setExported("done");
          return;
        }
        if (rep?.status === "failed") break;
      }
      setExported("failed");
    } catch {
      setExported("failed");
    }
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
          <>
            {TERMINAL.has(status) &&
              (report?.downloadPath ? (
                <ButtonLink href={report.downloadPath} variant="primary" download>
                  Télécharger le rapport
                </ButtonLink>
              ) : (
                <Button onClick={exportReport} disabled={exported === "busy"}>
                  {exported === "busy"
                    ? "rédaction en cours…"
                    : exported === "failed"
                      ? "Réessayer l'export"
                      : "Générer le rapport"}
                </Button>
              ))}
            <DeleteRun runId={runId} />
          </>
        }
      />

      {/* ── Progress ───────────────────────────────────────────────────── */}
      <section className="border-b border-line px-6 py-7 lg:px-10">
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

        {logs.length > 0 && running && (
          <div className="mt-6 max-h-40 overflow-auto border border-line bg-void p-4">
            {logs.map((l, i) => (
              <p key={i} className="font-mono text-label text-ash">
                <span className="text-line-bright">{String(i + 1).padStart(3, "0")} </span>
                {l}
              </p>
            ))}
          </div>
        )}
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
