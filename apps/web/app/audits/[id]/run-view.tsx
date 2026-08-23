"use client";

import { useEffect, useState, useCallback } from "react";
import { api, eventsUrl, type AuditRun, type Finding } from "@/lib/api";

const STEPS = ["queued", "cloning", "scanning", "analyzing", "reporting", "done"];
const TERMINAL = new Set(["done", "completed_with_errors", "failed", "canceled"]);

const SEV_ORDER = ["critical", "high", "medium", "low", "info"];
const SEV_CLASS: Record<string, string> = {
  critical: "bg-critical",
  high: "bg-high",
  medium: "bg-medium",
  low: "bg-low",
  info: "bg-info",
};

export function RunView({ runId }: { runId: string }) {
  const [run, setRun] = useState<AuditRun | null>(null);
  const [status, setStatus] = useState<string>("queued");
  const [logs, setLogs] = useState<string[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [sevFilter, setSevFilter] = useState<string | null>(null);

  const refreshFindings = useCallback(() => {
    api.listFindings(runId).then(setFindings).catch(() => {});
  }, [runId]);

  // Snapshot the run, then tail live events.
  useEffect(() => {
    api.getAudit(runId).then((r) => {
      setRun(r);
      setStatus(r.status);
      if (TERMINAL.has(r.status)) refreshFindings();
    });

    const es = new EventSource(eventsUrl(runId));
    es.addEventListener("status", (e) => {
      const d = JSON.parse((e as MessageEvent).data);
      setStatus(d.status);
    });
    es.addEventListener("scan", (e) => {
      const d = JSON.parse((e as MessageEvent).data);
      setLogs((l) => [...l, `${d.tool}: ${d.status}${d.findingCount != null ? ` (${d.findingCount})` : ""}`]);
    });
    es.addEventListener("log", (e) => {
      const d = JSON.parse((e as MessageEvent).data);
      setLogs((l) => [...l, d.message]);
    });
    es.addEventListener("done", (e) => {
      const d = JSON.parse((e as MessageEvent).data);
      setStatus(d.status);
      api.getAudit(runId).then(setRun);
      refreshFindings();
      es.close();
    });
    es.onerror = () => es.close();
    return () => es.close();
  }, [runId, refreshFindings]);

  async function triage(f: Finding, s: string) {
    await api.setTriage(f.fingerprint, s);
    setFindings((cur) =>
      cur.map((x) => (x.fingerprint === f.fingerprint ? { ...x, triageStatus: s } : x)),
    );
  }

  const shown = sevFilter ? findings.filter((f) => f.severity === sevFilter) : findings;
  const counts = SEV_ORDER.map((s) => ({
    sev: s,
    n: findings.filter((f) => f.severity === s).length,
  }));

  return (
    <main className="space-y-8">
      {/* Progress stepper */}
      <section>
        <h1 className="mb-3 text-xl font-semibold">
          Audit run <span className="font-mono text-sm text-neutral-500">{runId}</span>
        </h1>
        <ol className="flex flex-wrap items-center gap-2 text-sm">
          {STEPS.map((s, i) => {
            const idx = STEPS.indexOf(status === "completed_with_errors" ? "done" : status);
            const state = i < idx ? "done" : i === idx ? "active" : "todo";
            return (
              <li
                key={s}
                className={`rounded-full px-3 py-1 ${
                  state === "done"
                    ? "bg-neutral-900 text-white dark:bg-white dark:text-black"
                    : state === "active"
                      ? "animate-pulse bg-blue-600 text-white"
                      : "bg-neutral-200 text-neutral-500 dark:bg-neutral-800"
                }`}
              >
                {s}
              </li>
            );
          })}
          {status === "failed" && <li className="rounded-full bg-critical px-3 py-1 text-white">failed</li>}
        </ol>
      </section>

      {/* Score */}
      {run?.riskScore != null && (
        <section className="flex items-center gap-4">
          <div className="text-4xl font-bold">{run.riskScore}</div>
          <div className="text-sm text-neutral-500">
            overall risk score
            {run.scoringVersion && <span className="ml-2">· scoring v{run.scoringVersion}</span>}
          </div>
        </section>
      )}

      {/* Live log */}
      {logs.length > 0 && !TERMINAL.has(status) && (
        <section className="max-h-40 overflow-auto rounded-md bg-neutral-900 p-3 font-mono text-xs text-neutral-100">
          {logs.map((l, i) => (
            <div key={i}>{l}</div>
          ))}
        </section>
      )}

      {/* Findings explorer */}
      <section className="space-y-3">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold">Findings ({findings.length})</h2>
          {TERMINAL.has(status) && (
            <button
              onClick={() => api.exportReport(runId)}
              className="rounded-md border border-neutral-300 px-3 py-1.5 text-sm"
            >
              Export PDF
            </button>
          )}
        </div>

        <div className="flex flex-wrap gap-2">
          <FilterChip active={sevFilter === null} onClick={() => setSevFilter(null)}>
            all ({findings.length})
          </FilterChip>
          {counts.map((c) => (
            <FilterChip
              key={c.sev}
              active={sevFilter === c.sev}
              onClick={() => setSevFilter(c.sev)}
              dot={SEV_CLASS[c.sev]}
            >
              {c.sev} ({c.n})
            </FilterChip>
          ))}
        </div>

        <div className="space-y-2">
          {shown.map((f) => (
            <FindingRow key={f.id} f={f} onTriage={triage} />
          ))}
          {shown.length === 0 && TERMINAL.has(status) && (
            <p className="text-sm text-neutral-500">No findings for this filter.</p>
          )}
        </div>
      </section>
    </main>
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
      className={`flex items-center gap-1.5 rounded-full border px-3 py-1 text-xs ${
        active ? "border-neutral-900 bg-neutral-900 text-white dark:border-white dark:bg-white dark:text-black" : "border-neutral-300"
      }`}
    >
      {dot && <span className={`h-2 w-2 rounded-full ${dot}`} />}
      {children}
    </button>
  );
}

function FindingRow({ f, onTriage }: { f: Finding; onTriage: (f: Finding, s: string) => void }) {
  const [open, setOpen] = useState(false);
  const dimmed = f.triageStatus !== "open";
  return (
    <div className={`rounded-md border border-neutral-200 dark:border-neutral-800 ${dimmed ? "opacity-50" : ""}`}>
      <button onClick={() => setOpen((o) => !o)} className="flex w-full items-center gap-3 px-4 py-3 text-left">
        <span className={`h-2.5 w-2.5 shrink-0 rounded-full ${SEV_CLASS[f.severity]}`} />
        <span className="flex-1 text-sm font-medium">{f.title}</span>
        {f.sourceCount > 1 && (
          <span className="rounded bg-neutral-200 px-1.5 py-0.5 text-[10px] dark:bg-neutral-800">
            {f.sourceCount} tools
          </span>
        )}
        {f.vulnIds.slice(0, 1).map((v) => (
          <span key={v} className="font-mono text-xs text-neutral-500">{v}</span>
        ))}
        <span className="text-xs text-neutral-400">{f.tool}</span>
      </button>

      {open && (
        <div className="space-y-3 border-t border-neutral-200 px-4 py-3 text-sm dark:border-neutral-800">
          <p className="text-neutral-600 dark:text-neutral-400">{f.description}</p>
          {f.evidence && (
            <pre className="overflow-x-auto rounded bg-neutral-100 p-2 text-xs dark:bg-neutral-900">{f.evidence}</pre>
          )}
          {f.aiExplanation && (
            <div className="rounded-md border-l-2 border-blue-500 bg-blue-50 p-3 dark:bg-blue-950/30">
              <div className="mb-1 text-xs font-semibold uppercase tracking-wide text-blue-700 dark:text-blue-300">
                AI assessment{f.aiNeedsHuman ? " · needs human review" : ""}
              </div>
              <p>{f.aiExplanation}</p>
              {f.aiRemediation && <p className="mt-2 font-medium">Fix: {f.aiRemediation}</p>}
            </div>
          )}
          <div className="flex flex-wrap gap-2 pt-1">
            {["open", "false_positive", "ignored", "accepted"].map((s) => (
              <button
                key={s}
                onClick={() => onTriage(f, s)}
                className={`rounded border px-2 py-1 text-xs ${
                  f.triageStatus === s ? "border-neutral-900 bg-neutral-900 text-white dark:border-white dark:bg-white dark:text-black" : "border-neutral-300"
                }`}
              >
                {s.replace("_", " ")}
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
