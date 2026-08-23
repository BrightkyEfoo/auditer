import Link from "next/link";
import { SEVERITIES, sevBg } from "@/components/ui";
import { ago, grade, gradeTone, STATUS_FR, type AuditRunSummary } from "@/lib/api";
import { cn } from "@/lib/cn";

const RUNNING = new Set(["queued", "cloning", "scanning", "analyzing", "reporting"]);

/**
 * One run as a dense hairline row: state, target, severity distribution, score.
 * Rows rather than cards — a list of runs is a table of measurements, and cards
 * would spend three times the vertical space to say the same thing.
 */
export function RunRow({ run }: { run: AuditRunSummary }) {
  const total = SEVERITIES.reduce((n, s) => n + (run.counts?.[s] ?? 0), 0);
  const running = RUNNING.has(run.status);
  const failed = run.status === "failed" || run.status === "canceled";

  return (
    <li>
      <Link
        href={`/audits/${run.id}`}
        className="group grid grid-cols-12 items-center gap-x-4 gap-y-3 border-b border-line py-4 transition-colors duration-[180ms] hover:bg-slate/60"
      >
        {/* State */}
        <div className="col-span-6 flex min-w-0 items-center gap-3 lg:col-span-4">
          <span
            aria-hidden
            className={cn(
              "h-1.5 w-1.5 shrink-0",
              failed ? "bg-critical" : running ? "animate-pulse-dot bg-acid" : "bg-line-bright",
            )}
          />
          <div className="min-w-0">
            <p className="truncate font-mono text-data text-mineral">
              {run.repository?.fullName ?? "cible web"}
            </p>
            <p className="mt-0.5 font-mono text-label uppercase text-mute">
              {STATUS_FR[run.status] ?? run.status} · {ago(run.createdAt)}
            </p>
          </div>
        </div>

        {/* Pillars */}
        <p className="col-span-6 hidden truncate font-mono text-label uppercase text-mute lg:col-span-3 lg:block">
          {run.pillars.join(" · ")}
        </p>

        {/* Severity distribution as one stacked bar — proportion reads faster
            than five numbers. */}
        <div className="col-span-6 lg:col-span-3">
          {total > 0 ? (
            <>
              <div className="flex h-1.5 w-full overflow-hidden bg-line">
                {SEVERITIES.map((s) =>
                  run.counts[s] > 0 ? (
                    <span
                      key={s}
                      className={sevBg(s)}
                      style={{ width: `${(run.counts[s] / total) * 100}%` }}
                    />
                  ) : null,
                )}
              </div>
              <p className="mt-1.5 font-mono text-label uppercase text-mute">
                {total} finding(s)
                {run.counts.critical > 0 && (
                  <span className="text-critical"> · {run.counts.critical} critique(s)</span>
                )}
              </p>
            </>
          ) : (
            <p className="font-mono text-label uppercase text-mute">
              {running ? "en cours" : "aucun finding"}
            </p>
          )}
        </div>

        {/* Score */}
        <div className="col-span-6 flex items-baseline justify-end gap-2 lg:col-span-2">
          <span className={cn("font-display text-[1.5rem] font-bold leading-none tracking-tightest", gradeTone(run.riskScore))}>
            {run.riskScore ?? "—"}
          </span>
          <span className={cn("font-mono text-data", gradeTone(run.riskScore))}>
            {grade(run.riskScore)}
          </span>
          <span
            aria-hidden
            className="ml-2 font-mono text-label text-line-bright transition-colors duration-[180ms] group-hover:text-acid"
          >
            →
          </span>
        </div>
      </Link>
    </li>
  );
}
