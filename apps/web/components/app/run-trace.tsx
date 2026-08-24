"use client";

import { Label } from "@/components/ui";
import { cn } from "@/lib/cn";

/**
 * The live trace of a run: one row per engine, plus the phase notes between
 * them.
 *
 * It replaces a flat list of strings that said "osv-scanner — running" and then
 * nothing for nine and a half minutes. A reader could not tell a scanner that
 * was working from one that was stuck, and once a run had failed there was
 * nothing left to read at all. Every column here answers a question someone
 * actually asks: how long, why it stopped, and which binary produced the
 * result.
 *
 * `exitCode` earns its place on its own: the difference between "found nothing"
 * and "was killed by the memory limit" is exit 0 versus exit 137, and no other
 * field distinguishes them.
 */

export interface TraceEntry {
  kind: "scan" | "note" | "phase";
  at: string;
  tool?: string;
  pillar?: string;
  status?: string;
  findingCount?: number;
  durationMs?: number;
  exitCode?: number;
  image?: string;
  reason?: string;
  message?: string;
}

const STATUS_FR: Record<string, string> = {
  running: "en cours",
  success: "réussi",
  partial: "partiel",
  failed: "échec",
  skipped: "ignoré",
};

function tone(status?: string): string {
  switch (status) {
    case "success":
      return "text-acid";
    case "failed":
      return "text-critical";
    case "partial":
      return "text-high";
    case "skipped":
      return "text-mute";
    default:
      return "text-ash";
  }
}

function ms(n?: number): string {
  if (n == null) return "";
  if (n < 1000) return `${n} ms`;
  const s = n / 1000;
  if (s < 60) return `${s.toFixed(1)} s`;
  return `${Math.floor(s / 60)} min ${Math.round(s % 60)} s`;
}

/** Digest references are unreadable in full; keep the tag or the first bytes. */
function shortImage(ref?: string): string | null {
  if (!ref) return null;
  const [name = ref, digest] = ref.split("@sha256:");
  const base = name.split("/").pop() ?? name;
  return digest ? `${base}@${digest.slice(0, 10)}` : base;
}

export function RunTrace({ entries }: { entries: TraceEntry[] }) {
  if (entries.length === 0) return null;

  return (
    <div className="mt-6 border border-line bg-void">
      <div className="flex items-center justify-between border-b border-line px-4 py-2.5">
        <Label className="text-acid">Trace d&apos;exécution</Label>
        <span className="font-mono text-label uppercase text-mute">
          {entries.filter((e) => e.kind === "scan").length} événement(s) moteur
        </span>
      </div>

      <ol className="max-h-80 overflow-auto">
        {entries.map((e, i) => (
          <li
            key={i}
            className="grid grid-cols-12 items-baseline gap-x-3 border-b border-line/60 px-4 py-2 last:border-b-0"
          >
            <span className="col-span-2 font-mono text-label text-line-bright sm:col-span-1">
              {e.at.slice(11, 19)}
            </span>

            {e.kind === "scan" ? (
              <>
                <span className="col-span-4 truncate font-mono text-data text-mineral sm:col-span-2">
                  {e.tool}
                </span>
                <span className={cn("col-span-3 font-mono text-label uppercase sm:col-span-1", tone(e.status))}>
                  {STATUS_FR[e.status ?? ""] ?? e.status}
                </span>
                <span className="col-span-3 font-mono text-label text-ash sm:col-span-1">
                  {e.findingCount != null && e.status !== "running"
                    ? `${e.findingCount} finding(s)`
                    : ""}
                </span>
                <span className="col-span-6 font-mono text-label text-mute sm:col-span-1">
                  {ms(e.durationMs)}
                </span>
                <span className="col-span-6 truncate font-mono text-label text-mute sm:col-span-3">
                  {shortImage(e.image)}
                </span>
                {/* The reason is the whole point: an engine that stopped must
                    say why, or its silence reads as a clean pillar. */}
                <span
                  className={cn(
                    "col-span-12 font-mono text-label sm:col-span-3",
                    e.status === "failed" ? "text-critical" : "text-mute",
                  )}
                >
                  {e.reason ?? (e.exitCode != null && e.exitCode !== 0 ? `exit ${e.exitCode}` : "")}
                </span>
              </>
            ) : (
              <span
                className={cn(
                  "col-span-10 font-mono text-label sm:col-span-11",
                  e.kind === "phase" ? "uppercase text-acid" : "text-ash",
                )}
              >
                {e.message}
              </span>
            )}
          </li>
        ))}
      </ol>
    </div>
  );
}
