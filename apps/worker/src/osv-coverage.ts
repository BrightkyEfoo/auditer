import { readFile } from "node:fs/promises";
import { join } from "node:path";

/**
 * Provenance of the offline OSV database, for the report.
 *
 * "Aucune vulnérabilité connue" is a claim about a dataset, not about the code.
 * A report that cannot name the dataset — how many ecosystems it covers, how old
 * it is — states something timeless it has no basis for. This reads the manifest
 * written by packages/audit-engine/src/enrich/refresh-osv-db.ts so the claim can
 * carry its own limits.
 *
 * The worker mounts the database read-only for this and only this. Matching
 * itself happens inside the scanner container, which gets its own mount.
 *
 * Every failure resolves to `null` rather than throwing: a missing manifest must
 * degrade the report to "provenance non disponible", which is honest, and must
 * never fail a run that already produced findings.
 */

interface ManifestEntry {
  ecosystem: string;
  entries: number;
  lastModified?: string;
  error?: string;
}

interface Manifest {
  generatedAt?: string;
  ecosystems?: ManifestEntry[];
}

export interface OsvCoverage {
  /** Ecosystems with a usable archive on disk. */
  covered: string[];
  /** Listed but unusable — the gap a reader needs to see, not a blank. */
  missing: string[];
  /** Total advisories across the covered archives. */
  advisories: number;
  /** Oldest `last-modified` among the covered archives, ISO date. */
  oldest: string | null;
  /** When the refresher last ran, ISO instant. */
  refreshedAt: string | null;
}

export async function readOsvCoverage(root = process.env.OSV_DB_HOST_PATH): Promise<OsvCoverage | null> {
  if (!root) return null;
  let manifest: Manifest;
  try {
    manifest = JSON.parse(await readFile(join(root, "manifest.json"), "utf8")) as Manifest;
  } catch {
    return null;
  }
  const rows = manifest.ecosystems ?? [];
  if (rows.length === 0) return null;

  const covered: string[] = [];
  const missing: string[] = [];
  let advisories = 0;
  let oldest: string | null = null;

  for (const row of rows) {
    // `entries > 0` and not `!error`: an ecosystem whose refresh failed but whose
    // previous archive is still on disk DID contribute to the verdict, and
    // listing it as missing would understate the coverage as badly as hiding it
    // would overstate it.
    if (row.entries > 0) {
      covered.push(row.ecosystem);
      advisories += row.entries;
      const stamp = toIsoDate(row.lastModified);
      if (stamp && (oldest === null || stamp < oldest)) oldest = stamp;
    } else {
      missing.push(row.ecosystem);
    }
  }

  return {
    covered,
    missing,
    advisories,
    oldest,
    refreshedAt: manifest.generatedAt ?? null,
  };
}

/** HTTP `last-modified` is RFC 7231; the report shows a date, not a header. */
function toIsoDate(value: string | undefined): string | null {
  if (!value) return null;
  const t = Date.parse(value);
  return Number.isNaN(t) ? null : new Date(t).toISOString().slice(0, 10);
}
