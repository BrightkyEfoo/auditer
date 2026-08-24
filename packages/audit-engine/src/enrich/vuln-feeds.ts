import { readFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { gunzip } from "node:zlib";
import { promisify } from "node:util";
import { join, resolve } from "node:path";
import type { Severity, VulnEnrichment } from "@auditer/types";
import { SEVERITY_RANK } from "@auditer/types";

const gunzipAsync = promisify(gunzip);

/**
 * EPSS + CISA-KEV enrichment for vulnerability findings.
 *
 * WHY THIS EXISTS: ~58% of NVD CVEs are rated high/critical, so sorting by CVSS
 * sorts nothing. EPSS gives a 30-day exploitation probability; CISA KEV lists
 * what is *actually* being exploited (1 674 entries against ~364 000 scored
 * CVEs in the 2026-08-23 snapshot — under 0.5%). Together they turn "340
 * vulnerabilities" into "4 exploited in the wild today", which is the single
 * biggest noise reduction available to this product.
 *
 * WHERE IT RUNS: the CONTROL PLANE only, never inside a scanner sandbox.
 * Scanner containers have no network by design (see infra/compose), and this
 * module deliberately performs no network I/O at all — it reads a pre-fetched,
 * checksummed snapshot from a read-only mount refreshed out of band by
 * infra/scripts/refresh-vuln-feeds.sh. In the pipeline it belongs AFTER SARIF
 * normalization and AFTER dedup (see orchestrator.aggregate), so we enrich one
 * representative per issue instead of every duplicate row.
 *
 * DETERMINISM: every enriched value is dated by the snapshot it came from. The
 * caller MUST persist `snapshotDate` on the AuditRun (AuditRun.vulnFeedsSnapshot);
 * without it, two analyses of the same commit on two days produce two different
 * scores and the "deterministic audit" claim is false.
 *
 * Attribution: EPSS data is FIRST.org's, free to use with attribution. The CISA
 * KEV catalog is US-government public domain.
 */

// ─────────────────────────────────────────────────────────────────────────
// Manifest — written by the refresh script, read here
// ─────────────────────────────────────────────────────────────────────────

/** Bumped when the on-disk layout changes in a way an old loader can't read. */
export const VULN_FEEDS_MANIFEST_VERSION = 1;

export interface VulnFeedFileEntry {
  /** File name relative to the snapshot directory. */
  file: string;
  /** SHA-256 of the stored bytes, hex. Verified at load time. */
  sha256: string;
  bytes: number;
}

export interface VulnFeedsManifest {
  manifestVersion: number;
  /**
   * The authoritative snapshot date (YYYY-MM-DD), taken from the EPSS feed's own
   * `score_date` header rather than from the clock of whatever machine ran the
   * refresh. EPSS is the fast-moving half of the pair, so it dates the run.
   */
  snapshotDate: string;
  /** When the refresh script ran (ISO instant). Used as the cache key. */
  generatedAt: string;
  epss: VulnFeedFileEntry & { modelVersion: string; scoreDate: string; rows: number };
  kev: VulnFeedFileEntry & { catalogVersion: string; dateReleased: string; count: number };
  sources: { epss: string; kev: string };
}

// ─────────────────────────────────────────────────────────────────────────
// Parsers — shared by the refresh script (write-time validation) and the
// loader (read-time parsing), so one definition of "valid feed" exists.
// ─────────────────────────────────────────────────────────────────────────

/**
 * EPSS scores are published with exactly 5 decimals (`0.03351`, `0.99999`,
 * `1.0`). Storing them as integers scaled by 1e5 is therefore lossless against
 * the published data, and lets one Number carry both fields.
 */
const EPSS_SCALE = 100_000;
/** 100 001 distinct scaled values (0..100000 inclusive) — the packing radix. */
const EPSS_PACK_RADIX = EPSS_SCALE + 1;

/**
 * Pack (score, percentile) into a single Number.
 *
 * MEASURED, not estimated — real 2026-08-23 feed, 363 829 rows, Node 22.17,
 * heapUsed delta around a forced GC:
 *   Map<string, {score, percentile}>  →  47.2 MiB  (136 B/entry)
 *   Map<string, packedNumber>         →  25.3 MiB  ( 73 B/entry)
 * End-to-end through loadVulnFeeds(), including the 1 674-entry KEV map:
 *   25.8 MiB resident, 266 ms to read + gunzip + parse both feeds.
 *
 * The object-per-entry variant costs an extra ~22 MiB of permanently resident
 * heap in a long-lived api/worker process and carries no extra information, so
 * we pack. Max packed value is 100000*100001+100000 ≈ 1.0e10, far inside 2^53.
 */
function packEpss(score: number, percentile: number): number {
  return Math.round(score * EPSS_SCALE) * EPSS_PACK_RADIX + Math.round(percentile * EPSS_SCALE);
}

function unpackEpss(packed: number): EpssScore {
  return {
    score: Math.floor(packed / EPSS_PACK_RADIX) / EPSS_SCALE,
    percentile: (packed % EPSS_PACK_RADIX) / EPSS_SCALE,
  };
}

export interface EpssScore {
  /** Probability of exploitation in the next 30 days, 0-1. */
  score: number;
  /** Rank of that probability among all scored CVEs, 0-1. */
  percentile: number;
}

export interface ParsedEpss {
  modelVersion: string;
  /** ISO instant from the feed header, e.g. "2026-08-23T12:03:05Z". */
  scoreDate: string;
  /** CVE id (upper-case) → packed score. */
  index: Map<string, number>;
  rows: number;
}

const NEWLINE = 0x0a;
const COMMA = 0x2c;
const HASH = 0x23;

/**
 * Parse the gzip-decompressed EPSS CSV.
 *
 * Real format, verified against a live download rather than the docs:
 *   line 1: `#model_version:v2026.06.15,score_date:2026-08-23T12:03:05Z`
 *   line 2: `cve,epss,percentile`
 *   line 3+: `CVE-1999-0001,0.03351,0.87778`
 *
 * Parsed straight off the Buffer on purpose: `Buffer.toString()` always
 * allocates a FLAT string, whereas `bigString.slice()` returns a V8 SlicedString
 * that keeps its 11 MB parent alive. Slicing would have pinned the whole
 * decompressed CSV in memory behind the 364 k keys; going through the Buffer
 * lets it be collected as soon as parsing returns.
 */
export function parseEpssCsv(buf: Buffer): ParsedEpss {
  const index = new Map<string, number>();
  let modelVersion = "";
  let scoreDate = "";
  let rows = 0;
  let lineNo = 0;

  let start = 0;
  const len = buf.length;
  while (start < len) {
    let end = buf.indexOf(NEWLINE, start);
    if (end === -1) end = len;
    // Tolerate CRLF; the feed is LF today but a proxy could rewrite it.
    const stop = end > start && buf[end - 1] === 0x0d ? end - 1 : end;
    if (stop > start) {
      lineNo += 1;
      if (buf[start] === HASH) {
        // Header comment carries the provenance we date the whole run by.
        const meta = buf.toString("latin1", start + 1, stop);
        modelVersion = matchMeta(meta, "model_version") ?? modelVersion;
        scoreDate = matchMeta(meta, "score_date") ?? scoreDate;
      } else {
        const c1 = buf.indexOf(COMMA, start);
        if (c1 !== -1 && c1 < stop) {
          const c2 = buf.indexOf(COMMA, c1 + 1);
          if (c2 !== -1 && c2 < stop) {
            const cve = buf.toString("latin1", start, c1);
            // Skips the `cve,epss,percentile` header row without special-casing
            // its position, and skips any future junk row just as quietly.
            if (isCveId(cve)) {
              const score = Number.parseFloat(buf.toString("latin1", c1 + 1, c2));
              const percentile = Number.parseFloat(buf.toString("latin1", c2 + 1, stop));
              if (Number.isFinite(score) && Number.isFinite(percentile)) {
                index.set(cve.toUpperCase(), packEpss(clamp01(score), clamp01(percentile)));
                rows += 1;
              }
            }
          }
        }
      }
    }
    start = end + 1;
  }

  if (!scoreDate) {
    throw new VulnFeedFormatError(
      `EPSS CSV has no \`score_date\` header comment (read ${lineNo} lines). ` +
        `Without it the snapshot cannot be dated, and an undated snapshot breaks run determinism.`,
    );
  }
  if (rows === 0) {
    throw new VulnFeedFormatError("EPSS CSV contained no parseable CVE rows.");
  }
  return { modelVersion, scoreDate, index, rows };
}

function matchMeta(meta: string, key: string): string | undefined {
  for (const part of meta.split(",")) {
    const sep = part.indexOf(":");
    if (sep === -1) continue;
    if (part.slice(0, sep).trim() === key) return part.slice(sep + 1).trim();
  }
  return undefined;
}

export interface KevRecord {
  /** Date CISA added it to the catalog, `YYYY-MM-DD` (the feed's own granularity). */
  dateAdded: string;
  /** True when CISA marks the CVE as used in ransomware campaigns. */
  knownRansomware: boolean;
}

export interface ParsedKev {
  catalogVersion: string;
  dateReleased: string;
  index: Map<string, KevRecord>;
  count: number;
}

/**
 * Parse the CISA KEV catalog.
 *
 * Real format, verified against a live download:
 *   { title, catalogVersion: "2026.08.21", dateReleased: "2026-08-21T17:46:43.6019Z",
 *     count: 1674,
 *     vulnerabilities: [{ cveID, vendorProject, product, vulnerabilityName,
 *                         dateAdded: "YYYY-MM-DD", shortDescription, requiredAction,
 *                         dueDate, knownRansomwareCampaignUse: "Known"|"Unknown",
 *                         notes, cwes: [] }] }
 * `knownRansomwareCampaignUse` really is the string "Known"/"Unknown", not a
 * boolean — anything other than "Known" is treated as not-known-ransomware,
 * because "Unknown" means CISA has no evidence, not that there is none.
 */
export function parseKevJson(buf: Buffer): ParsedKev {
  let doc: unknown;
  try {
    doc = JSON.parse(buf.toString("utf8"));
  } catch (err) {
    throw new VulnFeedFormatError(`KEV feed is not valid JSON: ${(err as Error).message}`);
  }
  if (typeof doc !== "object" || doc === null) {
    throw new VulnFeedFormatError("KEV feed root is not an object.");
  }
  const root = doc as {
    catalogVersion?: unknown;
    dateReleased?: unknown;
    count?: unknown;
    vulnerabilities?: unknown;
  };
  if (!Array.isArray(root.vulnerabilities)) {
    throw new VulnFeedFormatError("KEV feed has no `vulnerabilities` array.");
  }

  const index = new Map<string, KevRecord>();
  for (const entry of root.vulnerabilities) {
    if (typeof entry !== "object" || entry === null) continue;
    const e = entry as { cveID?: unknown; dateAdded?: unknown; knownRansomwareCampaignUse?: unknown };
    if (typeof e.cveID !== "string" || !isCveId(e.cveID)) continue;
    index.set(e.cveID.toUpperCase(), {
      dateAdded: typeof e.dateAdded === "string" ? e.dateAdded : "",
      knownRansomware: e.knownRansomwareCampaignUse === "Known",
    });
  }

  if (index.size === 0) {
    throw new VulnFeedFormatError("KEV feed contained no usable CVE entries.");
  }
  // A shrinking catalog means a truncated or wrong file — CISA only ever adds.
  const declared = typeof root.count === "number" ? root.count : index.size;
  if (declared > 0 && index.size < declared * 0.9) {
    throw new VulnFeedFormatError(
      `KEV feed declares ${declared} entries but only ${index.size} parsed; refusing a truncated catalog.`,
    );
  }

  return {
    catalogVersion: typeof root.catalogVersion === "string" ? root.catalogVersion : "",
    dateReleased: typeof root.dateReleased === "string" ? root.dateReleased : "",
    index,
    count: index.size,
  };
}

export class VulnFeedFormatError extends Error {
  override readonly name = "VulnFeedFormatError";
}

/** Strict CVE id shape. GHSA/OSV/GO ids are legitimate but not keys in either feed. */
const CVE_RE = /^CVE-\d{4}-\d{4,}$/i;
function isCveId(s: string): boolean {
  return CVE_RE.test(s);
}

function clamp01(n: number): number {
  return n < 0 ? 0 : n > 1 ? 1 : n;
}

// ─────────────────────────────────────────────────────────────────────────
// The in-memory index
// ─────────────────────────────────────────────────────────────────────────

export interface VulnFeedsStats {
  epssRows: number;
  kevEntries: number;
  /** Approximate resident heap of the two maps, bytes (see packEpss note). */
  approxBytes: number;
}

/**
 * Both feeds, indexed by CVE id, loaded once and shared by every enrichment
 * call in the process. Immutable: a refreshed snapshot produces a NEW index
 * rather than mutating this one, so an in-flight run keeps the snapshot it
 * started with and stays internally consistent.
 */
export class VulnFeedsIndex {
  readonly manifest: VulnFeedsManifest;
  /** `YYYY-MM-DD` — persist on AuditRun.vulnFeedsSnapshot. */
  readonly snapshotDate: string;
  readonly stats: VulnFeedsStats;

  readonly #epss: Map<string, number>;
  readonly #kev: Map<string, KevRecord>;

  constructor(manifest: VulnFeedsManifest, epss: Map<string, number>, kev: Map<string, KevRecord>) {
    this.manifest = manifest;
    this.snapshotDate = manifest.snapshotDate;
    this.#epss = epss;
    this.#kev = kev;
    // 73 B/entry for the packed EPSS map and ~150 B/entry for the KEV records,
    // both measured rather than guessed. Reported so a deployment can size the
    // api/worker containers instead of discovering the number under load.
    this.stats = {
      epssRows: epss.size,
      kevEntries: kev.size,
      approxBytes: epss.size * 73 + kev.size * 150,
    };
  }

  /** EPSS score for a CVE id, or undefined when the feed does not score it. */
  epss(cveId: string): EpssScore | undefined {
    const packed = this.#epss.get(cveId.toUpperCase());
    return packed === undefined ? undefined : unpackEpss(packed);
  }

  /** KEV record for a CVE id, or undefined when it is not known-exploited. */
  kev(cveId: string): KevRecord | undefined {
    return this.#kev.get(cveId.toUpperCase());
  }
}

// ─────────────────────────────────────────────────────────────────────────
// Loading — the only I/O in this module. Degrades, never throws.
// ─────────────────────────────────────────────────────────────────────────

export type VulnFeedsWarningCode =
  | "not_configured"
  | "manifest_missing"
  | "manifest_invalid"
  | "file_missing"
  | "checksum_mismatch"
  | "feed_invalid"
  | "snapshot_stale"
  /**
   * Emitted by the pure enrichment step when it is handed no index. It does not
   * know WHY — the specific cause was reported by loadVulnFeeds — so it says
   * only what it can honestly observe rather than guessing at a reason.
   */
  | "feeds_unavailable";

export interface VulnFeedsWarning {
  code: VulnFeedsWarningCode;
  message: string;
}

/**
 * How old a snapshot may be before we refuse to use it. EPSS is republished
 * daily, so a week of slack absorbs a failed cron or a weekend without letting
 * a genuinely abandoned mount through.
 *
 * Past that we return NO data rather than stale data: an EPSS score is a 30-day
 * forecast, and a month-old forecast presented as today's is a silently wrong
 * number in an audit report. A missing score is visible; a wrong one is not.
 */
export const DEFAULT_MAX_SNAPSHOT_AGE_DAYS = 7;

/** Env var naming mirrors OSV_DB_HOST_PATH (see infra/compose/docker-compose.server.yml). */
export const VULN_FEEDS_PATH_ENV = "VULN_FEEDS_HOST_PATH";

export interface LoadVulnFeedsOptions {
  /**
   * Snapshot root. Accepts either a directory holding `manifest.json`, or a
   * root holding a `current/` symlink to one. Defaults to $VULN_FEEDS_HOST_PATH.
   */
  dir?: string;
  /** Clock injection point, so staleness is testable. */
  now?: Date;
  maxAgeDays?: number;
  /** Skip SHA-256 verification (tests only — it is the corruption backstop). */
  skipChecksums?: boolean;
  /** Bypass the process-wide cache. */
  force?: boolean;
}

export interface LoadVulnFeedsResult {
  /** null whenever the feeds are unusable — callers must handle it, not assume. */
  feeds: VulnFeedsIndex | null;
  warnings: VulnFeedsWarning[];
}

/**
 * Process-wide memo. Keyed on the resolved snapshot directory plus the
 * manifest's `generatedAt`, so a refreshed mount is picked up without a restart
 * while a re-read of the same snapshot costs one ~1 KB manifest stat.
 */
let cache: { key: string; feeds: VulnFeedsIndex } | null = null;

/** Test seam — drops the memo so a fixture change is observed. */
export function resetVulnFeedsCache(): void {
  cache = null;
}

export async function loadVulnFeeds(
  options: LoadVulnFeedsOptions = {},
): Promise<LoadVulnFeedsResult> {
  const warnings: VulnFeedsWarning[] = [];
  const configured = options.dir ?? process.env[VULN_FEEDS_PATH_ENV];
  if (!configured) {
    warnings.push({
      code: "not_configured",
      message:
        `${VULN_FEEDS_PATH_ENV} is not set; EPSS/KEV enrichment is disabled. ` +
        `Mount a snapshot produced by infra/scripts/refresh-vuln-feeds.sh.`,
    });
    return { feeds: null, warnings };
  }

  const root = resolve(configured);
  // Two accepted layouts: point straight at a snapshot, or at the root that
  // holds the `current` symlink the refresh script flips.
  let dir = root;
  let manifestRaw: Buffer;
  try {
    manifestRaw = await readFile(join(dir, "manifest.json"));
  } catch {
    dir = join(root, "current");
    try {
      manifestRaw = await readFile(join(dir, "manifest.json"));
    } catch {
      warnings.push({
        code: "manifest_missing",
        message: `No manifest.json under ${root} or ${dir}; EPSS/KEV enrichment is disabled.`,
      });
      return { feeds: null, warnings };
    }
  }

  let manifest: VulnFeedsManifest;
  try {
    manifest = parseManifest(manifestRaw);
  } catch (err) {
    warnings.push({
      code: "manifest_invalid",
      message: `Unusable manifest in ${dir}: ${(err as Error).message}`,
    });
    return { feeds: null, warnings };
  }

  // Staleness is checked BEFORE the ~4 MB of reads and hashing — a stale
  // snapshot is not going to be used, so there is no point parsing it.
  const ageDays = snapshotAgeDays(manifest.snapshotDate, options.now ?? new Date());
  const maxAge = options.maxAgeDays ?? DEFAULT_MAX_SNAPSHOT_AGE_DAYS;
  if (ageDays === null) {
    warnings.push({
      code: "manifest_invalid",
      message: `Manifest snapshotDate "${manifest.snapshotDate}" is not a YYYY-MM-DD date.`,
    });
    return { feeds: null, warnings };
  }
  if (ageDays > maxAge) {
    warnings.push({
      code: "snapshot_stale",
      message:
        `EPSS/KEV snapshot ${manifest.snapshotDate} is ${ageDays} days old (limit ${maxAge}); ` +
        `findings left un-enriched rather than scored from a stale forecast. ` +
        `Re-run infra/scripts/refresh-vuln-feeds.sh.`,
    });
    return { feeds: null, warnings };
  }

  const key = `${dir} ${manifest.generatedAt}`;
  if (!options.force && cache && cache.key === key) {
    return { feeds: cache.feeds, warnings };
  }

  let epssBuf: Buffer;
  let kevBuf: Buffer;
  try {
    [epssBuf, kevBuf] = await Promise.all([
      readFile(join(dir, manifest.epss.file)),
      readFile(join(dir, manifest.kev.file)),
    ]);
  } catch (err) {
    warnings.push({
      code: "file_missing",
      message: `Manifest references a file that could not be read: ${(err as Error).message}`,
    });
    return { feeds: null, warnings };
  }

  if (!options.skipChecksums) {
    // Catches the truncated download / half-finished rsync that would otherwise
    // surface as a plausible-looking but wrong set of scores.
    for (const [label, buf, expected] of [
      ["EPSS", epssBuf, manifest.epss.sha256],
      ["KEV", kevBuf, manifest.kev.sha256],
    ] as const) {
      const actual = sha256(buf);
      if (actual !== expected) {
        warnings.push({
          code: "checksum_mismatch",
          message: `${label} feed checksum mismatch in ${dir} (expected ${expected}, got ${actual}); enrichment disabled.`,
        });
        return { feeds: null, warnings };
      }
    }
  }

  let parsedEpss: ParsedEpss;
  let parsedKev: ParsedKev;
  try {
    const epssCsv = await gunzipAsync(epssBuf);
    parsedEpss = parseEpssCsv(epssCsv as Buffer);
    parsedKev = parseKevJson(kevBuf);
  } catch (err) {
    warnings.push({
      code: "feed_invalid",
      message: `Feed under ${dir} failed to parse: ${(err as Error).message}`,
    });
    return { feeds: null, warnings };
  }

  const feeds = new VulnFeedsIndex(manifest, parsedEpss.index, parsedKev.index);
  cache = { key, feeds };
  return { feeds, warnings };
}

function parseManifest(buf: Buffer): VulnFeedsManifest {
  const doc = JSON.parse(buf.toString("utf8")) as Partial<VulnFeedsManifest>;
  if (typeof doc.manifestVersion !== "number") throw new Error("missing manifestVersion");
  if (doc.manifestVersion > VULN_FEEDS_MANIFEST_VERSION) {
    throw new Error(
      `manifestVersion ${doc.manifestVersion} is newer than this build understands (${VULN_FEEDS_MANIFEST_VERSION})`,
    );
  }
  if (typeof doc.snapshotDate !== "string") throw new Error("missing snapshotDate");
  if (typeof doc.generatedAt !== "string") throw new Error("missing generatedAt");
  if (!doc.epss?.file || !doc.epss?.sha256) throw new Error("missing epss file entry");
  if (!doc.kev?.file || !doc.kev?.sha256) throw new Error("missing kev file entry");
  return doc as VulnFeedsManifest;
}

/** Whole days between a `YYYY-MM-DD` snapshot and now; null when unparseable. */
function snapshotAgeDays(snapshotDate: string, now: Date): number | null {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(snapshotDate)) return null;
  const t = Date.parse(`${snapshotDate}T00:00:00Z`);
  if (Number.isNaN(t)) return null;
  return Math.floor((now.getTime() - t) / 86_400_000);
}

export function sha256(buf: Buffer): string {
  return createHash("sha256").update(buf).digest("hex");
}

// ─────────────────────────────────────────────────────────────────────────
// Enrichment — pure
// ─────────────────────────────────────────────────────────────────────────

/**
 * Structural minimum this module needs. Matches both RawFinding and Finding, so
 * the caller can enrich before or after the Finding rows are materialized.
 */
export interface VulnEnrichable {
  vulnIds?: string[];
  vuln?: VulnEnrichment;
}

export interface VulnEnrichmentStats {
  total: number;
  /** Findings carrying at least one CVE id. */
  withCve: number;
  /** Findings that matched at least one feed. */
  enriched: number;
  epssMatched: number;
  kevMatched: number;
}

export interface VulnEnrichmentResult<T> {
  findings: T[];
  warnings: VulnFeedsWarning[];
  /** `YYYY-MM-DD`, or null when nothing was enriched. Persist on the AuditRun. */
  snapshotDate: string | null;
  stats: VulnEnrichmentStats;
}

/**
 * Attach EPSS/KEV data to every finding that carries a CVE. Pure: same inputs,
 * same outputs, no clock, no I/O. Findings are copied, never mutated.
 *
 * ALIAS RESOLUTION. A single finding routinely carries several identifiers —
 * osv-scanner emits the OSV id plus every alias, so `["GHSA-xxxx", "CVE-2024-1",
 * "CVE-2024-2"]` is normal. Only CVE ids key either feed, so non-CVE ids are
 * skipped rather than treated as misses. Across the CVE ids we keep:
 *
 *   - EPSS: the HIGHEST score. The finding is one concrete vulnerable package;
 *     if any identifier for it is being exploited, the package is at that risk.
 *     Averaging would dilute a real signal with unrelated aliases, and taking
 *     the first would make the result depend on scanner ordering — neither is
 *     defensible in an audit report.
 *   - The percentile is taken FROM THE CVE THAT WON the score, not maximized
 *     independently. A (score, percentile) pair from two different CVEs would be
 *     internally inconsistent and unexplainable to a reader.
 *   - KEV: listed if ANY id is in the catalog — same OR-logic as EPSS-max, and
 *     KEV is an assertion of observed exploitation that an alias cannot dilute.
 *   - kevDateAdded: the EARLIEST match, which answers "how long has this been
 *     known-exploited" rather than "which alias did we happen to look up last".
 *   - kevRansomware: true if ANY match is flagged, since CISA's "Unknown" means
 *     absence of evidence, not evidence of absence.
 *
 * `epssCveId`/`kevCveId` record WHICH identifier produced the value, because an
 * audit report has to be able to answer "where did this number come from".
 *
 * DEGRADATION: `feeds === null` returns the findings untouched with a warning.
 * Never throws, never invents a score, never silently reports zero.
 */
export function enrichWithVulnFeeds<T extends VulnEnrichable>(
  findings: readonly T[],
  feeds: VulnFeedsIndex | null,
): VulnEnrichmentResult<T> {
  const stats: VulnEnrichmentStats = {
    total: findings.length,
    withCve: 0,
    enriched: 0,
    epssMatched: 0,
    kevMatched: 0,
  };

  if (!feeds) {
    return {
      // Copy so the caller never gets an aliased array back on the degraded
      // path but a fresh one on the happy path.
      findings: [...findings],
      warnings: [
        {
          code: "feeds_unavailable",
          message:
            "EPSS/KEV feeds unavailable; findings returned un-enriched. " +
            "Prioritization falls back to severity + CVSS, which does not separate real risk.",
        },
      ],
      snapshotDate: null,
      stats,
    };
  }

  const out = findings.map((finding) => {
    const cveIds = (finding.vulnIds ?? []).filter(isCveId);
    if (cveIds.length === 0) return finding;
    stats.withCve += 1;

    let epssScore: number | undefined;
    let epssPercentile: number | undefined;
    let epssCveId: string | undefined;

    let kevListed = false;
    let kevDateAdded: string | undefined;
    let kevRansomware = false;
    let kevCveId: string | undefined;

    for (const raw of cveIds) {
      const cve = raw.toUpperCase();

      const e = feeds.epss(cve);
      if (e && (epssScore === undefined || e.score > epssScore)) {
        epssScore = e.score;
        epssPercentile = e.percentile;
        epssCveId = cve;
      }

      const k = feeds.kev(cve);
      if (k) {
        kevListed = true;
        if (k.knownRansomware) kevRansomware = true;
        // Earliest dateAdded wins; ISO dates compare correctly as strings.
        if (k.dateAdded && (kevDateAdded === undefined || k.dateAdded < kevDateAdded)) {
          kevDateAdded = k.dateAdded;
          kevCveId = cve;
        } else if (kevCveId === undefined) {
          kevCveId = cve;
        }
      }
    }

    if (epssScore === undefined && !kevListed) {
      // A CVE the feeds do not know. Leaving `vuln` absent is the honest
      // encoding: "not scored" must not be readable as "scored zero".
      return finding;
    }

    stats.enriched += 1;
    if (epssScore !== undefined) stats.epssMatched += 1;
    if (kevListed) stats.kevMatched += 1;

    const vuln: VulnEnrichment = {
      ...finding.vuln,
      ...(epssScore !== undefined ? { epssScore, epssPercentile, epssCveId } : {}),
      kevListed,
      // Legacy alias kept in lockstep: `knownExploited` predates this module and
      // may already be read elsewhere. One writer, two names, never divergent.
      knownExploited: kevListed,
      ...(kevDateAdded !== undefined ? { kevDateAdded } : {}),
      ...(kevListed ? { kevRansomware, kevCveId } : {}),
    };

    return { ...finding, vuln };
  });

  return { findings: out, warnings: [], snapshotDate: feeds.snapshotDate, stats };
}

/**
 * Convenience wrapper: load the mounted snapshot (cached) and enrich in one
 * call. This is the pipeline entry point; `enrichWithVulnFeeds` stays pure and
 * separately testable underneath it.
 */
export async function enrichFindingsFromFeeds<T extends VulnEnrichable>(
  findings: readonly T[],
  options: LoadVulnFeedsOptions = {},
): Promise<VulnEnrichmentResult<T>> {
  const { feeds, warnings } = await loadVulnFeeds(options);
  const result = enrichWithVulnFeeds(findings, feeds);
  return { ...result, warnings: [...warnings, ...result.warnings] };
}

// ─────────────────────────────────────────────────────────────────────────
// Prioritization — a DISPLAY ORDER, not a score
// ─────────────────────────────────────────────────────────────────────────

/**
 * EPSS below this is treated as carrying no usable signal.
 *
 * Roughly 90% of scored CVEs sit under 1%, so ordering strictly by raw EPSS
 * would let a 0.04%-probability dependency CVE outrank a hardcoded production
 * credential simply because the credential has no EPSS at all. The floor
 * collapses that statistical noise into one tier where severity decides, and
 * keeps EPSS authoritative exactly where it is meaningful.
 *
 * Pass `epssMaterialityFloor: 0` for the strict "KEV, then raw EPSS, then
 * severity, then CVSS" ordering with no floor.
 */
export const EPSS_MATERIALITY_FLOOR = 0.01;

/** Common "act on this" EPSS threshold, used for headline counts only. */
export const EPSS_HIGH_THRESHOLD = 0.1;

export interface PrioritizableFinding {
  severity: Severity;
  cvssScore?: number;
  vuln?: VulnEnrichment;
  /** Final deterministic tie-break; every RawFinding carries one. */
  fingerprint?: string;
}

export interface PrioritizeOptions {
  epssMaterialityFloor?: number;
}

/**
 * Total order over findings, worst first.
 *
 *   1. CISA KEV listed. The only tier grounded in OBSERVED exploitation rather
 *      than prediction. Under 0.5% of scored CVEs qualify, and it is the answer
 *      to "what do I fix this afternoon".
 *   2. EPSS descending, above the materiality floor. Forecast probability of
 *      exploitation in the next 30 days — the best available ranking among the
 *      vast majority of CVEs that are not KEV-listed.
 *   3. Severity. Governs everything with no meaningful exploitation signal:
 *      secrets, SAST, quality, and CVEs the feeds do not score. This is where
 *      non-CVE findings live, and why the floor above exists.
 *   4. CVSS descending. Impact-if-exploited, the last discriminator — useful
 *      only once likelihood has already been accounted for, which is precisely
 *      the inversion this whole function exists to correct.
 *   5. Fingerprint. Not a risk signal: it makes the order total, so the same
 *      finding set renders identically on every run regardless of input order.
 *
 * NOT a score. The scoring formula in ../scoring/index.ts is untouched and
 * remains the single source of the audit grade.
 */
export function comparePriority(
  a: PrioritizableFinding,
  b: PrioritizableFinding,
  epssMaterialityFloor: number = EPSS_MATERIALITY_FLOOR,
): number {
  const kevA = a.vuln?.kevListed === true ? 1 : 0;
  const kevB = b.vuln?.kevListed === true ? 1 : 0;
  if (kevA !== kevB) return kevB - kevA;

  const epssA = materialEpss(a, epssMaterialityFloor);
  const epssB = materialEpss(b, epssMaterialityFloor);
  if (epssA !== epssB) return epssB - epssA;

  const sevA = SEVERITY_RANK[a.severity] ?? 0;
  const sevB = SEVERITY_RANK[b.severity] ?? 0;
  if (sevA !== sevB) return sevB - sevA;

  const cvssA = a.cvssScore ?? 0;
  const cvssB = b.cvssScore ?? 0;
  if (cvssA !== cvssB) return cvssB - cvssA;

  return (a.fingerprint ?? "").localeCompare(b.fingerprint ?? "");
}

function materialEpss(f: PrioritizableFinding, floor: number): number {
  const s = f.vuln?.epssScore;
  if (s === undefined || s < floor) return 0;
  return s;
}

/** Worst-first ordering. Returns a new array; the input is not mutated. */
export function prioritizeFindings<T extends PrioritizableFinding>(
  findings: readonly T[],
  options: PrioritizeOptions = {},
): T[] {
  const floor = options.epssMaterialityFloor ?? EPSS_MATERIALITY_FLOOR;
  return [...findings].sort((a, b) => comparePriority(a, b, floor));
}

export interface ExploitabilitySummary {
  total: number;
  /** Known-exploited in the wild today — the headline number. */
  kevListed: number;
  kevRansomware: number;
  /** EPSS >= EPSS_HIGH_THRESHOLD but not KEV-listed. */
  epssHigh: number;
  /** `YYYY-MM-DD` the numbers above are true as of. */
  snapshotDate: string | null;
}

/**
 * The counts that turn "340 vulnerabilities" into "4 exploited in the wild".
 * Reported alongside the snapshot date, because both numbers are only true as
 * of a given day and stating one without the other is misleading.
 */
export function summarizeExploitability(
  findings: readonly PrioritizableFinding[],
  snapshotDate: string | null = null,
): ExploitabilitySummary {
  let kevListed = 0;
  let kevRansomware = 0;
  let epssHigh = 0;
  for (const f of findings) {
    const kev = f.vuln?.kevListed === true;
    if (kev) {
      kevListed += 1;
      if (f.vuln?.kevRansomware === true) kevRansomware += 1;
    } else if ((f.vuln?.epssScore ?? 0) >= EPSS_HIGH_THRESHOLD) {
      epssHigh += 1;
    }
  }
  return { total: findings.length, kevListed, kevRansomware, epssHigh, snapshotDate };
}
