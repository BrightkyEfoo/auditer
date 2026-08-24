import { mkdir, writeFile, rename, readdir, rm, symlink, stat } from "node:fs/promises";
import { join, resolve } from "node:path";
import { gunzip } from "node:zlib";
import { promisify } from "node:util";
import { pathToFileURL } from "node:url";
import {
  parseEpssCsv,
  parseKevJson,
  sha256,
  VULN_FEEDS_MANIFEST_VERSION,
  VULN_FEEDS_PATH_ENV,
  type VulnFeedsManifest,
} from "./vuln-feeds.js";

const gunzipAsync = promisify(gunzip);

/**
 * Refresh the offline EPSS + CISA-KEV snapshot.
 *
 * This is the ONLY place in the system that talks to these two services, and it
 * runs on the control-plane host (cron / ops command), never inside a scanner
 * sandbox — scanner containers have no network at all. The audit pipeline only
 * ever reads the directory this writes.
 *
 * It validates with the SAME parsers the loader uses (parseEpssCsv/parseKevJson),
 * so a feed that would fail at read time fails HERE instead, while the previous
 * snapshot is still the live one. A bad download must never become the current
 * snapshot.
 *
 * Layout written under <root>:
 *   2026-08-23/epss_scores.csv.gz
 *   2026-08-23/known_exploited_vulnerabilities.json
 *   2026-08-23/manifest.json
 *   current -> 2026-08-23        (relative symlink, flipped last)
 *
 * The symlink is RELATIVE so it still resolves inside a container that
 * bind-mounts <root> at a different path. An absolute target would dangle.
 * Snapshots are kept, not overwritten, so an old run can be re-explained with
 * the exact data it used.
 *
 * Data licensing: EPSS is FIRST.org's, free to use with attribution. The CISA
 * KEV catalog is US-government public domain.
 */

/**
 * EPSS publishes a dated file per day. The `-current` alias 302-redirects to
 * today's dated file, so we request the alias and read the date back out of the
 * CSV's own `score_date` header rather than trusting the local clock — the
 * refresh host's timezone must not decide what a snapshot is called.
 *
 * The feed moved from first.org/epss.cyentia.com to epss.empiricalsecurity.com;
 * the older hosts still redirect here, verified 2026-08-24.
 */
const EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz";
const KEV_URL =
  "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

const EPSS_FILE = "epss_scores.csv.gz";
const KEV_FILE = "known_exploited_vulnerabilities.json";

/**
 * Sanity floors. The real 2026-08-23 snapshot carries 363 829 EPSS rows and
 * 1 674 KEV entries; both feeds only ever grow. These catch a truncated
 * response or an error page served with a 200, which is the realistic failure
 * mode for a public CDN-fronted file.
 */
const MIN_EPSS_ROWS = 200_000;
const MIN_KEV_ENTRIES = 800;

/** Keep this many snapshots so an audit can be replayed against its own data. */
const DEFAULT_KEEP = 10;

export interface RefreshOptions {
  /** Snapshot root. Defaults to $VULN_FEEDS_HOST_PATH. */
  dir?: string;
  keep?: number;
  epssUrl?: string;
  kevUrl?: string;
  /** Per-request timeout, ms. */
  timeoutMs?: number;
  /** Download attempts per feed before giving up. */
  attempts?: number;
}

export interface RefreshResult {
  snapshotDir: string;
  manifest: VulnFeedsManifest;
}

export async function refreshVulnFeeds(options: RefreshOptions = {}): Promise<RefreshResult> {
  const configured = options.dir ?? process.env[VULN_FEEDS_PATH_ENV];
  if (!configured) {
    throw new Error(
      `No output directory: pass --dir=<path> or set ${VULN_FEEDS_PATH_ENV}.`,
    );
  }
  const root = resolve(configured);
  const epssUrl = options.epssUrl ?? EPSS_URL;
  const kevUrl = options.kevUrl ?? KEV_URL;
  const timeoutMs = options.timeoutMs ?? 120_000;
  const attempts = options.attempts ?? 4;

  log(`fetching EPSS  ${epssUrl}`);
  const epssGz = await download(epssUrl, timeoutMs, attempts);
  log(`fetching KEV   ${kevUrl}`);
  const kevRaw = await download(kevUrl, timeoutMs, attempts);

  // Validate by fully parsing, with the loader's own parsers. Anything that
  // throws here leaves the existing `current` snapshot untouched.
  const epssCsv = (await gunzipAsync(epssGz)) as Buffer;
  const epss = parseEpssCsv(epssCsv);
  const kev = parseKevJson(kevRaw);

  if (epss.rows < MIN_EPSS_ROWS) {
    throw new Error(
      `EPSS feed has only ${epss.rows} rows (floor ${MIN_EPSS_ROWS}); refusing a truncated download.`,
    );
  }
  if (kev.count < MIN_KEV_ENTRIES) {
    throw new Error(
      `KEV feed has only ${kev.count} entries (floor ${MIN_KEV_ENTRIES}); refusing a truncated download.`,
    );
  }

  // The EPSS score_date dates the whole snapshot: it is the fast-moving half of
  // the pair and it is stamped by the publisher, not by us.
  const snapshotDate = epss.scoreDate.slice(0, 10);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(snapshotDate)) {
    throw new Error(`EPSS score_date "${epss.scoreDate}" is not a usable date.`);
  }

  const manifest: VulnFeedsManifest = {
    manifestVersion: VULN_FEEDS_MANIFEST_VERSION,
    snapshotDate,
    generatedAt: new Date().toISOString(),
    epss: {
      file: EPSS_FILE,
      sha256: sha256(epssGz),
      bytes: epssGz.length,
      modelVersion: epss.modelVersion,
      scoreDate: epss.scoreDate,
      rows: epss.rows,
    },
    kev: {
      file: KEV_FILE,
      sha256: sha256(kevRaw),
      bytes: kevRaw.length,
      catalogVersion: kev.catalogVersion,
      dateReleased: kev.dateReleased,
      count: kev.count,
    },
    sources: { epss: epssUrl, kev: kevUrl },
  };

  const snapshotDir = join(root, snapshotDate);
  await mkdir(snapshotDir, { recursive: true });
  // Write the payloads before the manifest: the manifest is what the loader
  // looks for, so it must not exist until the files it checksums do.
  await writeFile(join(snapshotDir, EPSS_FILE), epssGz);
  await writeFile(join(snapshotDir, KEV_FILE), kevRaw);
  await writeFile(join(snapshotDir, "manifest.json"), JSON.stringify(manifest, null, 2) + "\n");

  await flipCurrent(root, snapshotDate);
  await prune(root, snapshotDate, options.keep ?? DEFAULT_KEEP);

  log(
    `snapshot ${snapshotDate}: ${epss.rows} EPSS rows (model ${epss.modelVersion}), ` +
      `${kev.count} KEV entries (catalog ${kev.catalogVersion})`,
  );
  log(`current -> ${snapshotDate} in ${root}`);
  return { snapshotDir, manifest };
}

/**
 * Download with bounded retry.
 *
 * Both feeds are multi-megabyte files off public CDNs, and a mid-transfer
 * ECONNRESET is a routine event on a daily cron — observed while building this.
 * Failing the whole refresh on one reset would leave the deployment a day
 * staler for no reason, so transient transport errors get a few attempts with
 * linear backoff. An HTTP 4xx is NOT retried: that is the feed telling us the
 * URL is wrong, and hammering it will not change the answer.
 *
 * `fetch` reports every transport failure as the opaque "fetch failed"; the
 * useful detail is on `err.cause`, so it is unwrapped into the message rather
 * than left for whoever reads the cron log at 4am.
 */
async function download(url: string, timeoutMs: number, attempts: number): Promise<Buffer> {
  let lastError = "";
  for (let attempt = 1; attempt <= attempts; attempt++) {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), timeoutMs);
    try {
      const res = await fetch(url, {
        signal: ctrl.signal,
        redirect: "follow",
        headers: { "user-agent": "auditer-vuln-feeds/1 (+offline enrichment refresh)" },
      });
      if (res.status >= 400 && res.status < 500) {
        throw new FatalDownloadError(`GET ${url} -> HTTP ${res.status} ${res.statusText}`);
      }
      if (!res.ok) throw new Error(`HTTP ${res.status} ${res.statusText}`);
      return Buffer.from(await res.arrayBuffer());
    } catch (err) {
      if (err instanceof FatalDownloadError) throw err;
      lastError = describe(err);
      if (attempt < attempts) {
        log(`attempt ${attempt}/${attempts} failed (${lastError}); retrying`);
        await sleep(attempt * 2_000);
      }
    } finally {
      clearTimeout(timer);
    }
  }
  throw new Error(`GET ${url} failed after ${attempts} attempts: ${lastError}`);
}

class FatalDownloadError extends Error {
  override readonly name = "FatalDownloadError";
}

/** Unwrap undici's "fetch failed" into the transport error that actually happened. */
function describe(err: unknown): string {
  const e = err as { message?: string; cause?: { message?: string; code?: string } };
  const cause = e?.cause?.message ?? e?.cause?.code;
  return cause ? `${e.message} (${cause})` : (e?.message ?? String(err));
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

/**
 * Flip `current` atomically. symlink() cannot replace an existing link, so we
 * create a uniquely named one and rename() over the old — rename is atomic on
 * POSIX, which means a concurrently starting worker sees either the old
 * snapshot or the new one, never a missing `current`.
 */
async function flipCurrent(root: string, target: string): Promise<void> {
  const tmp = join(root, `.current.${process.pid}.${Date.now()}`);
  await symlink(target, tmp, "dir");
  await rename(tmp, join(root, "current"));
}

/** Drop the oldest snapshots; names sort lexicographically because they are ISO dates. */
async function prune(root: string, keepDate: string, keep: number): Promise<void> {
  if (keep <= 0) return;
  const entries = await readdir(root, { withFileTypes: true });
  const snapshots = entries
    .filter((e) => e.isDirectory() && /^\d{4}-\d{2}-\d{2}$/.test(e.name))
    .map((e) => e.name)
    .sort()
    .reverse();
  for (const name of snapshots.slice(keep)) {
    if (name === keepDate) continue;
    await rm(join(root, name), { recursive: true, force: true });
    log(`pruned old snapshot ${name}`);
  }
}

function log(msg: string): void {
  process.stdout.write(`[vuln-feeds] ${msg}\n`);
}

/**
 * CLI entry. Guarded so importing this module (it lives in a library package)
 * never triggers a network fetch — only running the file directly does.
 */
async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const get = (name: string): string | undefined => {
    const hit = args.find((a) => a.startsWith(`--${name}=`));
    return hit?.slice(name.length + 3);
  };
  const keepArg = get("keep");
  const dir = get("dir");

  // Fail early and legibly when the target is a file rather than a directory.
  if (dir) {
    const s = await stat(dir).catch(() => null);
    if (s && !s.isDirectory()) throw new Error(`--dir=${dir} exists and is not a directory.`);
  }

  const attemptsArg = get("attempts");
  await refreshVulnFeeds({
    dir,
    keep: keepArg === undefined ? undefined : Number.parseInt(keepArg, 10),
    attempts: attemptsArg === undefined ? undefined : Number.parseInt(attemptsArg, 10),
    epssUrl: get("epss-url"),
    kevUrl: get("kev-url"),
  });
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((err: unknown) => {
    process.stderr.write(`[vuln-feeds] refresh FAILED: ${describe(err)}\n`);
    // Nonzero so a cron wrapper notices. The previous snapshot stays current.
    process.exit(1);
  });
}
