import { mkdir, writeFile, rename, readFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { createHash } from "node:crypto";

/**
 * Refresh the OFFLINE OSV database, one archive per ecosystem.
 *
 * Why this exists, and it is not a nicety: the SCA pillar runs osv-scanner with
 * `--experimental-offline` inside a sandbox that has no network, matching
 * against `<root>/osv-scanner/<Ecosystem>/all.zip`. The server carried exactly
 * one of those archives — `npm` — placed there by hand on 2026-08-23, with no
 * cron, no timer and no deploy step to renew it. Two consequences, both
 * measured rather than assumed:
 *
 *   - Any repository that is not npm got NO dependency coverage at all.
 *     Reproduced on a Python + Go repository: osv-scanner prints
 *     `could not find local databases for ecosystems: Go, PyPI`, emits
 *     `{"results": []}` on stdout and exits 127. The exit code is what saves
 *     us here — `classifyExit` maps it to a failed scan rather than to a clean
 *     pillar — but a failed scan is still a hole, and the customer's report
 *     simply had no dependency verdict.
 *   - The one archive that did exist would age forever. A vulnerability
 *     database that stops being updated does not announce itself; it just
 *     stops finding things.
 *
 * Like refresh-feeds.ts, this runs on the control-plane host, never inside a
 * scanner sandbox, and it is the only place in the system that talks to the OSV
 * bucket. Each archive is validated then swapped in atomically, so a truncated
 * download or an error page served with a 200 leaves the PREVIOUS archive live.
 * A stale database is a bad answer; a corrupt one is a scan that fails for a
 * reason nobody can read.
 *
 * The manifest it writes is what lets a report state the age and provenance of
 * the data behind a "no known vulnerabilities" line, instead of implying the
 * claim is timeless.
 */

const OSV_BUCKET = "https://osv-vulnerabilities.storage.googleapis.com";

/** Where osv-scanner looks, relative to OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY. */
const SUBDIR = "osv-scanner";

export const OSV_DB_MANIFEST_FILE = "manifest.json";

/**
 * The ecosystems osv-scanner 1.9.2 can resolve from a source checkout, which is
 * all this product scans. Distribution ecosystems (Alpine, Debian, Ubuntu, …)
 * are deliberately absent: they answer questions about a built container image,
 * not about a repository, and each is a large archive that would be downloaded
 * on every deploy to be matched against nothing.
 *
 * Adding a name here is not free — osv-scanner must actually detect a manifest
 * for it, or the archive is dead weight. Removing one silently deletes coverage
 * for a whole language, which is the failure this file exists to close, so a
 * removal belongs in a commit that says why.
 */
export const OSV_ECOSYSTEMS = [
  "npm", // package-lock.json, yarn.lock, pnpm-lock.yaml
  "PyPI", // requirements.txt, poetry.lock, Pipfile.lock, pdm.lock
  "Go", // go.mod
  "Maven", // pom.xml, gradle.lockfile
  "crates.io", // Cargo.lock
  "Packagist", // composer.lock
  "RubyGems", // Gemfile.lock
  "NuGet", // packages.lock.json, *.csproj
  "Hex", // mix.lock
  "Pub", // pubspec.lock
  "CRAN", // renv.lock
  "Hackage", // cabal.project.freeze, stack.yaml.lock
  "SwiftURL", // Package.resolved
  // No `ConanCenter`: osv-scanner names that ecosystem, but the OSV bucket
  // publishes no archive for it (HTTP 404, verified 2026-08-24). Listing it
  // produced a hard failure on every refresh for coverage that does not exist
  // to be had. C/C++ dependencies are therefore NOT covered by this pillar.
] as const;

export type OsvEcosystem = (typeof OSV_ECOSYSTEMS)[number];

/**
 * Floor on archive entries, per ecosystem. Every OSV archive holds one JSON
 * advisory per entry plus an index, so an archive that suddenly holds three
 * files is a truncated transfer or an error document, not a quiet week in that
 * language. The floors are deliberately far below the real counts observed on
 * 2026-08-24 (npm ≈ 4 500, Pub ≈ 30) — they exist to catch a broken download,
 * not to police upstream's publishing rate.
 */
const MIN_ENTRIES: Record<string, number> = {
  npm: 2000,
  PyPI: 2000,
  Go: 500,
  Maven: 1000,
  "crates.io": 300,
  Packagist: 1000,
  RubyGems: 300,
  NuGet: 200,
  Hex: 20,
  Pub: 5,
  CRAN: 5,
  Hackage: 5,
  SwiftURL: 5,
};

const DEFAULT_MIN_ENTRIES = 5;

export interface OsvDbEntry {
  ecosystem: string;
  file: string;
  bytes: number;
  sha256: string;
  entries: number;
  lastModified?: string;
  refreshed: boolean;
  error?: string;
}

export interface OsvDbManifest {
  manifestVersion: 1;
  generatedAt: string;
  source: string;
  ecosystems: OsvDbEntry[];
}

export interface RefreshOsvOptions {
  /** Database root — the directory holding `osv-scanner/`. */
  dir?: string;
  ecosystems?: readonly string[];
  timeoutMs?: number;
  attempts?: number;
}

export async function refreshOsvDb(options: RefreshOsvOptions = {}): Promise<OsvDbManifest> {
  const configured = options.dir ?? process.env.OSV_DB_HOST_PATH;
  if (!configured) {
    throw new Error("No output directory: pass --dir=<path> or set OSV_DB_HOST_PATH.");
  }
  const root = resolve(configured);
  const ecosystems = options.ecosystems ?? OSV_ECOSYSTEMS;
  const timeoutMs = options.timeoutMs ?? 300_000;
  const attempts = options.attempts ?? 4;

  // Previous manifest drives conditional requests below.
  const previousManifest = await readManifest(root);
  const entries: OsvDbEntry[] = [];
  let failures = 0;

  for (const ecosystem of ecosystems) {
    const url = `${OSV_BUCKET}/${encodeURIComponent(ecosystem)}/all.zip`;
    const dir = join(root, SUBDIR, ecosystem);
    const target = join(dir, "all.zip");
    const prior = previousManifest?.ecosystems.find((e) => e.ecosystem === ecosystem);
    try {
      log(`fetching ${ecosystem}`);
      // Conditional on the archive we already hold. The npm archive alone is
      // 210 MiB and this runs on every deploy; without this, shipping a
      // one-line change would move half a gigabyte to learn nothing. The
      // condition is only offered when the file is genuinely still on disk —
      // a manifest entry whose archive was deleted must re-download, not 304.
      const onDisk = prior?.lastModified ? await describeExisting(root, ecosystem) : null;
      const since = onDisk && onDisk.bytes > 0 ? prior?.lastModified : undefined;
      const { body, lastModified, notModified } = await download(url, timeoutMs, attempts, since);
      if (notModified) {
        entries.push({ ...onDisk!, ecosystem, file: `${SUBDIR}/${ecosystem}/all.zip`, lastModified: prior!.lastModified, refreshed: false });
        log(`  ${ecosystem}: inchange (${onDisk!.entries} avis)`);
        continue;
      }
      const count = countZipEntries(body);
      const floor = MIN_ENTRIES[ecosystem] ?? DEFAULT_MIN_ENTRIES;
      if (count < floor) {
        throw new Error(`${count} entries (floor ${floor}) — refusing a truncated archive`);
      }

      // Write beside the target then rename: `rename` within a directory is
      // atomic, so a scan starting mid-refresh reads either the old archive or
      // the new one, never a half-written file. osv-scanner opens this archive
      // read-only from a container while the refresh may be running on the host.
      await mkdir(dir, { recursive: true });
      const tmp = `${target}.tmp`;
      await writeFile(tmp, body);
      await rename(tmp, target);

      entries.push({
        ecosystem,
        file: `${SUBDIR}/${ecosystem}/all.zip`,
        bytes: body.length,
        sha256: createHash("sha256").update(body).digest("hex"),
        entries: count,
        lastModified,
        refreshed: true,
      });
      log(`  ${ecosystem}: ${count} advisories, ${(body.length / 1048576).toFixed(1)} MiB`);
    } catch (err) {
      // One ecosystem failing must not discard the thirteen that succeeded, and
      // must not delete what is already on disk. It is recorded in the manifest
      // so the staleness is READABLE rather than inferred from a missing file.
      failures++;
      const message = err instanceof Error ? err.message : String(err);
      const previous = await describeExisting(root, ecosystem);
      entries.push({
        ...previous,
        ecosystem,
        file: `${SUBDIR}/${ecosystem}/all.zip`,
        refreshed: false,
        error: message,
      });
      log(`  ${ecosystem}: ECHEC — ${message}${previous.bytes ? " (archive precedente conservee)" : ""}`);
    }
  }

  const manifest: OsvDbManifest = {
    manifestVersion: 1,
    generatedAt: new Date().toISOString(),
    source: OSV_BUCKET,
    ecosystems: entries,
  };
  await mkdir(root, { recursive: true });
  await writeFile(join(root, OSV_DB_MANIFEST_FILE), JSON.stringify(manifest, null, 2) + "\n");

  const covered = entries.filter((e) => e.entries > 0).length;
  log(`${covered}/${ecosystems.length} ecosystemes disponibles dans ${root}`);
  if (failures > 0) {
    // Non-zero so a deploy step or cron surfaces it, even though the archives
    // that did land are already usable.
    throw new Error(`${failures} ecosysteme(s) non rafraichi(s) — voir le manifeste`);
  }
  return manifest;
}

async function readManifest(root: string): Promise<OsvDbManifest | null> {
  try {
    return JSON.parse(await readFile(join(root, OSV_DB_MANIFEST_FILE), "utf8")) as OsvDbManifest;
  } catch {
    return null;
  }
}

/** Size/checksum of the archive already on disk, so a failure is not a blank row. */
async function describeExisting(
  root: string,
  ecosystem: string,
): Promise<Pick<OsvDbEntry, "bytes" | "sha256" | "entries">> {
  try {
    const buf = await readFile(join(root, SUBDIR, ecosystem, "all.zip"));
    return {
      bytes: buf.length,
      sha256: createHash("sha256").update(buf).digest("hex"),
      entries: countZipEntries(buf),
    };
  } catch {
    return { bytes: 0, sha256: "", entries: 0 };
  }
}

/**
 * Entry count from the ZIP end-of-central-directory record.
 *
 * Reading the EOCD rather than inflating the archive is the point: it is O(1),
 * it needs no zip library, and it fails on exactly what we are guarding
 * against — a truncated transfer or an HTML error page served with HTTP 200,
 * neither of which carries a valid EOCD.
 */
export function countZipEntries(buf: Buffer): number {
  // EOCD is 22 bytes plus a comment of at most 65 535; scan back from the end.
  const min = Math.max(0, buf.length - (22 + 0xffff));
  for (let i = buf.length - 22; i >= min; i--) {
    if (buf.readUInt32LE(i) === 0x06054b50) {
      const total = buf.readUInt16LE(i + 10);
      // 0xffff is the ZIP64 sentinel, and it is not hypothetical: the npm
      // archive holds more than 65 535 advisories and reaches us as ZIP64.
      // Treating the sentinel as unreadable rejected the single largest, most
      // consulted ecosystem in the database — caught only because the refresher
      // reported it as empty instead of quietly shipping it.
      if (total === 0xffff) return countZip64Entries(buf, i);
      return total;
    }
  }
  throw new Error("pas d'enregistrement de fin d'archive ZIP (telechargement tronque ?)");
}

/**
 * ZIP64 entry count.
 *
 * The classic EOCD is preceded by a 20-byte locator holding the absolute offset
 * of the ZIP64 EOCD record, whose entry count is a 64-bit field. Read through
 * the locator rather than scanning for the record: a scan could match those four
 * bytes inside compressed data, and a wrong count here would either reject a
 * good archive or accept a truncated one.
 */
function countZip64Entries(buf: Buffer, eocdOffset: number): number {
  const locator = eocdOffset - 20;
  if (locator < 0 || buf.readUInt32LE(locator) !== 0x07064b50) {
    throw new Error("archive ZIP64 sans localisateur de fin (telechargement tronque ?)");
  }
  const recordOffset = Number(buf.readBigUInt64LE(locator + 8));
  if (recordOffset < 0 || recordOffset + 56 > buf.length) {
    throw new Error("archive ZIP64 tronquee avant son enregistrement de fin");
  }
  if (buf.readUInt32LE(recordOffset) !== 0x06064b50) {
    throw new Error("enregistrement de fin ZIP64 introuvable a l'offset annonce");
  }
  return Number(buf.readBigUInt64LE(recordOffset + 32));
}

class FatalDownloadError extends Error {}

async function download(
  url: string,
  timeoutMs: number,
  attempts: number,
  ifModifiedSince?: string,
): Promise<{ body: Buffer; lastModified?: string; notModified?: boolean }> {
  let lastError = "";
  for (let attempt = 1; attempt <= attempts; attempt++) {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), timeoutMs);
    try {
      const headers: Record<string, string> = {
        "user-agent": "auditer-osv-db/1 (+offline SCA database refresh)",
      };
      if (ifModifiedSince) headers["if-modified-since"] = ifModifiedSince;
      const res = await fetch(url, { signal: ctrl.signal, redirect: "follow", headers });
      if (res.status === 304) return { body: Buffer.alloc(0), notModified: true };
      // A 4xx is upstream telling us the ecosystem name is wrong. Retrying will
      // not change the answer, and a typo here silently removes a language from
      // the product's coverage — so it must stop the refresh, loudly.
      if (res.status >= 400 && res.status < 500) {
        throw new FatalDownloadError(`GET ${url} -> HTTP ${res.status} ${res.statusText}`);
      }
      if (!res.ok) throw new Error(`GET ${url} -> HTTP ${res.status} ${res.statusText}`);
      const body = Buffer.from(await res.arrayBuffer());
      return { body, lastModified: res.headers.get("last-modified") ?? undefined };
    } catch (err) {
      if (err instanceof FatalDownloadError) throw err;
      lastError = unwrap(err);
      if (attempt < attempts) {
        await new Promise((r) => setTimeout(r, attempt * 2000));
      }
    } finally {
      clearTimeout(timer);
    }
  }
  throw new Error(`${url}: ${lastError}`);
}

/** `fetch` reports every transport failure as "fetch failed"; the detail is on cause. */
function unwrap(err: unknown): string {
  if (!(err instanceof Error)) return String(err);
  const cause = (err as { cause?: unknown }).cause;
  if (cause instanceof Error) return `${err.message}: ${cause.message}`;
  return err.message;
}

function log(message: string): void {
  process.stdout.write(`[osv-db] ${message}\n`);
}

// CLI: node dist/enrich/refresh-osv-db.js --dir=/path/to/osv-db
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const dirArg = process.argv.slice(2).find((a) => a.startsWith("--dir="));
  refreshOsvDb({ dir: dirArg?.slice("--dir=".length) }).catch((err: unknown) => {
    process.stderr.write(`[osv-db] ${err instanceof Error ? err.message : String(err)}\n`);
    process.exit(1);
  });
}
