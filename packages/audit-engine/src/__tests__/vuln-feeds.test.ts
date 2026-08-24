import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp, mkdir, writeFile, symlink, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gzipSync } from "node:zlib";
import type { RawFinding, Severity } from "@auditer/types";
import {
  parseEpssCsv,
  parseKevJson,
  sha256,
  loadVulnFeeds,
  resetVulnFeedsCache,
  enrichWithVulnFeeds,
  enrichFindingsFromFeeds,
  prioritizeFindings,
  summarizeExploitability,
  VulnFeedsIndex,
  VULN_FEEDS_MANIFEST_VERSION,
  type VulnFeedsManifest,
} from "../enrich/vuln-feeds.js";

// ─────────────────────────────────────────────────────────────────────────
// Fixtures — shaped from the REAL feeds (verified by download 2026-08-24),
// not from the published documentation.
// ─────────────────────────────────────────────────────────────────────────

const EPSS_CSV = [
  "#model_version:v2026.06.15,score_date:2026-08-23T12:03:05Z",
  "cve,epss,percentile",
  "CVE-2021-44228,0.94270,0.99982", // log4shell: high EPSS + KEV
  "CVE-2024-3400,0.99999,1.0", // KEV + ransomware
  "CVE-2023-00001,0.00043,0.10000", // real but statistically negligible
  "CVE-2020-11111,0.35000,0.97000", // material EPSS, not KEV
  "CVE-2019-22222,0.02000,0.80000",
  "",
].join("\n");

const KEV_JSON = JSON.stringify({
  title: "CISA Catalog of Known Exploited Vulnerabilities",
  catalogVersion: "2026.08.21",
  dateReleased: "2026-08-21T17:46:43.6019Z",
  count: 2,
  vulnerabilities: [
    {
      cveID: "CVE-2021-44228",
      vendorProject: "Apache",
      product: "Log4j2",
      vulnerabilityName: "Apache Log4j2 Remote Code Execution Vulnerability",
      dateAdded: "2021-12-10",
      shortDescription: "…",
      requiredAction: "…",
      dueDate: "2021-12-24",
      knownRansomwareCampaignUse: "Known",
      notes: "",
      cwes: ["CWE-502"],
    },
    {
      cveID: "CVE-2024-3400",
      vendorProject: "Palo Alto Networks",
      product: "PAN-OS",
      vulnerabilityName: "PAN-OS Command Injection Vulnerability",
      dateAdded: "2024-04-12",
      shortDescription: "…",
      requiredAction: "…",
      dueDate: "2024-04-19",
      knownRansomwareCampaignUse: "Unknown",
      notes: "",
      cwes: ["CWE-77"],
    },
  ],
});

/** Feeds are validated against a >=90% parse floor, so the fixture needs bulk. */
function bulkKevJson(realEntries: number): string {
  const doc = JSON.parse(KEV_JSON) as { count: number; vulnerabilities: unknown[] };
  doc.count = realEntries;
  return JSON.stringify(doc);
}

function buildIndex(): VulnFeedsIndex {
  const epss = parseEpssCsv(Buffer.from(EPSS_CSV, "utf8"));
  const kev = parseKevJson(Buffer.from(KEV_JSON, "utf8"));
  const manifest: VulnFeedsManifest = {
    manifestVersion: VULN_FEEDS_MANIFEST_VERSION,
    snapshotDate: "2026-08-23",
    generatedAt: "2026-08-23T13:00:00.000Z",
    epss: {
      file: "epss_scores.csv.gz",
      sha256: "x",
      bytes: 1,
      modelVersion: epss.modelVersion,
      scoreDate: epss.scoreDate,
      rows: epss.rows,
    },
    kev: {
      file: "known_exploited_vulnerabilities.json",
      sha256: "x",
      bytes: 1,
      catalogVersion: kev.catalogVersion,
      dateReleased: kev.dateReleased,
      count: kev.count,
    },
    sources: { epss: "test", kev: "test" },
  };
  return new VulnFeedsIndex(manifest, epss.index, kev.index);
}

function finding(partial: Partial<RawFinding>): RawFinding {
  return {
    pillar: "sca",
    tool: "osv-scanner",
    ruleId: "r",
    severity: "medium" as Severity,
    title: "t",
    description: "",
    cwe: [],
    vulnIds: [],
    references: [],
    fingerprint: "fp",
    ...partial,
  } as RawFinding;
}

/** Write a complete on-disk snapshot, exactly as the refresh script lays it out. */
async function writeSnapshot(opts: {
  root: string;
  snapshotDate: string;
  useCurrentSymlink?: boolean;
  corruptEpss?: boolean;
}): Promise<void> {
  const dir = join(opts.root, opts.snapshotDate);
  await mkdir(dir, { recursive: true });
  const epssGz = gzipSync(Buffer.from(EPSS_CSV, "utf8"));
  const kevBuf = Buffer.from(bulkKevJson(2), "utf8");
  await writeFile(join(dir, "epss_scores.csv.gz"), epssGz);
  await writeFile(join(dir, "known_exploited_vulnerabilities.json"), kevBuf);
  const manifest: VulnFeedsManifest = {
    manifestVersion: VULN_FEEDS_MANIFEST_VERSION,
    snapshotDate: opts.snapshotDate,
    generatedAt: `${opts.snapshotDate}T13:00:00.000Z`,
    epss: {
      file: "epss_scores.csv.gz",
      // A deliberately wrong digest simulates a truncated download / half-done rsync.
      sha256: opts.corruptEpss ? "0".repeat(64) : sha256(epssGz),
      bytes: epssGz.length,
      modelVersion: "v2026.06.15",
      scoreDate: `${opts.snapshotDate}T12:03:05Z`,
      rows: 5,
    },
    kev: {
      file: "known_exploited_vulnerabilities.json",
      sha256: sha256(kevBuf),
      bytes: kevBuf.length,
      catalogVersion: "2026.08.21",
      dateReleased: "2026-08-21T17:46:43.6019Z",
      count: 2,
    },
    sources: { epss: "test", kev: "test" },
  };
  await writeFile(join(dir, "manifest.json"), JSON.stringify(manifest, null, 2));
  if (opts.useCurrentSymlink) {
    // Relative target, as the refresh script writes it — must resolve after a
    // bind mount at a different path.
    await symlink(opts.snapshotDate, join(opts.root, "current"), "dir");
  }
}

beforeEach(() => {
  resetVulnFeedsCache();
});

// ─────────────────────────────────────────────────────────────────────────

describe("feed parsing (real formats)", () => {
  it("reads the EPSS header comment that dates the snapshot", () => {
    const parsed = parseEpssCsv(Buffer.from(EPSS_CSV, "utf8"));
    expect(parsed.modelVersion).toBe("v2026.06.15");
    expect(parsed.scoreDate).toBe("2026-08-23T12:03:05Z");
    expect(parsed.rows).toBe(5);
  });

  it("round-trips score and percentile losslessly through the packed encoding", () => {
    const idx = buildIndex();
    // The feed publishes 5 decimals; packing must not perturb them.
    expect(idx.epss("CVE-2021-44228")).toEqual({ score: 0.9427, percentile: 0.99982 });
    expect(idx.epss("CVE-2024-3400")).toEqual({ score: 0.99999, percentile: 1 });
  });

  it("rejects an EPSS feed with no score_date rather than dating it from the clock", () => {
    expect(() => parseEpssCsv(Buffer.from("cve,epss,percentile\nCVE-2020-1,0.1,0.5\n"))).toThrow(
      /score_date/,
    );
  });

  it("maps knownRansomwareCampaignUse's Known/Unknown strings to a boolean", () => {
    const kev = parseKevJson(Buffer.from(KEV_JSON, "utf8"));
    expect(kev.index.get("CVE-2021-44228")?.knownRansomware).toBe(true);
    expect(kev.index.get("CVE-2024-3400")?.knownRansomware).toBe(false);
    expect(kev.catalogVersion).toBe("2026.08.21");
  });

  it("refuses a KEV catalog that parses far short of its declared count", () => {
    const truncated = JSON.stringify({
      catalogVersion: "x",
      dateReleased: "x",
      count: 1674,
      vulnerabilities: [{ cveID: "CVE-2021-44228", dateAdded: "2021-12-10" }],
    });
    expect(() => parseKevJson(Buffer.from(truncated, "utf8"))).toThrow(/truncated/);
  });
});

describe("alias resolution", () => {
  it("ignores non-CVE identifiers and scores from the CVE aliases only", () => {
    const res = enrichWithVulnFeeds(
      [finding({ vulnIds: ["GHSA-jfh8-c2jp-5v3q", "OSV-2021-1", "CVE-2021-44228"] })],
      buildIndex(),
    );
    const vuln = res.findings[0]!.vuln!;
    expect(vuln.epssScore).toBe(0.9427);
    expect(vuln.kevListed).toBe(true);
    expect(vuln.epssCveId).toBe("CVE-2021-44228");
  });

  it("takes the HIGHEST EPSS across aliases, with the matching percentile", () => {
    const res = enrichWithVulnFeeds(
      [finding({ vulnIds: ["CVE-2023-00001", "CVE-2020-11111", "CVE-2019-22222"] })],
      buildIndex(),
    );
    const vuln = res.findings[0]!.vuln!;
    expect(vuln.epssScore).toBe(0.35);
    // Percentile comes from the winning CVE, not maximized independently — a
    // pair drawn from two different CVEs would be internally inconsistent.
    expect(vuln.epssPercentile).toBe(0.97);
    expect(vuln.epssCveId).toBe("CVE-2020-11111");
  });

  it("flags KEV when ANY alias is listed, and keeps the earliest dateAdded", () => {
    const res = enrichWithVulnFeeds(
      [finding({ vulnIds: ["CVE-2024-3400", "CVE-2021-44228"] })],
      buildIndex(),
    );
    const vuln = res.findings[0]!.vuln!;
    expect(vuln.kevListed).toBe(true);
    // 2021 beats 2024: answers "how long has this been known-exploited".
    expect(vuln.kevDateAdded).toBe("2021-12-10");
    // Ransomware is an OR across aliases — "Unknown" is absence of evidence.
    expect(vuln.kevRansomware).toBe(true);
  });

  it("is case-insensitive on CVE ids", () => {
    const res = enrichWithVulnFeeds([finding({ vulnIds: ["cve-2021-44228"] })], buildIndex());
    expect(res.findings[0]!.vuln!.kevListed).toBe(true);
  });

  it("keeps the legacy knownExploited alias in lockstep with kevListed", () => {
    const res = enrichWithVulnFeeds([finding({ vulnIds: ["CVE-2021-44228"] })], buildIndex());
    const vuln = res.findings[0]!.vuln!;
    expect(vuln.knownExploited).toBe(vuln.kevListed);
  });

  it("leaves vuln absent for an unknown CVE — 'not scored' is not 'scored zero'", () => {
    const res = enrichWithVulnFeeds([finding({ vulnIds: ["CVE-1990-9999"] })], buildIndex());
    expect(res.findings[0]!.vuln).toBeUndefined();
    expect(res.stats.withCve).toBe(1);
    expect(res.stats.enriched).toBe(0);
  });

  it("leaves findings with no vulnIds (secrets, SAST) untouched", () => {
    const f = finding({ pillar: "secrets", vulnIds: [] });
    const res = enrichWithVulnFeeds([f], buildIndex());
    expect(res.findings[0]).toBe(f);
    expect(res.stats.withCve).toBe(0);
  });

  it("does not mutate its input", () => {
    const f = finding({ vulnIds: ["CVE-2021-44228"] });
    enrichWithVulnFeeds([f], buildIndex());
    expect(f.vuln).toBeUndefined();
  });

  it("reports the snapshot date the caller must persist on the AuditRun", () => {
    const res = enrichWithVulnFeeds([finding({ vulnIds: ["CVE-2021-44228"] })], buildIndex());
    expect(res.snapshotDate).toBe("2026-08-23");
  });
});

describe("graceful degradation", () => {
  let root: string;

  beforeEach(async () => {
    root = await mkdtemp(join(tmpdir(), "auditer-feeds-"));
  });

  it("returns findings unchanged, with a warning, when feeds are null", () => {
    const f = finding({ vulnIds: ["CVE-2021-44228"] });
    const res = enrichWithVulnFeeds([f], null);
    expect(res.findings).toEqual([f]);
    expect(res.findings[0]!.vuln).toBeUndefined();
    expect(res.snapshotDate).toBeNull();
    expect(res.warnings).toHaveLength(1);
    // The pure step reports only what it can observe; loadVulnFeeds owns the
    // specific cause (stale / corrupt / unconfigured).
    expect(res.warnings[0]!.code).toBe("feeds_unavailable");
  });

  it("warns instead of throwing when the path is not configured", async () => {
    const res = await loadVulnFeeds({ dir: undefined, now: new Date("2026-08-23T00:00:00Z") });
    // No env var is set in the test process, so this is the unconfigured path.
    if (!process.env.VULN_FEEDS_HOST_PATH) {
      expect(res.feeds).toBeNull();
      expect(res.warnings[0]!.code).toBe("not_configured");
    }
  });

  it("warns instead of throwing when the directory has no manifest", async () => {
    const res = await loadVulnFeeds({ dir: root, now: new Date("2026-08-23T00:00:00Z") });
    expect(res.feeds).toBeNull();
    expect(res.warnings[0]!.code).toBe("manifest_missing");
  });

  it("refuses a stale snapshot rather than reporting a month-old forecast as today's", async () => {
    await writeSnapshot({ root, snapshotDate: "2026-07-01", useCurrentSymlink: true });
    const res = await loadVulnFeeds({ dir: root, now: new Date("2026-08-23T00:00:00Z") });
    expect(res.feeds).toBeNull();
    expect(res.warnings[0]!.code).toBe("snapshot_stale");
    expect(res.warnings[0]!.message).toMatch(/53 days old/);
  });

  it("refuses a snapshot whose checksum does not match the manifest", async () => {
    await writeSnapshot({
      root,
      snapshotDate: "2026-08-23",
      useCurrentSymlink: true,
      corruptEpss: true,
    });
    const res = await loadVulnFeeds({ dir: root, now: new Date("2026-08-23T06:00:00Z") });
    expect(res.feeds).toBeNull();
    expect(res.warnings[0]!.code).toBe("checksum_mismatch");
  });

  it("degrades end-to-end: bad feeds still return every finding", async () => {
    const findings = [finding({ vulnIds: ["CVE-2021-44228"] }), finding({ vulnIds: [] })];
    const res = await enrichFindingsFromFeeds(findings, {
      dir: root,
      now: new Date("2026-08-23T00:00:00Z"),
    });
    expect(res.findings).toHaveLength(2);
    expect(res.findings[0]!.vuln).toBeUndefined();
    expect(res.snapshotDate).toBeNull();
    expect(res.warnings.length).toBeGreaterThan(0);
  });
});

describe("snapshot loading", () => {
  let root: string;

  beforeEach(async () => {
    root = await mkdtemp(join(tmpdir(), "auditer-feeds-"));
  });

  it("loads through the relative `current` symlink the refresh script writes", async () => {
    await writeSnapshot({ root, snapshotDate: "2026-08-23", useCurrentSymlink: true });
    const res = await loadVulnFeeds({ dir: root, now: new Date("2026-08-23T18:00:00Z") });
    expect(res.warnings).toHaveLength(0);
    expect(res.feeds?.snapshotDate).toBe("2026-08-23");
    expect(res.feeds?.epss("CVE-2021-44228")?.score).toBe(0.9427);
    expect(res.feeds?.kev("CVE-2021-44228")?.dateAdded).toBe("2021-12-10");
  });

  it("also accepts a path pointing straight at a snapshot directory", async () => {
    await writeSnapshot({ root, snapshotDate: "2026-08-23" });
    const res = await loadVulnFeeds({
      dir: join(root, "2026-08-23"),
      now: new Date("2026-08-23T18:00:00Z"),
    });
    expect(res.feeds?.snapshotDate).toBe("2026-08-23");
  });

  it("serves the second load from cache (the feeds are loaded once)", async () => {
    await writeSnapshot({ root, snapshotDate: "2026-08-23", useCurrentSymlink: true });
    const now = new Date("2026-08-23T18:00:00Z");
    const first = await loadVulnFeeds({ dir: root, now });
    // Delete the payloads: a cache hit must not need them again.
    await rm(join(root, "2026-08-23", "epss_scores.csv.gz"));
    const second = await loadVulnFeeds({ dir: root, now });
    expect(second.feeds).toBe(first.feeds);
  });

  it("reports a measured memory footprint for the index", () => {
    const idx = buildIndex();
    expect(idx.stats.epssRows).toBe(5);
    expect(idx.stats.kevEntries).toBe(2);
    expect(idx.stats.approxBytes).toBeGreaterThan(0);
  });
});

describe("prioritization", () => {
  function scored(
    severity: Severity,
    vuln?: { epssScore?: number; kevListed?: boolean; kevRansomware?: boolean },
    extra: Partial<RawFinding> = {},
  ): RawFinding {
    return finding({ severity, ...(vuln ? { vuln } : {}), ...extra });
  }

  it("puts a medium KEV finding ahead of a high with no EPSS", () => {
    const mediumKev = scored("medium", { kevListed: true }, { fingerprint: "a" });
    const highPlain = scored("high", undefined, { fingerprint: "b" });
    const order = prioritizeFindings([highPlain, mediumKev]);
    expect(order[0]).toBe(mediumKev);
    expect(order[1]).toBe(highPlain);
  });

  it("puts KEV ahead of a higher raw EPSS that is not KEV-listed", () => {
    const kev = scored("low", { kevListed: true, epssScore: 0.2 }, { fingerprint: "a" });
    const hotter = scored("critical", { epssScore: 0.99 }, { fingerprint: "b" });
    expect(prioritizeFindings([hotter, kev])[0]).toBe(kev);
  });

  it("orders non-KEV findings by EPSS descending", () => {
    const lo = scored("critical", { epssScore: 0.05 }, { fingerprint: "a" });
    const hi = scored("low", { epssScore: 0.6 }, { fingerprint: "b" });
    expect(prioritizeFindings([lo, hi])[0]).toBe(hi);
  });

  it("does not let a negligible EPSS outrank a critical with no exploitation signal", () => {
    // 0.043% is statistical noise; a hardcoded credential is not. Below the
    // materiality floor, severity decides.
    const noise = scored("low", { epssScore: 0.00043 }, { fingerprint: "a" });
    const secret = scored("critical", undefined, { pillar: "secrets", fingerprint: "b" });
    expect(prioritizeFindings([noise, secret])[0]).toBe(secret);
  });

  it("honours the literal KEV → raw EPSS → severity order when the floor is 0", () => {
    const noise = scored("low", { epssScore: 0.00043 }, { fingerprint: "a" });
    const secret = scored("critical", undefined, { pillar: "secrets", fingerprint: "b" });
    const order = prioritizeFindings([secret, noise], { epssMaterialityFloor: 0 });
    expect(order[0]).toBe(noise);
  });

  it("falls back to severity, then CVSS, then fingerprint", () => {
    const a = scored("high", undefined, { cvssScore: 9.1, fingerprint: "zzz" });
    const b = scored("high", undefined, { cvssScore: 7.5, fingerprint: "aaa" });
    const c = scored("high", undefined, { cvssScore: 9.1, fingerprint: "aaa" });
    const order = prioritizeFindings([b, a, c]);
    expect(order.map((f) => f.fingerprint)).toEqual(["aaa", "zzz", "aaa"]);
    expect(order[0]!.cvssScore).toBe(9.1);
    expect(order[2]!.cvssScore).toBe(7.5);
  });

  it("is a total order — input order cannot change the result", () => {
    const items = [
      scored("high", { epssScore: 0.5 }, { fingerprint: "a" }),
      scored("high", { epssScore: 0.5 }, { fingerprint: "b" }),
      scored("critical", { kevListed: true }, { fingerprint: "c" }),
      scored("low", undefined, { fingerprint: "d" }),
    ];
    const forward = prioritizeFindings(items).map((f) => f.fingerprint);
    const backward = prioritizeFindings([...items].reverse()).map((f) => f.fingerprint);
    expect(forward).toEqual(backward);
  });

  it("does not mutate the input array", () => {
    const items = [scored("low", undefined, { fingerprint: "a" }), scored("critical")];
    const before = [...items];
    prioritizeFindings(items);
    expect(items).toEqual(before);
  });
});

describe("exploitability summary", () => {
  it("turns a pile of findings into the headline counts", () => {
    const enriched = enrichWithVulnFeeds(
      [
        finding({ vulnIds: ["CVE-2021-44228"], fingerprint: "a" }), // KEV + ransomware
        finding({ vulnIds: ["CVE-2024-3400"], fingerprint: "b" }), // KEV
        finding({ vulnIds: ["CVE-2020-11111"], fingerprint: "c" }), // EPSS 0.35
        finding({ vulnIds: ["CVE-2023-00001"], fingerprint: "d" }), // negligible
        finding({ vulnIds: [], fingerprint: "e" }),
      ],
      buildIndex(),
    );
    const s = summarizeExploitability(enriched.findings, enriched.snapshotDate);
    expect(s.total).toBe(5);
    expect(s.kevListed).toBe(2);
    expect(s.kevRansomware).toBe(1);
    expect(s.epssHigh).toBe(1);
    expect(s.snapshotDate).toBe("2026-08-23");
  });
});
