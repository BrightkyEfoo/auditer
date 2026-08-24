import { describe, it, expect } from "vitest";
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { countZipEntries, OSV_ECOSYSTEMS } from "../enrich/refresh-osv-db.js";

/**
 * The guard these tests protect is narrow and load-bearing: an OSV archive that
 * downloaded badly must be REJECTED rather than swapped in. A truncated zip or
 * an HTML error page served with HTTP 200 would otherwise become the offline
 * database, and osv-scanner would then report zero vulnerabilities for a whole
 * ecosystem without failing.
 */

function makeZip(fileCount: number): Buffer {
  const dir = mkdtempSync(join(tmpdir(), "osvzip-"));
  try {
    const names: string[] = [];
    for (let i = 0; i < fileCount; i++) {
      const name = `advisory-${i}.json`;
      writeFileSync(join(dir, name), `{"id":"GHSA-${i}"}`);
      names.push(name);
    }
    // `zip` is present on macOS and on the CI image; building the archive with
    // the real tool is the point — a hand-rolled buffer would only prove the
    // parser agrees with itself.
    execFileSync("zip", ["-q", "out.zip", ...names], { cwd: dir });
    return readFileSync(join(dir, "out.zip"));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

describe("countZipEntries", () => {
  it("compte les entrées d'une archive réelle", () => {
    expect(countZipEntries(makeZip(1))).toBe(1);
    expect(countZipEntries(makeZip(37))).toBe(37);
  });

  it("rejette une archive tronquée", () => {
    const zip = makeZip(12);
    // Half a transfer: the central directory never arrived.
    expect(() => countZipEntries(zip.subarray(0, Math.floor(zip.length / 2)))).toThrow(
      /fin d'archive/,
    );
  });

  it("rejette une page d'erreur servie en 200", () => {
    const html = Buffer.from("<!doctype html><title>404</title>no such object");
    expect(() => countZipEntries(html)).toThrow(/fin d'archive/);
  });

  it("rejette une réponse vide", () => {
    expect(() => countZipEntries(Buffer.alloc(0))).toThrow(/fin d'archive/);
  });
});

describe("OSV_ECOSYSTEMS", () => {
  it("couvre les écosystèmes que les piliers annoncent", () => {
    // Removing one of these silently deletes dependency coverage for an entire
    // language — the exact failure that left the server with npm alone.
    for (const required of ["npm", "PyPI", "Go", "Maven", "Packagist", "RubyGems", "NuGet"]) {
      expect(OSV_ECOSYSTEMS).toContain(required);
    }
  });

  it("n'embarque aucun écosystème de distribution", () => {
    // Alpine/Debian/Ubuntu answer questions about a built image, not about a
    // repository, and each is a large archive downloaded to match nothing.
    for (const e of OSV_ECOSYSTEMS) {
      expect(e).not.toMatch(/^(Alpine|Debian|Ubuntu|Rocky|AlmaLinux)/);
    }
  });
});
