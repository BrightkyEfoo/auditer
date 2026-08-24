import type { ExitClass, RawFinding } from "@auditer/types";
import type { ScannerAdapter, ScanContext, ScanMetrics } from "../ports/adapter.js";
import type { SandboxSpec, SandboxResult } from "../ports/sandbox.js";
import { DEFAULT_HARDENING, CONTAINER_REPO_PATH } from "../ports/sandbox.js";

/**
 * Quality pillar — scc (Sloc, Cloc and Code) MEASURES the repo; it does not
 * judge it. This adapter exists to close a specific hole: `computeScore` has
 * always accepted a `kloc` for density normalization, but nothing ever measured
 * one, so every repo scored with the `kloc ?? 10` fallback and the advertised
 * "large repos aren't punished for absolute counts" was a no-op. scc is the
 * cheapest honest way to produce that number — a single static Go binary, MIT,
 * no runtime deps, no network, no build step, and it does not execute a line of
 * the code it counts.
 *
 * Image: `ghcr.io/boyter/scc` is the project's own GHCR publication. v3.4.0 is
 * the NEWEST immutable version tag published there — upstream has cut v3.5.0,
 * v3.6.0, v3.7.0 and v4.0.0 since, but only pushed them to the moving `master`
 * and `latest` tags. A moving tag cannot back a reproducible audit (two scans of
 * the same commit would count against different binaries), so we pin the last
 * versioned release rather than follow `master`. Nothing in the line-counting
 * path changed in those releases for the languages we score; when upstream
 * resumes version tags, bump here and re-pin the digest.
 */

const SCC_BINARY = "/bin/scc";

/**
 * Metric keys this adapter publishes. `loc.code` is the one the scoring path
 * depends on — exported so the orchestrator does not have to hardcode a string
 * that lives here.
 */
export const SCC_METRIC_KEYS = {
  /** Lines of actual code, excluding comments and blanks. Drives kLOC. */
  code: "loc.code",
  /** Physical lines, including comments and blanks. */
  total: "loc.total",
  comment: "loc.comment",
  blank: "loc.blank",
  /** Number of source files scc actually counted. */
  files: "loc.files",
  /** scc's branch/keyword complexity estimate, summed over all languages. */
  complexity: "loc.complexity",
  /** Distinct languages detected — a crude but useful heterogeneity signal. */
  languages: "loc.languages",
} as const;

/**
 * One entry per detected language in `scc --format json`. `Files` is only
 * populated under `--by-file`, which we deliberately do not pass (see buildSpec).
 */
interface SccLanguageSummary {
  Name?: string;
  Lines?: number;
  Code?: number;
  Comment?: number;
  Blank?: number;
  Complexity?: number;
  Count?: number;
  Bytes?: number;
}

export class SccAdapter implements ScannerAdapter {
  readonly id = "scc";
  readonly pillar = "quality" as const;
  readonly tool = "scc";
  readonly isolationTier = "gvisor" as const;
  readonly needsNetwork = false;
  // scc v3.4.0 — pinned by digest: the kLOC this produces is a scoring
  // denominator, so a changed counter silently rescales every density-normalized
  // score. Cosign-signed (keyless, GitHub Actions OIDC, subject
  // github.com/boyter/scc/.github/workflows/docker-publish.yml@refs/tags/v3.4.0)
  // and verified at pin time — see infra/docker/scanners/README.md.
  readonly image =
    "ghcr.io/boyter/scc@sha256:537c0a10cf21cdbefb8b1e644e3cef9a736bdc0ca11ee8deee2dc31e5b8ed7a3";

  appliesTo(ctx: ScanContext): boolean {
    // Counting needs a checkout. DAST/UX runs carry a verified URL and no
    // workspace; scanning "" would bind-mount an empty host path.
    return ctx.workspacePath !== "";
  }

  buildSpec(_ctx: ScanContext): SandboxSpec {
    return {
      image: this.image,
      // The scc image declares no ENTRYPOINT (its Cmd is plain `/bin/scc`), and
      // the runner passes `cmd` as Cmd — so unlike the jscpd adapter we must
      // name the binary ourselves or the container would run with no argv.
      //
      // No `--by-file`: per-file output is ~370 bytes per file, and the runner
      // caps captured stdout at 8 MiB. A 25k-file monorepo would be truncated
      // mid-array, JSON.parse would throw, and we would lose the kLOC — the one
      // number this scanner exists to produce — precisely on the large repos
      // where density normalization matters most. Aggregates are ~2 KiB
      // regardless of repo size.
      //
      // scc honors .gitignore/.ignore by default and its default
      // --exclude-file list already drops lockfiles (package-lock.json,
      // pnpm-lock.yaml, ...), so vendored and generated bulk does not inflate
      // the denominator.
      cmd: [SCC_BINARY, "--format", "json", CONTAINER_REPO_PATH],
      workdir: CONTAINER_REPO_PATH,
      mounts: [{ source: "", target: CONTAINER_REPO_PATH, readOnly: true }],
      network: { mode: "none" },
      isolationTier: this.isolationTier,
      ...DEFAULT_HARDENING,
      // scc is a parallel filesystem walk in a static Go binary — it counts
      // millions of lines per second. Two minutes is already pathological; the
      // long default would just delay a hung run's failure.
      timeoutMs: 2 * 60_000,
    };
  }

  classifyExit(result: SandboxResult): ExitClass {
    // scc has no "found issues" exit code: 0 is a normal successful count and
    // anything else is a real error (unreadable path, bad flag).
    if (result.timedOut) return "partial";
    if (result.exitCode === 0) return "success";
    return "fail";
  }

  /**
   * scc finds no vulnerabilities, and this adapter deliberately emits ZERO
   * findings — including the "file over 1000 lines" style info finding that
   * would be easy to fake here.
   *
   * Three reasons, in order of weight. (1) There is no defensible universal
   * threshold: 1200 lines of generated protobuf, of Terraform, or of a switch
   * table are not a defect, and scc's `Complexity` is a raw language-specific
   * keyword count with no cross-language scale to threshold against. (2) info
   * findings are not free — SEVERITY_WEIGHT.info is 0.5 and they deduct like
   * anything else, so a few hundred of them would visibly move the very score
   * this adapter was added to make honest. (3) Per-file thresholds need
   * `--by-file`, which we refuse for the stdout-cap reason above.
   *
   * The measurements go out through `measure()` instead. If a defensible
   * file-level threshold is ever agreed on, it belongs in a rule with an owner,
   * not in a line counter.
   */
  async parse(_result: SandboxResult, _ctx: ScanContext): Promise<RawFinding[]> {
    return [];
  }

  async measure(result: SandboxResult, _ctx: ScanContext): Promise<ScanMetrics | undefined> {
    const json = extractJsonArray(result.stdout);
    if (!json) return undefined;
    let languages: SccLanguageSummary[];
    try {
      languages = JSON.parse(json) as SccLanguageSummary[];
    } catch {
      // Truncated (stdout cap) or malformed output. Returning undefined rather
      // than a partial sum is the whole point: an under-count would be silently
      // treated as a measured kLOC and over-penalize the repo.
      return undefined;
    }
    if (!Array.isArray(languages) || languages.length === 0) return undefined;

    const metrics: ScanMetrics = {
      [SCC_METRIC_KEYS.code]: sum(languages, (l) => l.Code),
      [SCC_METRIC_KEYS.total]: sum(languages, (l) => l.Lines),
      [SCC_METRIC_KEYS.comment]: sum(languages, (l) => l.Comment),
      [SCC_METRIC_KEYS.blank]: sum(languages, (l) => l.Blank),
      [SCC_METRIC_KEYS.files]: sum(languages, (l) => l.Count),
      [SCC_METRIC_KEYS.complexity]: sum(languages, (l) => l.Complexity),
      [SCC_METRIC_KEYS.languages]: languages.length,
    };

    // An empty repo (or one whose every file was ignored) is not a measurement
    // of zero — it is the absence of one. Zero kLOC would divide into the
    // density factor as a floor-clamped 1, i.e. a silent fallback wearing a
    // "measured" label.
    if (metrics[SCC_METRIC_KEYS.code]! <= 0) return undefined;
    return metrics;
  }
}

function sum(
  languages: SccLanguageSummary[],
  pick: (l: SccLanguageSummary) => number | undefined,
): number {
  let total = 0;
  for (const l of languages) {
    const v = pick(l);
    if (typeof v === "number" && Number.isFinite(v)) total += v;
  }
  return total;
}

/** scc writes a bare JSON array to stdout; be lenient about surrounding noise. */
function extractJsonArray(s: string): string | null {
  const start = s.indexOf("[");
  const end = s.lastIndexOf("]");
  if (start === -1 || end === -1 || end < start) return null;
  return s.slice(start, end + 1);
}
