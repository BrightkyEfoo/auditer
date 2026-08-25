import { mkdtemp, mkdir, writeFile, rm, chmod } from "node:fs/promises";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { defaultRegistry } from "../registry.js";
import { runScan } from "../orchestrator.js";
import { DockerGvisorRunner } from "../sandbox/docker-gvisor-runner.js";
import type { ScanContext } from "../ports/adapter.js";
import type { SandboxSpec } from "../ports/sandbox.js";

const exec = promisify(execFile);

/**
 * Runs every registered scanner against a fixture repository, in the real
 * sandbox, with its real image and its real argv — and fails if one of them
 * comes back empty-handed.
 *
 * This exists because six engines were found dead in production in a single
 * afternoon, and every one of them was found by hand, by running its command
 * and reading the error:
 *
 *   gitleaks      cloned without blobs → "no leaks found in partial scan"
 *   nuclei        no template corpus   → probed nothing, exit 0
 *   osv-scanner   npm database only    → exit 127 on every other language
 *   semgrep       $HOME unwritable     → OSError, exit 1
 *   trivy config  $TMPDIR unwritable   → FATAL, exit 1
 *   hadolint      wrong path assumed   → file not found, exit 1
 *
 * `pnpm build` was green throughout. A type checker cannot know that a flag was
 * removed upstream, that an image ships without its rules, or that a container
 * cannot write where the tool expects to. Only running it knows.
 *
 * The fixture is built to make every scanner FIND something. That is the whole
 * design: an engine that runs correctly but reports nothing is indistinguishable
 * from one that crashed politely, so "exit 0" is not the assertion — "returned
 * findings" is, for every scanner where findings are the output. The two that
 * measure rather than detect (scc, jscpd) are asserted on their metrics instead.
 *
 * Run on the deploy host, where the images and the socket-proxy live:
 *   docker compose --profile ops run --rm engines-verify
 */

interface EngineExpectation {
  /** Findings are the output; zero means it did not really run. */
  expectsFindings: boolean;
  /** Why this fixture should trip it — printed on failure, so a red run explains itself. */
  because: string;
}

const EXPECTED: Record<string, EngineExpectation> = {
  gitleaks: {
    expectsFindings: true,
    because: "un jeton AWS est commité dans l'historique de la fixture",
  },
  "osv-scanner": {
    expectsFindings: true,
    because: "la fixture déclare des dépendances npm ET PyPI vulnérables connues",
  },
  semgrep: {
    expectsFindings: true,
    because: "la fixture contient un eval() sur une entrée non validée",
  },
  "trivy-config": {
    expectsFindings: true,
    because: "le Dockerfile de la fixture tourne en root sans HEALTHCHECK",
  },
  hadolint: {
    expectsFindings: true,
    because: "le Dockerfile de la fixture utilise une image en tag latest et un apt-get sans version",
  },
  zizmor: {
    expectsFindings: true,
    because: "le workflow de la fixture interpole github.event dans un run:",
  },
  // Measurement engines: their output is metrics, not findings. A repository
  // can legitimately have zero duplication, so asserting findings here would
  // produce a red run that means nothing.
  scc: { expectsFindings: false, because: "scc mesure, il ne détecte pas" },
  jscpd: { expectsFindings: false, because: "jscpd peut légitimement ne rien trouver" },
};

/** Engines needing a live target rather than a checkout — not covered here. */
const TARGET_ENGINES = new Set(["nuclei", "lighthouse"]);

export interface EngineVerdict {
  id: string;
  pillar: string;
  ok: boolean;
  exitClass: string;
  exitCode: number;
  findings: number;
  durationMs: number;
  detail: string;
}

export async function verifyEngines(): Promise<EngineVerdict[]> {
  const dir = await buildFixture();
  const runner = new DockerGvisorRunner();
  const ctx: ScanContext = {
    auditRunId: "verify",
    organizationId: "verify",
    workspacePath: dir,
    manifests: ["package-lock.json", "requirements.txt", ".github/workflows"],
    dockerfiles: ["Dockerfile"],
  };

  const verdicts: EngineVerdict[] = [];
  try {
    for (const adapter of defaultRegistry().all()) {
      if (TARGET_ENGINES.has(adapter.id)) {
        verdicts.push({
          id: adapter.id,
          pillar: adapter.pillar,
          ok: true,
          exitClass: "skipped",
          exitCode: 0,
          findings: 0,
          durationMs: 0,
          detail: "moteur de cible vivante — non couvert par cette vérification",
        });
        continue;
      }

      const expectation = EXPECTED[adapter.id];
      let verdict: EngineVerdict;
      try {
        const r = await runScan(adapter, runner, ctx);
        const wantsFindings = expectation?.expectsFindings ?? false;
        // `skipped` means appliesTo said no. On this fixture that is a defect in
        // the gate, not a legitimate outcome — the fixture carries an input for
        // every engine on purpose.
        const ok = r.skipped
          ? false
          : r.exitClass !== "fail" && (!wantsFindings || r.findings.length > 0);
        verdict = {
          id: adapter.id,
          pillar: adapter.pillar,
          ok,
          exitClass: r.skipped ? "skipped" : r.exitClass,
          exitCode: r.exitCode,
          findings: r.findings.length,
          durationMs: r.durationMs,
          detail: ok
            ? ""
            : r.skipped
              ? "appliesTo a refusé la fixture alors qu'elle porte une entrée pour ce moteur"
              : r.exitClass === "fail"
                ? `sortie ${r.exitCode}`
                : `0 finding alors que ${expectation?.because ?? "des findings étaient attendus"}`,
        };
      } catch (err) {
        verdict = {
          id: adapter.id,
          pillar: adapter.pillar,
          ok: false,
          exitClass: "error",
          exitCode: -1,
          findings: 0,
          durationMs: 0,
          detail: err instanceof Error ? err.message : String(err),
        };
      }
      verdicts.push(verdict);
      const mark = verdict.ok ? "ok  " : "ECHEC";
      process.stdout.write(
        `[moteurs] ${mark} ${verdict.id.padEnd(14)} ${String(verdict.findings).padStart(4)} finding(s)  ` +
          `${verdict.exitClass} (${verdict.exitCode})  ${Math.round(verdict.durationMs / 100) / 10}s  ${verdict.detail}\n`,
      );
      // A failing check that only says "0 findings" sends whoever reads it back
      // to reproducing the container by hand — which is the work this file was
      // written to stop. On failure, run the same spec once more and print what
      // the engine actually said.
      if (!verdict.ok) await explain(adapter, runner, ctx);
    }
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
  return verdicts;
}

/**
 * Re-runs one engine's spec and prints its raw output, so a red line explains
 * itself instead of sending a reader back to a manual `docker run`.
 */
async function explain(
  adapter: { id: string; buildSpec: (ctx: ScanContext) => SandboxSpec },
  runner: DockerGvisorRunner,
  ctx: ScanContext,
): Promise<void> {
  try {
    const spec = adapter.buildSpec(ctx);
    spec.mounts = spec.mounts.map((m) =>
      m.target === "/repo" ? { ...m, source: ctx.workspacePath } : m,
    );
    const r = await runner.run(spec);
    const out = r.stdout.trim();
    // Keep the raw output. "0 findings from a document that clearly has some"
    // cannot be diagnosed from a 300-character excerpt, and the fixture is
    // deleted when the check ends.
    const dumpRoot = process.env.WORKSPACE_ROOT ?? "/tmp";
    const dump = join(dumpRoot, `verify-${adapter.id}.stdout.json`);
    await writeFile(dump, r.stdout);
    process.stdout.write(`[moteurs]   ${adapter.id} · sortie brute conservée : ${dump}\n`);
    process.stdout.write(
      `[moteurs]   ${adapter.id} · argv: ${(spec.cmd ?? []).join(" ")}\n` +
        `[moteurs]   ${adapter.id} · sortie ${r.exitCode}, stdout ${out.length} o, stderr ${r.stderr.length} o\n` +
        `[moteurs]   ${adapter.id} · stdout: ${out.slice(0, 300).replace(/\n/g, " ")}\n` +
        `[moteurs]   ${adapter.id} · stderr: ${r.stderr.trim().slice(-400).replace(/\n/g, " ")}\n`,
    );
  } catch (err) {
    process.stdout.write(
      `[moteurs]   ${adapter.id} · diagnostic impossible : ${err instanceof Error ? err.message : String(err)}\n`,
    );
  }
}

/**
 * A repository built to trip every scanner exactly once.
 *
 * Everything in here is deliberate. The AWS key is the canonical documentation
 * example (AKIAIOSFODNN7EXAMPLE), not a real credential; the vulnerable versions
 * are old enough that no future advisory can make them clean; the Dockerfile
 * breaks several hadolint rules and one trivy check at the same time.
 */
async function buildFixture(): Promise<string> {
  const root = process.env.WORKSPACE_ROOT ?? "/tmp";
  const dir = await mkdtemp(join(root, "auditer-verify-"));

  await writeFile(
    join(dir, "config.js"),
    // Two separate baits: a hardcoded credential for the secret scanners and an
    // eval on request input for the SAST rules.
    //
    // NOT the AWS documentation key (`AKIAIOSFODNN7EXAMPLE`): gitleaks
    // allowlists it by name, precisely because it appears in every tutorial. A
    // fixture built on it produces a green "no leaks" that proves nothing, which
    // is the exact failure mode this whole file exists to catch. The value below
    // is synthetic and matches no real account — it only has to match the rule's
    // shape, `AKIA` followed by sixteen upper-case alphanumerics.
    `const AWS_ACCESS_KEY_ID = "AKIA2E0K4NPFXQ7RTJ5W";\n` +
      `const AWS_SECRET_ACCESS_KEY = "hV3kQ8pZ1mR6tY9wA2sD4fG7jL0xC5vB8nM1qE3u";\n` +
      `module.exports.run = (req) => eval(req.query.expr);\n`,
  );

  // Duplicated block, so jscpd has something to measure.
  const dup = Array.from({ length: 40 }, (_, i) => `  const v${i} = compute(${i}) + offset;`).join("\n");
  await writeFile(join(dir, "a.js"), `function a(offset) {\n${dup}\n  return 0;\n}\n`);
  await writeFile(join(dir, "b.js"), `function b(offset) {\n${dup}\n  return 0;\n}\n`);

  await writeFile(
    join(dir, "package.json"),
    JSON.stringify({ name: "fixture", version: "1.0.0", dependencies: { lodash: "4.17.15" } }, null, 2),
  );
  await writeFile(
    join(dir, "package-lock.json"),
    JSON.stringify(
      {
        name: "fixture",
        version: "1.0.0",
        lockfileVersion: 3,
        requires: true,
        packages: {
          "": { name: "fixture", version: "1.0.0", dependencies: { lodash: "4.17.15" } },
          "node_modules/lodash": {
            version: "4.17.15",
            resolved: "https://registry.npmjs.org/lodash/-/lodash-4.17.15.tgz",
          },
        },
      },
      null,
      2,
    ),
  );
  // A second ecosystem, so a database missing everything but npm fails here
  // instead of failing at a customer.
  await writeFile(join(dir, "requirements.txt"), "django==2.2.0\nflask==0.12.2\n");

  await writeFile(
    join(dir, "Dockerfile"),
    "FROM ubuntu:latest\n" + // hadolint DL3006/DL3007
      "RUN apt-get update && apt-get install -y curl\n" + // DL3008/DL3009
      "USER root\n" + // trivy misconfig
      "CMD curl http://localhost\n",
  );

  await mkdir(join(dir, ".github", "workflows"), { recursive: true });
  await writeFile(
    join(dir, ".github", "workflows", "ci.yml"),
    "name: ci\n" +
      "on: [pull_request_target]\n" + // zizmor dangerous-triggers
      "jobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n" +
      "      - run: echo \"${{ github.event.pull_request.title }}\"\n", // template-injection
  );

  // gitleaks scans git HISTORY (`gitleaks git /repo`), so the fixture has to be
  // a real repository with a real commit — a bare directory would fail for a
  // reason that says nothing about gitleaks. Identity and dates are fixed so two
  // runs of this check produce the same commit and the same fingerprints.
  const env = {
    ...process.env,
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_AUTHOR_NAME: "auditer",
    GIT_AUTHOR_EMAIL: "verify@auditer.local",
    GIT_COMMITTER_NAME: "auditer",
    GIT_COMMITTER_EMAIL: "verify@auditer.local",
    GIT_AUTHOR_DATE: "2026-01-01T00:00:00+00:00",
    GIT_COMMITTER_DATE: "2026-01-01T00:00:00+00:00",
  };
  await exec("git", ["init", "--quiet", "--initial-branch=main", dir], { env });
  await exec("git", ["-C", dir, "add", "-A"], { env });
  await exec("git", ["-C", dir, "commit", "--quiet", "-m", "fixture"], { env });

  // Hand the tree to 65534, exactly as workspace.ts does for a real clone.
  // Readable-by-all is not enough for gitleaks: git refuses a repository whose
  // owner differs from the caller ("dubious ownership"), and it refuses it in
  // the worst possible way — stderr non-empty, so gitleaks reports
  // `failed to scan Git repository` then `no leaks found in partial scan` and
  // exits 1. Same misleading sentence as the blobless-clone defect, different
  // cause. A fixture that does not reproduce the worker's own preparation would
  // fail engines for reasons that say nothing about the engines.
  await exec("chown", ["-R", "65534:65534", dir]);
  await exec("chmod", ["-R", "a+rX", dir]);
  await chmod(dir, 0o755);
  return dir;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  verifyEngines()
    .then((verdicts) => {
      const failed = verdicts.filter((v) => !v.ok);
      process.stdout.write(
        `[moteurs] ${verdicts.length - failed.length}/${verdicts.length} moteurs vérifiés\n`,
      );
      if (failed.length > 0) {
        process.stderr.write(
          `[moteurs] EN ECHEC : ${failed.map((f) => `${f.id} (${f.detail})`).join(" · ")}\n`,
        );
        process.exit(1);
      }
    })
    .catch((err: unknown) => {
      process.stderr.write(`[moteurs] ${err instanceof Error ? err.message : String(err)}\n`);
      process.exit(1);
    });
}
