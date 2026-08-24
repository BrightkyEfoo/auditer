import { mkdtemp, rm, writeFile, chmod } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DockerGvisorRunner, DEFAULT_HARDENING } from "@auditer/audit-engine";
import type { SandboxSpec } from "@auditer/audit-engine";

/**
 * Renders the print-ready report HTML into a PDF.
 *
 * The PDF is the format the deliverable is judged on — a director opens it, an
 * auditor archives it — but it is NOT worth losing the report over. Every
 * failure path here returns `null` so the caller can still store the HTML it
 * already has; a report in the wrong container beats no report at all.
 *
 * Chromium runs in the same hardened, one-shot sandbox as every scanner
 * (DockerGvisorRunner → docker-socket-proxy → runsc), for the same reason: the
 * HTML embeds finding titles, file paths and code excerpts taken from an
 * untrusted repository, so the renderer parses attacker-influenced input.
 * Opening a second, softer path to Docker for it would undo the isolation the
 * scanners are given.
 */

/**
 * Built on the deploy host by .github/workflows/deploy.yml, exactly like the
 * semgrep image, so the worker resolves it from the local daemon. The tag
 * carries the Chromium version: a report that gets re-rendered must not
 * silently re-paginate because the renderer moved underneath it.
 */
const RENDERER_IMAGE = process.env.PDF_RENDERER_IMAGE ?? "auditer/chromium-pdf:136.0.7103.113-1";

/**
 * A report that takes longer than this is not going to finish: Chromium is
 * laying out a static, asset-free document with no network. The budget covers
 * container creation plus the renderer's own 15 s virtual-time budget with room
 * to spare, and the runner force-removes the container when it expires.
 */
const RENDER_TIMEOUT_MS = 60_000;

/**
 * Second, outer bound. `spec.timeoutMs` makes the runner SIGKILL the container,
 * which only helps while the Docker API answers — if the socket-proxy stops
 * responding, `container.wait()` never settles and the caller waits forever.
 * This race bounds the caller instead. It does not orphan a container: the
 * runner's own `finally` still force-removes it whenever its call finally
 * returns.
 */
const HARD_TIMEOUT_MS = RENDER_TIMEOUT_MS + 30_000;

/** PDF is capped well below the runner's 8 MiB stdout cap; base64 costs +33 %. */
const MAX_PDF_BYTES = 5 * 1024 * 1024;

const runner = new DockerGvisorRunner();

export async function renderPdf(html: string): Promise<Buffer | null> {
  let dir: string | undefined;
  try {
    dir = await stageHtml(html);
    const htmlPath = join(dir, "report.html");

    const spec: SandboxSpec = {
      image: RENDERER_IMAGE,
      // The image's ENTRYPOINT is the render script; this is its single
      // argument. Same absolute path inside and outside, so the string the
      // worker computed is the string Chromium opens.
      cmd: [htmlPath],
      mounts: [{ source: dir, target: dir, readOnly: true }],
      // No network, and nothing to reach: the HTML is self-contained (inline
      // CSS, no remote asset). A renderer that could fetch would turn every
      // report into an SSRF surface pointed at the deploy host's own network.
      network: { mode: "none" },
      isolationTier: "gvisor",
      ...DEFAULT_HARDENING,
      timeoutMs: RENDER_TIMEOUT_MS,
    };

    const result = await withHardTimeout(runner.run(spec), HARD_TIMEOUT_MS);
    if (!result) {
      warn("renderer did not answer before the hard timeout");
      return null;
    }
    if (result.timedOut) {
      warn(`renderer timed out after ${RENDER_TIMEOUT_MS} ms`);
      return null;
    }
    if (result.exitCode !== 0) {
      warn(`renderer exited ${result.exitCode}: ${lastLine(result.stderr)}`);
      return null;
    }

    return decodePdf(result.stdout);
  } catch (err) {
    // Includes the case that matters most in practice: the image is missing on
    // this host because the deploy step that builds it has not run yet.
    warn(`renderer unavailable: ${err instanceof Error ? err.message : String(err)}`);
    return null;
  } finally {
    // The staged HTML is a copy of the report, findings included. It must go
    // whether the render succeeded, failed or timed out.
    if (dir) await rm(dir, { recursive: true, force: true }).catch(() => {});
  }
}

/**
 * Writes the HTML where BOTH the worker and the host-spawned container can see
 * it under one path.
 *
 * Same pattern as `prepare()` in workspace.ts: WORKSPACE_ROOT is bind-mounted
 * into the worker at its own host path, so a bind source computed here resolves
 * correctly when the daemon — which lives on the host — creates the container.
 * A path under the container's private /tmp would not exist on the host, and
 * the mount would silently produce an empty directory.
 */
async function stageHtml(html: string): Promise<string> {
  const root = process.env.WORKSPACE_ROOT ?? tmpdir();
  const dir = await mkdtemp(join(root, "auditer-pdf-"));
  const file = join(dir, "report.html");
  await writeFile(file, html, "utf8");

  // mkdtemp creates the directory 0700, which the sandbox uid (65534, per
  // DEFAULT_HARDENING) cannot even traverse — Chromium would report a file it
  // can see in the mount but not open. Traverse + read for others, no write:
  // the mount is read-only anyway. The owner keeps write on the directory so
  // the cleanup below can still unlink the file.
  await chmod(dir, 0o755);
  await chmod(file, 0o444);
  return dir;
}

/**
 * The renderer emits base64 because the runner decodes stdout as UTF-8, which
 * would destroy raw PDF bytes. busybox wraps at 76 columns, hence the strip.
 */
function decodePdf(stdout: string): Buffer | null {
  const b64 = stdout.replace(/\s+/g, "");
  if (b64.length === 0) {
    warn("renderer produced no output");
    return null;
  }
  const pdf = Buffer.from(b64, "base64");

  // Buffer.from is lenient with malformed base64 — it silently drops bad
  // characters rather than throwing — so the magic number is what actually
  // proves we decoded a PDF and not a stray log line.
  if (pdf.subarray(0, 5).toString("latin1") !== "%PDF-") {
    warn("renderer output is not a PDF");
    return null;
  }
  if (pdf.byteLength > MAX_PDF_BYTES) {
    warn(`rendered PDF is ${pdf.byteLength} bytes, over the ${MAX_PDF_BYTES} cap`);
    return null;
  }
  return pdf;
}

/** Resolves to `null` instead of rejecting when the promise outlives the bound. */
function withHardTimeout<T>(p: Promise<T>, ms: number): Promise<T | null> {
  return new Promise<T | null>((resolve) => {
    const timer = setTimeout(() => resolve(null), ms);
    timer.unref?.();
    p.then(
      (v) => {
        clearTimeout(timer);
        resolve(v);
      },
      () => {
        clearTimeout(timer);
        resolve(null);
      },
    );
  });
}

/**
 * Headless Chromium always logs a full ANGLE/Vulkan initialisation failure
 * before falling back to software rendering, so the last stderr line is almost
 * never the real cause. The render script prefixes its own diagnostics with
 * "render-pdf:" precisely so this can pick them out.
 */
function lastLine(stderr: string): string {
  const lines = stderr.trim().split("\n").filter(Boolean);
  const own = lines.filter((l) => l.startsWith("render-pdf:"));
  return (own.at(-1) ?? lines.at(-1))?.slice(0, 300) ?? "no stderr";
}

function warn(message: string): void {
  // eslint-disable-next-line no-console
  console.warn(`[pdf] ${message}`);
}
