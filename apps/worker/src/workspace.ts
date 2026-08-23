import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { mkdtemp, rm, readdir, mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

const exec = promisify(execFile);

/**
 * Prepares a read-only repo workspace for scanning, then shreds it.
 *
 * - Source code is NEVER persisted to object storage; it lives only in this
 *   ephemeral per-job directory and is removed in `cleanup`.
 * - `fullHistory` (secrets pillar) clones all refs; otherwise a shallow,
 *   blobless, single-branch clone bounded by a size cap.
 * - The clone token is injected into the URL only for the git process; it is
 *   never logged. (TODO: route through an Anthropic-style git proxy so the
 *   token never enters the worker at all.)
 */
export interface PrepareOpts {
  cloneUrl: string; // https URL, no credentials
  ref?: string;
  token?: string; // short-lived token (optional for public repos)
  tokenUser?: string; // basic-auth username for the token (github: x-access-token, gitlab: oauth2)
  fullHistory: boolean;
}

export interface Workspace {
  path: string;
  manifests: string[];
  cleanup: () => Promise<void>;
}

const MANIFEST_BASENAMES = new Set([
  "package.json",
  "package-lock.json",
  "pnpm-lock.yaml",
  "yarn.lock",
  "requirements.txt",
  "poetry.lock",
  "Pipfile.lock",
  "go.mod",
  "go.sum",
  "pom.xml",
  "build.gradle",
  "composer.lock",
  "Cargo.lock",
  "Gemfile.lock",
  "packages.lock.json",
  "Dockerfile",
]);

function authUrl(cloneUrl: string, token?: string, tokenUser?: string): string {
  if (!token) return cloneUrl;
  const u = new URL(cloneUrl);
  // Username depends on the provider: GitHub App → "x-access-token", GitLab
  // OAuth → "oauth2".
  u.username = tokenUser ?? "x-access-token";
  u.password = token;
  return u.toString();
}

export async function prepare(opts: PrepareOpts): Promise<Workspace> {
  // WORKSPACE_ROOT is the "same path in and out" dir for the DinD-sibling
  // pattern: bind-mounted at the identical host path into the worker, so the
  // absolute workspace path is valid both here and for scanner containers the
  // host Docker spawns. Defaults to the OS tmp dir (single-host dev).
  const root = process.env.WORKSPACE_ROOT ?? tmpdir();
  await mkdir(root, { recursive: true });
  const dir = await mkdtemp(join(root, "auditer-ws-"));
  const url = authUrl(opts.cloneUrl, opts.token, opts.tokenUser);
  const isLocal = opts.cloneUrl.startsWith("/") || opts.cloneUrl.startsWith("file://");

  // git refuses to operate on a repo owned by another uid ("dubious ownership")
  // and IGNORES safe.directory from -c/env for security — it must come from a
  // config FILE. Write a throwaway global config and point git at it.
  const gitconfig = join(dir, "..", `.gitconfig-${Date.now()}`);
  await writeFile(gitconfig, "[safe]\n\tdirectory = *\n");

  const args = ["clone"];
  if (isLocal) {
    // Local mirror/demo: plain clone (cheap, all refs). --filter/--depth need
    // file:// + server-side config, so we skip them for local sources.
  } else if (opts.fullHistory) {
    // secrets need history + all refs, but no blobs we don't touch.
    args.push("--filter=blob:none", "--no-single-branch");
  } else {
    args.push("--depth=1", "--single-branch", "--filter=blob:none");
  }
  if (opts.ref) args.push("--branch", opts.ref);
  args.push(url, dir);

  await exec("git", args, {
    timeout: 10 * 60_000,
    maxBuffer: 16 * 1024 * 1024,
    env: {
      ...process.env,
      GIT_TERMINAL_PROMPT: "0", // never hang on an auth prompt
      GIT_CONFIG_NOSYSTEM: "1",
      GIT_CONFIG_GLOBAL: gitconfig, // honors safe.directory=* from this file
    },
  });
  await rm(gitconfig, { force: true }).catch(() => {});

  // Match the sandbox uid so non-root scanner containers see matching ownership
  // on the cloned repo (avoids git's dubious-ownership guard). Worker is root,
  // so this succeeds; root can still clean it up afterwards.
  const uid = process.env.SANDBOX_UID ?? "65534:65534";
  await exec("chown", ["-R", uid, dir]).catch(() => {});

  const manifests = await detectManifests(dir);

  return {
    path: dir,
    manifests,
    cleanup: () => rm(dir, { recursive: true, force: true }),
  };
}

/** Shallow scan of the repo root for known manifest basenames (relevance gate). */
async function detectManifests(dir: string): Promise<string[]> {
  const found = new Set<string>();
  try {
    const entries = await readdir(dir, { withFileTypes: true });
    for (const e of entries) {
      if (e.isFile() && MANIFEST_BASENAMES.has(e.name)) found.add(e.name);
    }
  } catch {
    /* ignore */
  }
  return [...found];
}
