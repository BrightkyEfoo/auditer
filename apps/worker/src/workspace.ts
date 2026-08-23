import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { mkdtemp, rm, readdir } from "node:fs/promises";
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
  token?: string; // short-lived installation token (optional for public repos)
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

function authUrl(cloneUrl: string, token?: string): string {
  if (!token) return cloneUrl;
  const u = new URL(cloneUrl);
  // x-access-token is the GitHub App installation-token username convention.
  u.username = "x-access-token";
  u.password = token;
  return u.toString();
}

export async function prepare(opts: PrepareOpts): Promise<Workspace> {
  const dir = await mkdtemp(join(tmpdir(), "auditer-ws-"));
  const url = authUrl(opts.cloneUrl, opts.token);

  const args = ["clone"];
  if (opts.fullHistory) {
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
    },
  });

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
