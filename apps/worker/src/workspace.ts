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
  /**
   * Repo-relative paths of every Dockerfile in the checkout.
   *
   * Separate from `manifests`, which is basenames only. hadolint has no
   * recursive mode and ships distroless — no shell to expand a glob — so it
   * needs real paths or it lints nothing.
   */
  dockerfiles: string[];
  /**
   * The commit actually analysed, read back from the clone rather than taken
   * from the request. Every report asserts "the result holds for the commit
   * shown above" and prints "non déclaré" instead, because nothing ever
   * recorded it — the sentence was unbacked. Null only for a source that has
   * no git history.
   */
  commitSha: string | null;
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
    // FULL clone — deliberately NOT `--filter=blob:none`.
    //
    // A blobless clone downloads history without file CONTENT and fetches each
    // blob lazily from the remote on first access. The secrets scanner reads
    // every blob in every commit, and it runs in a sandbox with `--network=none`
    // by design. So every blob fetch failed:
    //
    //   fatal: unable to access 'https://github.com/...': Could not resolve host
    //   failed to scan Git repository
    //   WRN no leaks found in partial scan
    //
    // gitleaks then exited 1 and reported no leaks. The secrets pillar — the
    // one this product leads with — had never once worked on a real repository,
    // and it said so in the only way that matters to a customer: "nothing
    // found". It passed on local test repos purely because the branch above
    // skips the filter for those.
    //
    // The blobs ARE the thing being scanned. Downloading them is not overhead
    // here, it is the job.
    args.push("--no-single-branch");
  } else {
    // Shallow + blobless is safe ONLY because these scanners read the working
    // tree, which git materialises at checkout. Any scanner that walks history
    // must request `fullHistory` instead — a lazy blob fetch cannot succeed
    // from a sandbox with no network.
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
  // Read the commit BEFORE handing the tree to another uid: rev-parse is a git
  // operation, and after the chown git treats the tree as dubiously owned.
  let commitSha: string | null = null;
  try {
    const { stdout } = await exec("git", ["-C", dir, "rev-parse", "HEAD"], {
      timeout: 15_000,
      env: { ...process.env, GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: gitconfig },
    });
    commitSha = stdout.trim() || null;
  } catch {
    // A source with no history (a plain directory) legitimately has no commit.
  }

  await rm(gitconfig, { force: true }).catch(() => {});

  // Hand the tree to the sandbox uid so non-root scanner containers see
  // matching ownership and git's dubious-ownership guard stays quiet inside
  // them. The worker runs as root, so this succeeds — and root can still remove
  // the directory afterwards.
  //
  // NOT swallowed. A failed chown means every git-aware scanner (gitleaks reads
  // the full history) dies on "detected dubious ownership" — which is recorded
  // as a failed scan, and a failed scan reads to the customer as a clean
  // pillar. Silence here buys nothing and hides exactly the failure that is
  // hardest to diagnose after the fact.
  const uid = process.env.SANDBOX_UID ?? "65534:65534";
  try {
    await exec("chown", ["-R", uid, dir]);
  } catch (err) {
    throw new Error(
      `workspace: chown to ${uid} failed — git-aware scanners would fail on ` +
        `dubious ownership. Is the worker running as root? (${String(err)})`,
    );
  }

  const manifests = await detectManifests(dir);
  const dockerfiles = await findDockerfiles(dir);

  return {
    path: dir,
    manifests,
    dockerfiles,
    commitSha,
    cleanup: () => rm(dir, { recursive: true, force: true }),
  };
}

/**
 * Marker emitted when the repository has GitHub Actions workflows.
 *
 * Not a basename like the rest: the file that matters is `.github/workflows/*.yml`,
 * whose name is arbitrary. Adapters gate on this string, so it is exported
 * rather than spelled out at each call site.
 */
export const WORKFLOWS_MANIFEST = ".github/workflows";

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
  // CI workflows are a whole attack surface the root scan cannot see, and the
  // adapter that audits them must not run on a repository that has none —
  // zizmor exits 3 "no inputs collected", which would be recorded as a failed
  // scan for a repository that is simply not using GitHub Actions.
  try {
    const wf = await readdir(join(dir, ".github", "workflows"), { withFileTypes: true });
    if (wf.some((e) => e.isFile() && /\.ya?ml$/i.test(e.name))) found.add(WORKFLOWS_MANIFEST);
  } catch {
    /* no workflows directory */
  }
  return [...found];
}

/** Directories never worth walking: vendored code and VCS internals. */
const SKIP_DIRS = new Set([
  ".git",
  "node_modules",
  "vendor",
  "dist",
  "build",
  ".next",
  ".turbo",
  "target",
  "__pycache__",
]);

/** A repository with more Dockerfiles than this is not what the depth bound is for. */
const MAX_DOCKERFILES = 200;
const MAX_DEPTH = 6;

/**
 * Walk the checkout for Dockerfiles.
 *
 * Bounded on purpose. The workspace is attacker-supplied — a repository can
 * carry a directory tree deep and wide enough to make an unbounded walk the
 * cheapest denial of service in the product — so depth, count and the skip list
 * are limits, not optimisations. Symlinks are never followed for the same
 * reason: `withFileTypes` reports a link as a link, and a link is neither
 * recursed into nor reported as a Dockerfile.
 */
async function findDockerfiles(root: string): Promise<string[]> {
  const found: string[] = [];

  async function walk(dir: string, rel: string, depth: number): Promise<void> {
    if (depth > MAX_DEPTH || found.length >= MAX_DOCKERFILES) return;
    let entries;
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      if (found.length >= MAX_DOCKERFILES) return;
      const childRel = rel ? `${rel}/${e.name}` : e.name;
      if (e.isDirectory()) {
        if (SKIP_DIRS.has(e.name) || e.name.startsWith(".")) continue;
        await walk(join(dir, e.name), childRel, depth + 1);
      } else if (e.isFile() && isDockerfile(e.name)) {
        found.push(childRel);
      }
    }
  }

  await walk(root, "", 0);
  return found.sort();
}

/** `Dockerfile`, `Dockerfile.prod`, `api.Dockerfile` — all three conventions. */
function isDockerfile(name: string): boolean {
  return /^Dockerfile(\..+)?$/i.test(name) || /\.Dockerfile$/i.test(name);
}
