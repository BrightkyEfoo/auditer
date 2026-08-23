import type { IsolationTier } from "@auditer/types";

/**
 * Sandbox execution port. Every scanner runs inside one of these — we assume
 * RCE inside every sandbox, so the SPEC below is the security boundary, not an
 * afterthought. Implementations MUST honor every hardening field or refuse to
 * run.
 *
 * The default implementation (DockerGvisorRunner) talks to a docker-socket-proxy,
 * NEVER the raw host Docker socket, and runs containers under gVisor (runsc).
 */

export interface Mount {
  /** Host path (a per-job workspace prepared by the worker). */
  source: string;
  /** Path inside the container. */
  target: string;
  /** Repo is mounted read-only; scratch is writable tmpfs (see spec). */
  readOnly: boolean;
}

/** Network policy. Default is `none`; egress is granted only via the proxy. */
export type NetworkPolicy =
  | { mode: "none" }
  | { mode: "egress-proxy"; proxyUrl: string; allowHosts: string[] };

export interface SandboxSpec {
  /** Digest-pinned, cosign-verified image, e.g. "ghcr.io/gitleaks/gitleaks@sha256:...". */
  image: string;
  /** Command + args to run. */
  cmd: string[];
  /** Working directory inside the container. */
  workdir?: string;
  env?: Record<string, string>;
  mounts: Mount[];
  network: NetworkPolicy;
  isolationTier: IsolationTier;

  // ── Hardening (all enforced by the runner) ──────────────────────────────
  /** Wall-clock timeout; container is killed + removed on expiry. */
  timeoutMs: number;
  memoryBytes: number;
  cpus: number;
  pidsLimit: number;
  /** Size of the writable tmpfs scratch at /scratch. */
  tmpfsBytes: number;
  /** Run as this uid:gid, never root. */
  user: string; // e.g. "65534:65534"
}

export interface SandboxResult {
  exitCode: number;
  /** Combined or separated stdout/stderr, size-capped. */
  stdout: string;
  stderr: string;
  timedOut: boolean;
  durationMs: number;
}

export interface SandboxRunner {
  readonly tier: IsolationTier;
  /** Run one ephemeral, hardened, one-shot container; destroy it after. */
  run(spec: SandboxSpec): Promise<SandboxResult>;
}

/**
 * Canonical hardening defaults. An adapter overrides only what it must
 * (e.g. a network-enabled step). Anything an adapter forgets falls back to
 * these deny-by-default values.
 */
export const DEFAULT_HARDENING = {
  timeoutMs: 5 * 60_000,
  memoryBytes: 2 * 1024 * 1024 * 1024, // 2 GiB
  cpus: 1,
  pidsLimit: 512,
  tmpfsBytes: 1 * 1024 * 1024 * 1024, // 1 GiB scratch
  user: "65534:65534", // nobody:nogroup
} as const;

export const CONTAINER_REPO_PATH = "/repo";
export const CONTAINER_SCRATCH_PATH = "/scratch";
