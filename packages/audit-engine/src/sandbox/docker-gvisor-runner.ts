import Docker from "dockerode";
import type {
  SandboxRunner,
  SandboxSpec,
  SandboxResult,
} from "../ports/sandbox.js";
import { CONTAINER_SCRATCH_PATH } from "../ports/sandbox.js";

/**
 * The default sandbox runner: ephemeral, one-shot, hardened containers under
 * gVisor (runsc), created through a docker-socket-proxy — NEVER the raw host
 * Docker socket. Every scan gets a fresh container that is force-removed after.
 *
 * We assume RCE inside every container. The hardening below is the security
 * boundary; if the proxy or runtime can't honor it, `run` throws rather than
 * degrade silently.
 */

const STDOUT_CAP = 8 * 1024 * 1024; // 8 MiB — enough for large SARIF, bounded


export interface DockerRunnerOpts {
  /** Points at the socket-proxy, e.g. "tcp://socket-proxy:2375". */
  dockerHost?: string;
  /** Container runtime; "runsc" = gVisor. Falls back to "runc" only in dev. */
  runtime?: string;
}

export class DockerGvisorRunner implements SandboxRunner {
  readonly tier = "gvisor" as const;
  private readonly docker: Docker;
  private readonly runtime: string;

  constructor(opts: DockerRunnerOpts = {}) {
    const host = opts.dockerHost ?? process.env.DOCKER_HOST ?? "tcp://localhost:2375";
    const url = new URL(host.replace(/^tcp:/, "http:"));
    this.docker = new Docker({ host: url.hostname, port: Number(url.port) || 2375 });
    this.runtime = opts.runtime ?? process.env.SANDBOX_RUNTIME ?? "runsc";
  }

  async run(spec: SandboxSpec): Promise<SandboxResult> {
    const started = Date.now();
    const binds = spec.mounts.map(
      (m) => `${m.source}:${m.target}:${m.readOnly ? "ro" : "rw"}`,
    );

    const network =
      spec.network.mode === "none" ? "none" : "bridge"; // egress-proxy uses bridge + proxy env

    const env = Object.entries(spec.env ?? {}).map(([k, v]) => `${k}=${v}`);
    if (spec.network.mode === "egress-proxy") {
      env.push(`HTTP_PROXY=${spec.network.proxyUrl}`);
      env.push(`HTTPS_PROXY=${spec.network.proxyUrl}`);
      env.push(`http_proxy=${spec.network.proxyUrl}`);
      env.push(`https_proxy=${spec.network.proxyUrl}`);
    }

    const container = await this.docker.createContainer({
      Image: spec.image,
      Cmd: spec.cmd,
      Env: env,
      WorkingDir: spec.workdir,
      User: spec.user,
      NetworkDisabled: spec.network.mode === "none",
      HostConfig: {
        Runtime: this.runtime,
        AutoRemove: false, // we remove explicitly after reading logs
        NetworkMode: network,
        Binds: binds,
        ReadonlyRootfs: true,
        CapDrop: ["ALL"],
        SecurityOpt: ["no-new-privileges"],
        Memory: spec.memoryBytes,
        MemorySwap: spec.memoryBytes, // swap off: swap == memory
        NanoCpus: Math.round(spec.cpus * 1e9),
        PidsLimit: spec.pidsLimit,
        Tmpfs: {
          [CONTAINER_SCRATCH_PATH]: `rw,noexec,nosuid,size=${spec.tmpfsBytes}`,
        },
        Ulimits: [
          { Name: "nofile", Soft: 4096, Hard: 4096 },
          { Name: "nproc", Soft: spec.pidsLimit, Hard: spec.pidsLimit },
        ],
      },
    });

    let timedOut = false;

    try {
      await container.start();

      const timer = setTimeout(() => {
        timedOut = true;
        container.kill({ signal: "SIGKILL" }).catch(() => {});
      }, spec.timeoutMs);

      const waitRes = await container.wait();
      clearTimeout(timer);

      // Read the output from the container LOG, not from an attached stream.
      //
      // `container.attach` opens a hijacked connection (HTTP 101), and the
      // worker never talks to the daemon directly — it goes through
      // docker-socket-proxy. That proxy terminates the hijacked stream at
      // 65 476 bytes, exactly and reproducibly. semgrep emitted 1 086 300 bytes
      // of SARIF and the worker read the first 64 KiB of it: `JSON.parse` threw,
      // `parse()` returned an empty array, and the scan was recorded SUCCESSFUL
      // with zero findings. Every scanner whose report fits under 64 KiB —
      // gitleaks, trivy, zizmor, hadolint — was unaffected, which is why this
      // survived every earlier check: it works on a toy repository and fails on
      // exactly the repositories customers bring.
      //
      // `logs` is an ordinary buffered response, so the proxy has nothing to cut
      // short, and reading AFTER the wait means there is no race with the
      // container's exit either.
      const raw = (await container.logs({
        stdout: true,
        stderr: true,
        follow: false,
      })) as unknown as Buffer;
      const { stdout, stderr } = demux(Buffer.from(raw));

      return {
        exitCode: waitRes.StatusCode ?? -1,
        stdout,
        stderr,
        timedOut,
        durationMs: Date.now() - started,
      };
    } finally {
      // One-shot: always destroy the container.
      await container.remove({ force: true }).catch(() => {});
    }
  }
}

/**
 * Split a Docker log stream into stdout and stderr.
 *
 * The log stream is framed: an 8-byte header per chunk, byte 0 the stream id
 * (1 = stdout, 2 = stderr) and bytes 4..8 a big-endian payload length. A
 * container created without a TTY — every scanner here — always produces this
 * framing, so a buffer that does not parse as frames is a bug worth surfacing
 * rather than guessing around.
 *
 * Both sides are capped so a log bomb cannot OOM the worker. Truncation is
 * announced in the text itself: a report cut silently is the failure this
 * runner keeps being bitten by.
 */
function demux(buf: Buffer): { stdout: string; stderr: string } {
  const out: Buffer[] = [];
  const err: Buffer[] = [];
  let outSize = 0;
  let errSize = 0;
  let offset = 0;

  while (offset + 8 <= buf.length) {
    const type = buf[offset];
    const len = buf.readUInt32BE(offset + 4);
    const start = offset + 8;
    const endAt = Math.min(start + len, buf.length);
    const payload = buf.subarray(start, endAt);
    if (type === 2) {
      if (errSize < STDOUT_CAP) {
        const slice = payload.subarray(0, STDOUT_CAP - errSize);
        err.push(slice);
        errSize += slice.length;
      }
    } else {
      if (outSize < STDOUT_CAP) {
        const slice = payload.subarray(0, STDOUT_CAP - outSize);
        out.push(slice);
        outSize += slice.length;
      }
    }
    offset = endAt;
  }

  const suffix = (size: number): string =>
    size >= STDOUT_CAP ? `\n[bac à sable: sortie tronquée à ${STDOUT_CAP} octets]` : "";
  return {
    stdout: Buffer.concat(out).toString("utf8") + suffix(outSize),
    stderr: Buffer.concat(err).toString("utf8") + suffix(errSize),
  };
}
