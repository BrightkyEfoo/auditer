import Docker from "dockerode";
import { PassThrough } from "node:stream";
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

    const stdout = new CappedBuffer(STDOUT_CAP);
    const stderr = new CappedBuffer(STDOUT_CAP);
    let timedOut = false;

    try {
      const stream = await container.attach({
        stream: true,
        stdout: true,
        stderr: true,
      });
      const outPt = new PassThrough();
      const errPt = new PassThrough();
      this.docker.modem.demuxStream(stream, outPt, errPt);
      outPt.on("data", (c: Buffer) => stdout.push(c));
      errPt.on("data", (c: Buffer) => stderr.push(c));

      await container.start();

      const timer = setTimeout(() => {
        timedOut = true;
        container.kill({ signal: "SIGKILL" }).catch(() => {});
      }, spec.timeoutMs);

      const waitRes = await container.wait();
      clearTimeout(timer);

      return {
        exitCode: waitRes.StatusCode ?? -1,
        stdout: stdout.toString(),
        stderr: stderr.toString(),
        timedOut,
        durationMs: Date.now() - started,
      };
    } finally {
      // One-shot: always destroy the container.
      await container.remove({ force: true }).catch(() => {});
    }
  }
}

/** Ring-capped buffer so a fork/log bomb can't OOM the worker. */
class CappedBuffer {
  private chunks: Buffer[] = [];
  private size = 0;
  constructor(private readonly cap: number) {}
  push(c: Buffer): void {
    if (this.size >= this.cap) return;
    const room = this.cap - this.size;
    const slice = c.length > room ? c.subarray(0, room) : c;
    this.chunks.push(slice);
    this.size += slice.length;
  }
  toString(): string {
    return Buffer.concat(this.chunks).toString("utf8");
  }
}
