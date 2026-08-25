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

/**
 * How long to keep reading after the container has exited.
 *
 * Generous on purpose: this only ever waits for bytes already produced, so it
 * costs nothing on a normal run and only bites when the socket is genuinely
 * stuck — a case that must fail loudly rather than return a truncated report.
 */
const DRAIN_TIMEOUT_MS = 30_000;

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

      // The attached stream outlives the container's exit: `container.wait()`
      // resolves when the process is gone, while whatever the kernel had not yet
      // handed us is still in the socket. Reading the buffer at that moment
      // returns the FIRST ~64 KiB and drops the rest — silently, and in
      // proportion to how much the scanner had to say.
      //
      // Measured: semgrep emitted 1 086 300 bytes of SARIF and the worker read
      // 65 476. The JSON was cut mid-document, `JSON.parse` threw, `parse()`
      // returned an empty array, and the scan was recorded SUCCESSFUL with zero
      // findings. Every scanner under 64 KiB — gitleaks, trivy, zizmor, hadolint
      // — was unaffected, which is why this survived: it works on a toy
      // repository and fails on exactly the repositories customers bring.
      // Wait on the SOURCE stream, not on the demuxed PassThroughs:
      // `modem.demuxStream` writes into them but never ends them, so an `end`
      // listener there fires never — the first version of this fix waited 30
      // seconds per engine and refused every scan. The PassThroughs are in
      // flowing mode (a `data` listener is attached above), so every byte the
      // demuxer writes is delivered synchronously; once the source is done,
      // everything it carried is already in the buffers.
      const drained = new Promise<void>((resolve) => {
        stream.once("end", () => resolve());
        stream.once("close", () => resolve());
        stream.once("error", () => resolve());
      });

      await container.start();

      const timer = setTimeout(() => {
        timedOut = true;
        container.kill({ signal: "SIGKILL" }).catch(() => {});
      }, spec.timeoutMs);

      const waitRes = await container.wait();
      clearTimeout(timer);

      // Bounded: a half-open socket must not hang a worker forever. If the
      // stream does not end in time we have a truncated report and no way to
      // know where it was cut, so this THROWS rather than returning a document
      // that would parse to fewer findings than the scanner found. A partial
      // report that looks whole is the failure this whole file is guarding.
      let drainTimer: NodeJS.Timeout | undefined;
      const drainedOrTimeout = await Promise.race([
        drained.then(() => "drained" as const),
        new Promise<"timeout">((resolve) => {
          drainTimer = setTimeout(() => resolve("timeout"), DRAIN_TIMEOUT_MS);
        }),
      ]);
      if (drainTimer) clearTimeout(drainTimer);
      if (drainedOrTimeout === "timeout" && !timedOut) {
        throw new Error(
          `sandbox: flux de sortie non terminé après ${DRAIN_TIMEOUT_MS} ms — rapport potentiellement tronqué, scan refusé`,
        );
      }

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
