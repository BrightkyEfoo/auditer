import {
  S3Client,
  PutObjectCommand,
  GetObjectCommand,
  DeleteObjectCommand,
  HeadObjectCommand,
} from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";
import { createHash, randomUUID } from "node:crypto";

/**
 * Object-storage wrapper. Depends ONLY on the S3 protocol — MinIO in dev,
 * swappable to Cloudflare R2 / AWS S3 by env with no code change. Stores raw
 * scanner output (SARIF/JSON), scanner logs, SBOMs, and generated PDFs.
 *
 * The audited source code is NEVER stored here. Repo tarballs, if ever kept,
 * carry a short retention TTL and live under the `ephemeral/` prefix.
 */

/**
 * `report` is the rendered deliverable, whatever its container (HTML today,
 * PDF once the paged renderer lands). It is deliberately distinct from `pdf`:
 * storing an HTML document under `pdf` made the row lie about its own content,
 * and a download endpoint that trusts that row then serves the wrong type.
 */
export type ArtifactType = "raw" | "sarif" | "sbom" | "report" | "pdf" | "log";

export interface StorageConfig {
  endpoint: string;
  accessKeyId: string;
  secretAccessKey: string;
  bucket: string;
  region?: string;
  forcePathStyle?: boolean;
}

export interface PutResult {
  key: string;
  checksum: string;
  sizeBytes: number;
  contentType?: string;
}

export function storageConfigFromEnv(): StorageConfig {
  return {
    endpoint: process.env.S3_ENDPOINT ?? "http://localhost:9000",
    accessKeyId: process.env.S3_ACCESS_KEY ?? "minioadmin",
    secretAccessKey: process.env.S3_SECRET_KEY ?? "minioadmin",
    bucket: process.env.S3_BUCKET ?? "auditer",
    region: process.env.S3_REGION ?? "us-east-1",
    forcePathStyle: (process.env.S3_FORCE_PATH_STYLE ?? "true") === "true",
  };
}

export class Storage {
  private readonly s3: S3Client;
  private readonly bucket: string;

  constructor(cfg: StorageConfig = storageConfigFromEnv()) {
    this.bucket = cfg.bucket;
    this.s3 = new S3Client({
      endpoint: cfg.endpoint,
      region: cfg.region ?? "us-east-1",
      forcePathStyle: cfg.forcePathStyle ?? true,
      credentials: {
        accessKeyId: cfg.accessKeyId,
        secretAccessKey: cfg.secretAccessKey,
      },
    });
  }

  /** Deterministic-ish key: <org>/<run>/<type>/<uuid>.<ext>. */
  buildKey(opts: {
    organizationId: string;
    auditRunId?: string;
    type: ArtifactType;
    ext: string;
  }): string {
    const run = opts.auditRunId ?? "misc";
    return `${opts.organizationId}/${run}/${opts.type}/${randomUUID()}.${opts.ext}`;
  }

  async put(
    key: string,
    body: Buffer | Uint8Array | string,
    contentType?: string,
  ): Promise<PutResult> {
    const buf = typeof body === "string" ? Buffer.from(body) : Buffer.from(body);
    const checksum = createHash("sha256").update(buf).digest("hex");
    await this.s3.send(
      new PutObjectCommand({
        Bucket: this.bucket,
        Key: key,
        Body: buf,
        ContentType: contentType,
        ChecksumSHA256: undefined,
      }),
    );
    return { key, checksum, sizeBytes: buf.byteLength, contentType };
  }

  async get(key: string): Promise<Buffer> {
    const res = await this.s3.send(
      new GetObjectCommand({ Bucket: this.bucket, Key: key }),
    );
    const bytes = await res.Body?.transformToByteArray();
    if (!bytes) throw new Error(`storage: empty object at ${key}`);
    return Buffer.from(bytes);
  }

  async getText(key: string): Promise<string> {
    return (await this.get(key)).toString("utf8");
  }

  async delete(key: string): Promise<void> {
    await this.s3.send(
      new DeleteObjectCommand({ Bucket: this.bucket, Key: key }),
    );
  }

  async exists(key: string): Promise<boolean> {
    try {
      await this.s3.send(
        new HeadObjectCommand({ Bucket: this.bucket, Key: key }),
      );
      return true;
    } catch {
      return false;
    }
  }

  /** Presigned GET for the browser to download a PDF/artifact directly. */
  async presignGet(key: string, expiresInSeconds = 300): Promise<string> {
    return getSignedUrl(
      this.s3,
      new GetObjectCommand({ Bucket: this.bucket, Key: key }),
      { expiresIn: expiresInSeconds },
    );
  }
}

let singleton: Storage | undefined;
export function getStorage(): Storage {
  singleton ??= new Storage();
  return singleton;
}
