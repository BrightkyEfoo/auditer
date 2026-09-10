import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
} from "node:crypto";

/**
 * Envelope encryption for at-rest secrets (VCS refresh tokens, PATs, DAST
 * auth configs).
 *
 * Design: a per-secret 256-bit DEK encrypts the plaintext with AES-256-GCM.
 * The DEK itself is wrapped by a KEK held in OpenBao's Transit engine — the
 * KEK never leaves the vault, and rotating it re-wraps DEKs without touching
 * ciphertext. This module speaks Transit over HTTP; a `LocalKek` fallback
 * (dev only) wraps DEKs with a local key so the stack runs without OpenBao.
 *
 * Wire format of a sealed secret (stored as a single string):
 *   v1:<wrappedDek base64>:<iv base64>:<authTag base64>:<ciphertext base64>
 */

const VERSION = "v1";

/**
 * The secret cannot be decrypted, and no retry will change that.
 *
 * Kept apart from a transient vault failure ON PURPOSE, because the two demand
 * opposite reactions: an unreachable vault must be retried and must NOT touch
 * stored data, while a ciphertext the key can no longer open is dead and the
 * connection holding it has to be marked for re-authentication. Conflating them
 * either deletes a working secret during an outage, or retries a dead one every
 * twenty seconds forever — which is what the api did, one stack trace per call.
 *
 * Cause seen in production: OpenBao ran with `server -dev`, whose storage is in
 * MEMORY. The container was recreated on 2026-09-02 and every KEK died with it,
 * so a GitLab refresh token sealed on 2026-08-25 became permanently unreadable.
 */
export class SecretUnrecoverableError extends Error {
  readonly unrecoverable = true as const;
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "SecretUnrecoverableError";
  }
}

export interface Kek {
  /** Wrap (encrypt) a raw DEK. Returns an opaque token. */
  wrap(dek: Buffer): Promise<string>;
  /** Unwrap (decrypt) a previously wrapped DEK. */
  unwrap(wrapped: string): Promise<Buffer>;
}

/** OpenBao/Vault Transit KEK. The KEK stays inside the vault. */
export class TransitKek implements Kek {
  constructor(
    private readonly addr: string,
    private readonly token: string,
    private readonly keyName: string,
  ) {}

  private async call(path: string, body: unknown): Promise<any> {
    const res = await fetch(`${this.addr}/v1/transit/${path}`, {
      method: "POST",
      headers: {
        "X-Vault-Token": this.token,
        "content-type": "application/json",
      },
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      throw new Error(`transit ${path} failed: ${res.status} ${await res.text()}`);
    }
    return res.json();
  }

  async wrap(dek: Buffer): Promise<string> {
    const out = await this.call(`encrypt/${this.keyName}`, {
      plaintext: dek.toString("base64"),
    });
    return out.data.ciphertext as string; // "vault:v1:...."
  }

  async unwrap(wrapped: string): Promise<Buffer> {
    const res = await fetch(`${this.addr}/v1/transit/decrypt/${this.keyName}`, {
      method: "POST",
      headers: { "X-Vault-Token": this.token, "content-type": "application/json" },
      body: JSON.stringify({ ciphertext: wrapped }),
    });
    if (res.status === 400) {
      // Transit answers 400 only when the ciphertext does not verify against the
      // key — a different key, a rotated-and-destroyed version, or a corrupt
      // value. `cipher: message authentication failed`. None of those improve
      // with time, so this is reported as final rather than retried.
      throw new SecretUnrecoverableError(
        `transit decrypt/${this.keyName}: le chiffré ne correspond pas à la clé (${(await res.text()).slice(0, 200)})`,
      );
    }
    if (!res.ok) {
      // 403 sealed, 404 key absent, 5xx, connection refused: the vault is
      // unavailable or misconfigured. The secret may be perfectly fine.
      throw new Error(
        `transit decrypt/${this.keyName} failed: ${res.status} ${await res.text()}`,
      );
    }
    const out = (await res.json()) as { data: { plaintext: string } };
    return Buffer.from(out.data.plaintext, "base64");
  }
}

/**
 * Dev-only KEK: wraps the DEK with a local 32-byte key from OPENBAO fallback
 * env. NOT for production — there is no HSM/vault boundary. Emits a warning.
 */
export class LocalKek implements Kek {
  private readonly key: Buffer;
  constructor(keyMaterial?: string) {
    const raw = keyMaterial ?? process.env.LOCAL_KEK ?? "";
    if (raw.length < 32) {
      // The fallback key is a CONSTANT compiled into this file, so anyone
      // holding a database copy can decrypt every token in it. Harmless in
      // development, and a breach in production — where the published privacy
      // policy states that a copy of the database is not enough to read the
      // tokens. Refusing here is what keeps that sentence true.
      if (process.env.NODE_ENV === "production") {
        throw new Error(
          "crypto: aucune clé de chiffrement configurée en production — " +
            "renseigner OPENBAO_ADDR/OPENBAO_TOKEN, ou LOCAL_KEK (32 octets minimum). " +
            "Le repli de développement utilise une clé publique et n'est pas utilisable ici.",
        );
      }
      // eslint-disable-next-line no-console
      console.warn("[crypto] LocalKek in use — DEV ONLY, no vault boundary.");
      this.key = Buffer.alloc(32, "auditer-dev-kek-not-for-production!!");
    } else {
      this.key = Buffer.from(raw.slice(0, 32));
    }
  }
  async wrap(dek: Buffer): Promise<string> {
    const iv = randomBytes(12);
    const c = createCipheriv("aes-256-gcm", this.key, iv);
    const ct = Buffer.concat([c.update(dek), c.final()]);
    const tag = c.getAuthTag();
    return `local:${iv.toString("base64")}:${tag.toString("base64")}:${ct.toString("base64")}`;
  }
  async unwrap(wrapped: string): Promise<Buffer> {
    const [, ivB, tagB, ctB] = wrapped.split(":");
    if (!ivB || !tagB || !ctB) {
      throw new SecretUnrecoverableError("crypto: enveloppe locale malformée");
    }
    const d = createDecipheriv(
      "aes-256-gcm",
      this.key,
      Buffer.from(ivB, "base64"),
    );
    d.setAuthTag(Buffer.from(tagB, "base64"));
    try {
      return Buffer.concat([d.update(Buffer.from(ctB, "base64")), d.final()]);
    } catch (err) {
      // GCM authentication failure — the key changed. Final, like Transit's 400.
      throw new SecretUnrecoverableError(
        "crypto: le chiffré ne correspond pas à la clé locale",
        { cause: err },
      );
    }
  }
}

export function kekFromEnv(): Kek {
  const addr = process.env.OPENBAO_ADDR;
  const token = process.env.OPENBAO_TOKEN;
  const keyName = process.env.OPENBAO_TRANSIT_KEY ?? "auditer-kek";
  if (addr && token) return new TransitKek(addr, token, keyName);
  // A vault ADDRESS without a token is a misconfiguration, not a request for
  // the local fallback: silently downgrading would seal production tokens with
  // a key that ships in this repository, and nothing would say so until someone
  // read the ciphertexts. Fail where the mistake is, at startup.
  if (addr && !token) {
    throw new Error(
      "crypto: OPENBAO_ADDR est défini mais OPENBAO_TOKEN est vide — " +
        "le coffre est inutilisable et le repli local est refusé.",
    );
  }
  return new LocalKek();
}

/** Seal a plaintext secret into the storable envelope string. */
export async function seal(kek: Kek, plaintext: string): Promise<string> {
  const dek = randomBytes(32);
  const iv = randomBytes(12);
  const c = createCipheriv("aes-256-gcm", dek, iv);
  const ct = Buffer.concat([c.update(plaintext, "utf8"), c.final()]);
  const tag = c.getAuthTag();
  const wrappedDek = await kek.wrap(dek);
  return [
    VERSION,
    Buffer.from(wrappedDek).toString("base64"),
    iv.toString("base64"),
    tag.toString("base64"),
    ct.toString("base64"),
  ].join(":");
}

/** Open a sealed secret back to plaintext. */
export async function open(kek: Kek, sealed: string): Promise<string> {
  const [v, wrappedB, ivB, tagB, ctB] = sealed.split(":");
  if (v !== VERSION || !wrappedB || !ivB || !tagB || !ctB) {
    throw new SecretUnrecoverableError("crypto: enveloppe scellée malformée");
  }
  const dek = await kek.unwrap(Buffer.from(wrappedB, "base64").toString("utf8"));
  const d = createDecipheriv("aes-256-gcm", dek, Buffer.from(ivB, "base64"));
  d.setAuthTag(Buffer.from(tagB, "base64"));
  try {
    return Buffer.concat([
      d.update(Buffer.from(ctB, "base64")),
      d.final(),
    ]).toString("utf8");
  } catch (err) {
    // The KEK opened the DEK but the payload does not authenticate: the stored
    // string was truncated or altered. Nothing to retry.
    throw new SecretUnrecoverableError(
      "crypto: le contenu scellé n'authentifie pas",
      { cause: err },
    );
  }
}

/** True for a failure that no retry and no restart will fix. */
export function isUnrecoverable(err: unknown): err is SecretUnrecoverableError {
  return err instanceof SecretUnrecoverableError;
}
