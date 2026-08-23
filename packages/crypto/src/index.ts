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
    const out = await this.call(`decrypt/${this.keyName}`, {
      ciphertext: wrapped,
    });
    return Buffer.from(out.data.plaintext as string, "base64");
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
      // Deterministic dev key so restarts can still decrypt. Loudly unsafe.
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
    if (!ivB || !tagB || !ctB) throw new Error("crypto: malformed local wrap");
    const d = createDecipheriv(
      "aes-256-gcm",
      this.key,
      Buffer.from(ivB, "base64"),
    );
    d.setAuthTag(Buffer.from(tagB, "base64"));
    return Buffer.concat([d.update(Buffer.from(ctB, "base64")), d.final()]);
  }
}

export function kekFromEnv(): Kek {
  const addr = process.env.OPENBAO_ADDR;
  const token = process.env.OPENBAO_TOKEN;
  const keyName = process.env.OPENBAO_TRANSIT_KEY ?? "auditer-kek";
  if (addr && token) return new TransitKek(addr, token, keyName);
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
    throw new Error("crypto: malformed sealed secret");
  }
  const dek = await kek.unwrap(Buffer.from(wrappedB, "base64").toString("utf8"));
  const d = createDecipheriv("aes-256-gcm", dek, Buffer.from(ivB, "base64"));
  d.setAuthTag(Buffer.from(tagB, "base64"));
  return Buffer.concat([
    d.update(Buffer.from(ctB, "base64")),
    d.final(),
  ]).toString("utf8");
}
