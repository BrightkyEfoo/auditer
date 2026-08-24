import { Logger } from "@nestjs/common";
import { getStorage } from "@auditer/storage";

const logger = new Logger("artifact-purge");

/**
 * Remove the bytes behind Artifact rows from object storage.
 *
 * Nothing cascades from Postgres into S3: deleting an `artifacts` row (directly
 * or through `ON DELETE CASCADE` from `audit_runs`) leaves the object in the
 * bucket forever. Every code path that erases artifacts must therefore call
 * this FIRST, before the rows go.
 *
 * The order matters and it is not arbitrary. Storage and Postgres cannot commit
 * together, so a crash between them leaves one of two states:
 *   - rows first  → objects with no row: unreachable garbage that no later
 *     sweep can even enumerate, and it is exactly the data we promised to erase;
 *   - bytes first → a row pointing at a missing object: a download that fails
 *     loudly, is visible, and can be cleaned up.
 * An erasure promise has to fail toward "gone", so the bytes go first.
 *
 * Failures are logged and swallowed on purpose: a bucket that is briefly
 * unreachable must not block an account deletion the user is entitled to.
 */
export async function dropObjects(keys: readonly string[]): Promise<number> {
  if (keys.length === 0) return 0;

  const storage = getStorage();
  let dropped = 0;
  for (const key of keys) {
    try {
      await storage.delete(key);
      dropped += 1;
    } catch (err) {
      // Named at WARN, not swallowed silently: an object we failed to delete is
      // a retention breach, and the only trace of it is this line.
      logger.warn(`failed to delete object ${key}: ${String(err)}`);
    }
  }
  return dropped;
}
