import { Logger } from "@nestjs/common";
import { dropObjects as dropObjectsShared } from "@auditer/retention";

const logger = new Logger("artifact-purge");

/**
 * Remove the bytes behind Artifact rows from object storage.
 *
 * The implementation — and the reasoning about why bytes go BEFORE rows — now
 * lives in @auditer/retention, because the nightly purge runs in the worker and
 * needs the same erasure. This file is the Nest-flavoured entry point: it binds
 * the api's Logger so the four call sites keep their signature and their log
 * channel unchanged.
 */
export async function dropObjects(keys: readonly string[]): Promise<number> {
  return dropObjectsShared(keys, logger);
}
