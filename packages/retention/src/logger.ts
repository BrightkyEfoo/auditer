/**
 * The narrowest logger this package can work against.
 *
 * Deliberately not `@nestjs/common`'s Logger: the whole point of moving the
 * purge out of the api was that the WORKER can run it, and the worker has no
 * Nest container. Nest's Logger satisfies this shape structurally, so the api
 * keeps passing its own and its log lines are unchanged.
 */
export interface PurgeLogger {
  log(message: string): void;
  warn(message: string): void;
}

/** Fallback for callers that have no logger — never silent. */
export const consoleLogger: PurgeLogger = {
  // eslint-disable-next-line no-console
  log: (m) => console.log(m),
  // eslint-disable-next-line no-console
  warn: (m) => console.warn(m),
};
