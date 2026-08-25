/**
 * Reading a SARIF report off a scanner's stdout, and deciding whether an exit
 * code that "means findings" really did.
 *
 * Several tools here exit 1 for "I found something" and 1 for "I crashed", and
 * four adapters independently mapped 1 to success. That mapping is correct for
 * the first case and catastrophic for the second: a crash was recorded as a
 * SUCCESSFUL scan with zero findings, which is the one failure a customer cannot
 * see. Both engines below were dead in production for exactly this reason and
 * neither showed up as an error anywhere:
 *
 *   semgrep  → OSError: [Errno 30] Read-only file system: '/.semgrep'   exit 1
 *   hadolint → /repo/Dockerfile: does not exist                          exit 1
 *
 * The discriminator is not the exit code, it is the REPORT. A tool that found
 * findings printed them; a tool that crashed printed nothing. So `success`
 * requires a parseable report on stdout whenever the exit code is ambiguous.
 */

/**
 * Extract the JSON document from a scanner's stdout.
 *
 * Scanners interleave progress lines with the report, so the payload is sliced
 * between the first `{"` and the last `}` rather than assuming stdout is pure
 * JSON.
 */
export function extractSarif(s: string): string | null {
  const start = s.indexOf('{"');
  const end = s.lastIndexOf("}");
  if (start === -1 || end === -1 || end < start) return null;
  return s.slice(start, end + 1);
}

/**
 * True when stdout carries something that actually parses as a SARIF log.
 *
 * A crash can still leave a `{"` somewhere in a stack trace, so this parses
 * rather than pattern-matching, and it insists on the `runs` array — the one
 * structural element every SARIF log has and no error message does.
 */
export function hasSarifReport(stdout: string): boolean {
  const json = extractSarif(stdout);
  if (!json) return false;
  try {
    const parsed: unknown = JSON.parse(json);
    return (
      typeof parsed === "object" &&
      parsed !== null &&
      Array.isArray((parsed as { runs?: unknown }).runs)
    );
  } catch {
    return false;
  }
}
