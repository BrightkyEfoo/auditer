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
 * The version this replaces looked for the first `{"` — an opening brace glued
 * to a key — and it silently discarded the reports of every tool that
 * pretty-prints. zizmor and trivy both emit `{\n  "version": ...`, so the slice
 * started at the first `{"` INSIDE the document (`[{"logicalLocations"`), the
 * parse threw, `parse()` returned an empty array, and the pillar read clean.
 * Measured: trivy config produced 4 findings on the verification fixture and all
 * four were thrown away here, after the adapter had already been fixed twice.
 *
 * The tiers below go from strictest to loosest, so a tool that prints nothing
 * but JSON is never at the mercy of a heuristic:
 *
 *   1. the whole of stdout parses — the common case;
 *   2. first `{` to last `}` — a tool that printed progress lines around it;
 *   3. the same slice starting from the first `{` on its own line — a tool whose
 *      progress lines themselves contain braces.
 */
export function extractSarif(s: string): string | null {
  const trimmed = s.trim();
  if (!trimmed) return null;

  if (parses(trimmed)) return trimmed;

  const first = trimmed.indexOf("{");
  const last = trimmed.lastIndexOf("}");
  if (first === -1 || last === -1 || last < first) return null;

  const sliced = trimmed.slice(first, last + 1);
  if (parses(sliced)) return sliced;

  // A progress line carrying a brace shifted the start. Retry from each line
  // that BEGINS a JSON document; there are only ever a handful.
  const lines = trimmed.split("\n");
  let offset = 0;
  for (const line of lines) {
    if (line.startsWith("{") && offset > first) {
      const candidate = trimmed.slice(offset, last + 1);
      if (parses(candidate)) return candidate;
    }
    offset += line.length + 1;
  }

  // Nothing parsed. Return the widest slice anyway: the caller parses again and
  // handles the failure, and returning null here would erase the difference
  // between "no report" and "a report we could not read".
  return sliced;
}

function parses(s: string): boolean {
  try {
    JSON.parse(s);
    return true;
  } catch {
    return false;
  }
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
