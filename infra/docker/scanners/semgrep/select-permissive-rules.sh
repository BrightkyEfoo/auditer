#!/usr/bin/env bash
# Selects the Semgrep rules we are legally allowed to run AS A SERVICE.
#
# Why this exists: rule corpora carry licences independent of the engine, and
# most of the well-known ones forbid exactly our use case.
#
#   - semgrep/semgrep-rules  → "Semgrep Rules License v1.0": you may not "make
#     them available to others as a service". Disqualified outright.
#   - opengrep/opengrep-rules → LGPL-2.1 + Commons Clause: forbids selling a
#     service whose value derives from the software. Disqualified too.
#   - gitlab-org/security-products/sast-rules → MIT for its own rules, but it
#     VENDORS third-party rules under GPL-2.0, LGPL-3.0 and Commons Clause in
#     the same tree.
#
# GitLab annotates every rule file with its real licence, so we filter on that
# annotation rather than on directory layout: an upstream reorganisation then
# cannot silently pull a copyleft rule into the image. Anything whose licence we
# cannot READ is dropped — unknown is treated as forbidden, never as permissive.
set -euo pipefail

SRC="${1:?usage: select-permissive-rules.sh <src> <dest>}"
DEST="${2:?usage: select-permissive-rules.sh <src> <dest>}"

# Licences under which a commercial SaaS may execute and distribute the rules.
ALLOW_RE='MIT|Apache 2\.0|Apache-2\.0|BSD'
# Explicit denies, checked first so a file naming two licences is rejected.
# "Commons Clause" is the decisive one: it is what makes an otherwise-LGPL rule
# unusable for a paid service.
DENY_RE='GPL|Commons Clause|Semgrep Rules License|CC BY-SA|Proprietary'

mkdir -p "$DEST"
kept=0
dropped=0
: >"/tmp/kept.txt"
: >"/tmp/dropped.txt"

while IFS= read -r -d '' file; do
  rel="${file#"$SRC"/}"
  # The annotation lives in the first few comment lines of each rule file.
  header="$(head -n 6 "$file" | grep -i '^#\s*License:' || true)"

  if [[ -z "$header" ]]; then
    printf '%s\tNO-LICENCE-HEADER\n' "$rel" >>/tmp/dropped.txt
    dropped=$((dropped + 1))
    continue
  fi
  if grep -Eq "$DENY_RE" <<<"$header"; then
    printf '%s\t%s\n' "$rel" "$(sed 's/^#\s*License:\s*//I' <<<"$header")" >>/tmp/dropped.txt
    dropped=$((dropped + 1))
    continue
  fi
  if ! grep -Eq "$ALLOW_RE" <<<"$header"; then
    printf '%s\tUNRECOGNISED\t%s\n' "$rel" "$header" >>/tmp/dropped.txt
    dropped=$((dropped + 1))
    continue
  fi

  mkdir -p "$DEST/$(dirname "$rel")"
  cp "$file" "$DEST/$rel"
  printf '%s\t%s\n' "$rel" "$(sed 's/^#\s*License:\s*//I' <<<"$header")" >>/tmp/kept.txt
  kept=$((kept + 1))
done < <(find "$SRC" -name '*.yml' -not -path '*/.git/*' -not -path '*/qa/*' -not -path '*/spec/*' -print0)

# A build that silently produces an empty ruleset would ship a SAST pillar that
# finds nothing and reports success — the exact failure this image replaces.
if [[ "$kept" -lt 100 ]]; then
  echo "FATAL: only $kept rules selected; upstream layout or licence headers changed." >&2
  head -n 20 /tmp/dropped.txt >&2
  exit 1
fi

# Attribution + audit trail, shipped inside the image so the provenance of any
# finding can be traced back from a running container.
{
  echo "# Semgrep ruleset — provenance and licences"
  echo
  echo "Source: gitlab-org/security-products/sast-rules"
  echo "Rules kept: $kept — rules dropped: $dropped"
  echo
  echo "## Licences of the rules in this image"
  cut -f2 /tmp/kept.txt | sort | uniq -c | sort -rn
  echo
  echo "## Licences excluded (never copied into the image)"
  cut -f2 /tmp/dropped.txt | sort | uniq -c | sort -rn
} >"$DEST/LICENSES.md"

cp "$SRC/LICENSE" "$DEST/LICENSE-gitlab-sast-rules.txt" 2>/dev/null || true

echo "selected $kept rules, dropped $dropped"
