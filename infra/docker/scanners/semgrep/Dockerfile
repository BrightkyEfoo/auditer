# Semgrep with a VENDORED, licence-filtered ruleset baked in at /rules.
#
# The SAST pillar was silently dead before this image existed: the adapter ran
# `semgrep --config /rules` against the upstream semgrep image, which has no
# /rules directory, so every scan exited non-zero and was classified as a failed
# scan producing zero findings.
#
# Baking the rules in (rather than `--config p/...`) is what keeps scans offline
# and reproducible: no registry fetch at scan time, and the rules that produced
# a given report are pinned to the image digest recorded on that scan.
#
# Build:
#   docker build -t auditer/semgrep-rules:1.99.0-1 infra/docker/scanners/semgrep

FROM alpine/git:latest AS rules

# Pinned commit, not a branch: the ruleset must not change under a rebuild, or
# two scans of the same commit would return different findings.
ARG SAST_RULES_REF=39fc7de205d447c70e75a1fdabdcf4588733adc8

RUN apk add --no-cache bash
RUN git clone --filter=blob:none \
      https://gitlab.com/gitlab-org/security-products/sast-rules.git /src \
 && git -C /src checkout --quiet "$SAST_RULES_REF"

COPY select-permissive-rules.sh /select-permissive-rules.sh
RUN bash /select-permissive-rules.sh /src /rules && cat /rules/LICENSES.md

FROM semgrep/semgrep:1.99.0
COPY --from=rules /rules /rules
