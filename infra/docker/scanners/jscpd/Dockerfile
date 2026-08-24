# jscpd — copy/paste detection for the quality pillar.
#
# Built here because there is no jscpd container image ANYWHERE. The adapter
# used to reference `ghcr.io/kucherenko/jscpd:4.0.5`, which has never existed —
# so the quality pillar failed on "no such image" on every run, and a failed
# scanner is a hole in a pillar, not an error anyone sees. jscpd is published on
# npm only.
#
# Pinned to an exact version, not a range: two analyses of the same commit must
# report the same duplication, and `npm i -g jscpd` without a version would make
# the result depend on the day the image was built.
#
# Build:
#   docker build -t auditer/jscpd:5.0.16-1 infra/docker/scanners/jscpd

# Base pinned by digest, not by the moving `22-alpine` tag: it is the only
# build input left that could change under a rebuild, and a scanner whose
# runtime changes silently cannot back a reproducible report.
FROM node:22-alpine@sha256:c610fcdfb1d5b4740dd70c284ed3cb16bb857e0f7166196e36a5501df7a3aa32

ARG JSCPD_VERSION=5.0.16
RUN npm install -g --no-fund --no-audit "jscpd@${JSCPD_VERSION}" \
  && npm cache clean --force

COPY run-jscpd /usr/local/bin/run-jscpd
RUN chmod +x /usr/local/bin/run-jscpd

# Non-root, matching the sandbox's own user so the read-only repo mount is
# readable and nothing is ever written back to it.
USER 65534:65534
ENTRYPOINT ["/usr/local/bin/run-jscpd"]
