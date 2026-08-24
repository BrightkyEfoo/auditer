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

FROM node:22-alpine

ARG JSCPD_VERSION=5.0.16
RUN npm install -g --no-fund --no-audit "jscpd@${JSCPD_VERSION}" \
  && npm cache clean --force

COPY run-jscpd /usr/local/bin/run-jscpd
RUN chmod +x /usr/local/bin/run-jscpd

# Non-root, matching the sandbox's own user so the read-only repo mount is
# readable and nothing is ever written back to it.
USER 65534:65534
ENTRYPOINT ["/usr/local/bin/run-jscpd"]
