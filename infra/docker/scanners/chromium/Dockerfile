# Headless Chromium that turns the print-ready report HTML into a PDF.
#
# The PDF is the deliverable: a director opens it, an auditor archives it. The
# renderer lives in its OWN image rather than in the app image for two reasons.
# It weighs ~693 MB (222 MB of Chromium, the rest its Mesa/Vulkan/GTK
# dependency closure, ~20 MB of fonts) — carrying that in the image that runs
# api, worker AND web would tax every deploy for a step that runs once per
# report. And the renderer parses attacker-influenced content: findings carry
# repository text, so the HTML is untrusted input. Keeping it in a separate,
# network-less, capability-less container means a Chromium exploit lands in a
# throwaway sandbox, not next to the database credentials.
#
# Build:
#   docker build -t auditer/chromium-pdf:136.0.7103.113-1 infra/docker/scanners/chromium

# Base pinned by digest: the tag alpine:3.21 moves, and a renderer that changes
# under a rebuild re-paginates a report that is supposed to be reproducible.
FROM alpine:3.21@sha256:48b0309ca019d89d40f670aa1bc06e426dc0931948452e8491e3d65087abc07d

# Exact package versions, same reasoning as the pinned ruleset commit in the
# semgrep image: two renders of the same report must not disagree because the
# distribution shipped a new Chromium in between.
#
# The cost is explicit and accepted: Alpine keeps only the newest revision of a
# package in a branch repository, so when 3.21 moves to -r1 this build FAILS
# with "unable to select packages". That failure is the point — it is a one-line
# ARG bump plus a new image tag, and it is far cheaper than discovering after
# the fact that last month's report cannot be reproduced.
ARG CHROMIUM_VERSION=136.0.7103.113-r0
ARG FONT_NOTO_VERSION=24.7.1-r0
ARG TTF_LIBERATION_VERSION=2.1.5-r2

# Fonts are not optional. The report asks for "Iowan Old Style", Georgia and a
# monospace face; none of them exist here, so without a fallback family every
# glyph renders as a box. Liberation covers the serif/sans/mono trio with metric
# compatibility, Noto covers the accented Latin the French text needs.
RUN apk add --no-cache \
      "chromium=${CHROMIUM_VERSION}" \
      "font-noto=${FONT_NOTO_VERSION}" \
      "ttf-liberation=${TTF_LIBERATION_VERSION}"

COPY render-pdf /usr/local/bin/render-pdf
RUN chmod 0555 /usr/local/bin/render-pdf

# nobody:nogroup — the same uid the sandbox spec pins (DEFAULT_HARDENING.user),
# declared here too so a plain `docker run` of this image is unprivileged as
# well. Chromium never needs to write inside the image: everything it produces
# goes to the tmpfs the runner mounts at /scratch.
USER 65534:65534

ENTRYPOINT ["/usr/local/bin/render-pdf"]
