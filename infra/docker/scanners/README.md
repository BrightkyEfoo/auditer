# Scanner sandbox images

Scanner containers are pulled and run by the **worker**, through the
`docker-socket-proxy` (never the raw host socket), under **gVisor (runsc)**,
hardened and no-network-by-default (see
`packages/audit-engine/src/sandbox/docker-gvisor-runner.ts`).

## Digest pinning + cosign (MANDATORY before promotion)

Adapters currently reference images by tag (e.g.
`ghcr.io/gitleaks/gitleaks:v8.21.2`). **Before running untrusted repos in
production, replace every tag with a cosign-verified `@sha256:` digest** so only
the exact reviewed binary can execute. Workflow:

```sh
# 1. Resolve + verify the image
cosign verify ghcr.io/gitleaks/gitleaks:v8.21.2 \
  --certificate-identity-regexp '.*' --certificate-oidc-issuer-regexp '.*'
DIGEST=$(crane digest ghcr.io/gitleaks/gitleaks:v8.21.2)

# 2. Pin it in the adapter (image field), e.g.
#    ghcr.io/gitleaks/gitleaks@sha256:<DIGEST>
```

Track the pinned digest + license per scanner in the adapter metadata.

## Wave 1 images

| Pillar   | Adapter        | Image (pin the digest)                     | License |
|----------|----------------|--------------------------------------------|---------|
| secrets  | `gitleaks`     | `ghcr.io/gitleaks/gitleaks:v8.21.2`        | MIT     |
| sca      | `osv-scanner`  | `ghcr.io/google/osv-scanner:v1.9.2`        | Apache-2.0 |

## Offline vuln DB (osv-scanner)

osv-scanner runs `--offline`. The worker mounts a pre-fetched OSV database
read-only at `/opt/osv-db` (env `OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY`). Refresh
it on a schedule outside the sandbox; the sandbox itself never has network.

## gVisor runtime

Install runsc on the Docker host and register it as a runtime:

```sh
# host: install gVisor, then in /etc/docker/daemon.json
{ "runtimes": { "runsc": { "path": "/usr/local/bin/runsc" } } }
```

The runner requests `Runtime: runsc`. In dev without gVisor, set
`SANDBOX_RUNTIME=runc` (weaker isolation — never in production).
