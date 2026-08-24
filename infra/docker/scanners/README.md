# Scanner sandbox images

Scanner containers are pulled and run by the **worker**, through the
`docker-socket-proxy` (never the raw host socket), under **gVisor (runsc)**,
hardened and no-network-by-default (see
`packages/audit-engine/src/sandbox/docker-gvisor-runner.ts`).

## Digest pinning — current state

Every third-party scanner image is referenced **by digest**, not by tag, in its
adapter (`packages/audit-engine/src/scanners/*.ts`, field `readonly image`). A
tag is a mutable pointer: the publisher can repoint `v8.21.2` at a new build at
any time, and two analyses of the same commit would then disagree for reasons
that have nothing to do with the commit — which is exactly the determinism the
reports claim. A digest is the content address of the manifest; it cannot move.

Each adapter keeps the human-readable version in a comment directly above the
digest. Do not drop it: a bare `@sha256:` tells a reader nothing about which
version is running.

| Pillar   | Adapter         | Version | Digest | Cosign | Licence |
|----------|-----------------|---------|--------|--------|---------|
| secrets  | `gitleaks`      | `ghcr.io/gitleaks/gitleaks` v8.21.2 | `sha256:0e99e8821643ea5b235718642b93bb32486af9c8162c8b8731f7cbdc951a7f46` | none published | MIT |
| sca      | `osv-scanner`   | `ghcr.io/google/osv-scanner` v1.9.2 | `sha256:239d47ec1a70af430c3cd57524d18e8b2d2dc2f28869384217b64f409ab6650a` | none published | Apache-2.0 |
| quality  | `scc`           | `ghcr.io/boyter/scc` v3.4.0 | `sha256:537c0a10cf21cdbefb8b1e644e3cef9a736bdc0ca11ee8deee2dc31e5b8ed7a3` | **signed, verified** | MIT |
| hygiene  | `trivy-config`  | `aquasec/trivy` 0.58.0 | `sha256:b88012e2a0a309d6a8a00463d4e63e5e513377fb74eccbc8f9b0f8f81940ebeb` | **signed, verified** | Apache-2.0 |
| hygiene  | `hadolint`      | `hadolint/hadolint` 2.12.0 | `sha256:30a8fd2e785ab6176eed53f74769e04f125afb2f74a6c52aef7d463583b6d45e` | none published | GPL-3.0 (separate container, never linked) |
| dast     | `nuclei`        | `projectdiscovery/nuclei` v3.4.10 | `sha256:aeb5ea2db32a252b8135707d2ad0e89b90e19a18ea7816d38759bc51efb46b97` | none published | MIT |
| ux       | `lighthouse`    | `femtopixel/google-lighthouse` v8.6.0 | `sha256:609559dac4184c63bcddaa7e109f3865c4eb44f46a3eb91eeaf22a09598eccdc` | none published | Apache-2.0 (Lighthouse) |

Two references in that table were not merely unpinned, they were **unpullable**,
and pinning is what surfaced it:

- `nuclei` named `v3.3.7`. Upstream cut a v3.3.7 GitHub release but never pushed
  a container for it — Docker Hub goes `v3.3.6` → `v3.3.8`. Every DAST run would
  have died at pull time. Now `v3.4.10`, the newest v3.4 patch, confirmed
  pullable on the x86_64 deploy host.
- `lighthouse` named `8.6.0`. That publisher tags with a leading `v`, so the real
  tag is `v8.6.0` and `8.6.0` resolves to nothing. Same intended version, real
  tag, pinned.

## A pinned image is not a working scanner

Pinning forced every adapter's argv to be run rather than read, and two of them
did not survive it. Both failed in the direction that hides: a pillar that
reports **clean** instead of reporting an error.

- **`trivy-config` could never run.** It passed `--skip-db-update`, which is not
  a flag of `trivy config` (it belongs to the vulnerability scanner). trivy
  0.58.0 exits FATAL `unknown flag`. The offline switch is `--skip-check-update`.
- **`trivy-config` also wrote its report to a file.** `--output /scratch/trivy.sarif`
  put the SARIF in the scratch tmpfs while `parse` reads `result.stdout`, so even
  a run that executed would have been discarded with the container. Same defect
  that was found in jscpd. Fixed by dropping `--output`: trivy writes SARIF to
  stdout, the only channel the runner keeps.
- **`osv-scanner` passed a flag that does not exist**, `--experimental-local-db-path`.
  osv-scanner 1.9.2 ignores it silently rather than rejecting it, so it read like
  the DB location was pinned when the only thing pointing the scanner at the
  mounted DB is `OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY`. Removed. (Verified with
  no DB mounted it exits 127, which `classifyExit` maps to `fail` — a missing DB
  is loud, not a silent zero-vulnerability report.)

**`nuclei` is the one still open, and it is the worst of the three.** Upstream's
Dockerfile (checked at v3.4.10) installs only the nuclei binary on top of alpine
— **no template corpus**. nuclei fetches nuclei-templates from GitHub on first
run, which this sandbox forbids twice: egress is proxy-scoped to the audited host
alone, and the container runs as 65534 with no writable HOME. A run with zero
templates probes nothing, prints nothing and **exits 0**, so `classifyExit`
records success and the DAST pillar reads clean on a scan that never happened. A
stdout heuristic cannot patch this — `-silent` suppresses the template count. The
fix is to bake a reviewed, pinned nuclei-templates corpus into an image we build
(the `auditer/semgrep-rules` pattern) and pass `-templates`.

So when bumping or adding a scanner, **run the adapter's exact argv against the
pinned image** and confirm the report lands on stdout. `pnpm build` proves
nothing about either.

`femtopixel/google-lighthouse:v8.6.0` is a **single amd64 manifest** (no manifest
list). It runs on the amd64 deploy host and will not run on an arm64 one. The six
others are amd64 + arm64 manifest lists, so the digests above are index digests
and stay correct on either architecture.

## Images we build ourselves — deliberately not digest-pinned

| Image | Built from | Referenced by |
|-------|-----------|---------------|
| `auditer/semgrep-rules:1.99.0-2` | `infra/docker/scanners/semgrep` | `scanners/semgrep.ts` |
| `auditer/jscpd:5.0.16-1` | `infra/docker/scanners/jscpd` | `scanners/jscpd.ts` |
| `auditer/chromium-pdf:136.0.7103.113-1` | `infra/docker/scanners/chromium` | `apps/worker/src/pdf.ts` |

These carry **no `@sha256:`, and should not**. A digest identifies a manifest in a
registry; these images were never pushed to one. They are built on the deploy
host by `.github/workflows/deploy.yml` and resolved from the local daemon, and
the id a local `docker build` produces is host-specific — pinning it here would
name something that exists on exactly one machine and would break on the next
rebuild.

Their reproducibility comes from their **build inputs** instead, which is where
to look when one of them drifts:

- `semgrep`: pinned `semgrep/semgrep:1.99.0` base + pinned sast-rules commit.
- `chromium`: base pinned by digest (`alpine:3.21@sha256:…`) + exact apk versions.
- `jscpd`: pinned `jscpd@5.0.16`, but its base is `node:22-alpine`, a **moving
  tag** — the one build input in this set that can still change under a rebuild.
  Pin it by digest when that image is next touched.

Push any of these to a registry and it moves to the table above: pin it like the
others.

## Cosign — what is actually verified

The honest answer: **two of the seven third-party images are signed, and nothing
is verified at scan time.** The previous version of this file promised a
cosign gate that did not exist; here is the measured state instead.

Verified with `cosign v2.4.1` against each pinned digest:

| Image | `cosign verify` | Signer identity |
|-------|-----------------|-----------------|
| `aquasec/trivy` | **passes** | `github.com/aquasecurity/trivy/.github/workflows/reusable-release.yaml@refs/tags/v0.58.0`, issuer `https://token.actions.githubusercontent.com` |
| `ghcr.io/boyter/scc` | **passes** | `github.com/boyter/scc/.github/workflows/docker-publish.yml@refs/tags/v3.4.0`, issuer `https://token.actions.githubusercontent.com` |
| `ghcr.io/gitleaks/gitleaks` | `no signatures found` | — |
| `ghcr.io/google/osv-scanner` | `no signatures found` | — |
| `hadolint/hadolint` | `no signatures found` | — |
| `projectdiscovery/nuclei` | `no signatures found` | — |
| `femtopixel/google-lighthouse` | `no signatures found` | — |

Five of seven publish no cosign signature at all, so there is nothing to verify
and no configuration will change that. Where a signature does exist it was
checked once, by hand, at pin time — recorded in the adapter comment. There is
**no runtime cosign check**: the worker starts containers through the
docker-socket-proxy, which has no cosign and no policy engine.

What the digest pin buys without cosign is still the property we need: the image
cannot change under us. It does not prove the publisher's registry account was
not compromised *before* we resolved the digest. Adding a real gate would mean a
signature-enforcing admission step in front of the daemon, and it would only ever
cover trivy and scc. Do not re-promise it here until it exists.

Re-run the check for one image with:

```sh
docker run --rm ghcr.io/sigstore/cosign/cosign:v2.4.1 verify \
  aquasec/trivy@sha256:b88012e2a0a309d6a8a00463d4e63e5e513377fb74eccbc8f9b0f8f81940ebeb \
  --certificate-identity 'https://github.com/aquasecurity/trivy/.github/workflows/reusable-release.yaml@refs/tags/v0.58.0' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com'
```

Pin the identity as above rather than `--certificate-identity-regexp '.*'`: the
wildcard form accepts a signature from *anyone* who can get a Fulcio certificate
and proves only that the image was signed, not by whom.

## Bumping a scanner

1. **Resolve the digest of the exact version you want.** Never `latest`, and
   check the tag exists before believing it does — two of ours did not.

   ```sh
   # index digest, works without pulling; identical to what `crane digest` returns
   docker buildx imagetools inspect --raw <repo>:<tag> | shasum -a 256
   ```

   `docker manifest inspect <repo>:<tag>` or, if the image is already local,
   `docker pull <repo>:<tag> && docker inspect --format='{{index .RepoDigests 0}}' <repo>:<tag>`
   give the same answer.

2. **Check whether it is signed**, with the `cosign verify` invocation above, and
   update both the table and the adapter comment. If it stopped being signed, say
   so; if it started, record the signer identity.

3. **Replace the digest in the adapter**, keeping the version comment above it
   current. That comment is the only place a human can read which version runs.

4. **Run it for real** — a compile proves nothing about an image reference. Start
   the container with the pinned reference and check the output is the shape the
   adapter parses, and that the version inside matches the tag you claim to have
   pinned:

   ```sh
   docker run --rm --network none -v "$PWD:/repo:ro" \
     hadolint/hadolint@sha256:30a8fd... hadolint --format sarif /repo/Dockerfile
   # -> SARIF whose tool.driver.version must equal the version in the comment
   ```

5. **Update the pre-pull list in `.github/workflows/deploy.yml`** — see below.

## The deploy pre-pull list must be bumped in lockstep

`.github/workflows/deploy.yml` ("Pull third-party scanner images") warms the
host's image set, because the docker-socket-proxy may create containers but not
pull: an image missing from the host fails one pillar and still lets the run
report success, with a hole in its coverage.

That list is now **by digest**, matching the adapters exactly. It used to name
tags, including the two that never existed (`projectdiscovery/nuclei:v3.3.7`,
`femtopixel/google-lighthouse:8.6.0`) — and with `set -e` on that loop, a
`docker pull` on either one failed the whole deploy step.

Tags there were the wrong shape even once corrected. A tag warms whatever the
publisher currently points it at; if that is no longer the pinned digest, the
host looks fully provisioned while every scan fails on "no such image". Digest on
both sides means the step either fetches exactly what the adapters ask for, or
fails at deploy time where someone is watching.

**Update both in the same change.** The digest in the adapter and the digest in
the workflow are one fact written twice.

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
