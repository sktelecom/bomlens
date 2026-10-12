---
description: The result manifest (bomlens-result.json) every scan writes, for a program that runs the BomLens image as its scan engine.
---

# Engine contract

A program that runs the BomLens image as its scan engine reads `bomlens-result.json`, written to the output folder by every scan. It says how the run ended, which steps ran, were turned off, could not run or failed, and which file in the folder plays which role, so the program does not parse the log or guess file names.

The format is checked against [`schemas/engine-result-1.json`](https://github.com/sktelecom/bomlens/blob/main/schemas/engine-result-1.json) by `tests/test-engine-contract.sh` in CI. This page describes contract version `1.2.0`.

## The file

`bomlens-result.json` has a fixed name, so give each scan its own output folder. A manifest left in the folder by an earlier run is removed when the run starts, before anything else is checked, and the new one is written when the run ends, also when it stops early on an error. A folder with no manifest after the run means the engine was killed before it could write one.

The scan's exit code is unchanged by the contract. A run that produced its SBOM exits 0 even when a step failed along the way; the manifest is where that failure is reported.

| Field | Meaning |
|---|---|
| `contract` | `name` is `bomlens-engine`, `version` the contract version (semantic versioning, separate from the BomLens version) |
| `engine` | `version` is the BomLens version built into the image. `image` and `image_digest` repeat `BOMLENS_IMAGE_REF` and `BOMLENS_IMAGE_DIGEST` when the caller passes them; the image cannot see its own reference |
| `input` | `kind` (`source`, `image`, `sbom`, `binary`, `rootfs`, `firmware`, `ai-model`, `dataset`), the `MODE` it ran in, and `target` (the image reference for an image scan; paths are not recorded) |
| `run` | `status`, `reason`, `started_at`, `ended_at` (UTC), `exit_code` |
| `steps[]` | one entry per step, in the order they were recorded; a step is recorded when it ends (below) |
| `tools` | tool name and version: the generator recorded in the SBOM, syft, and Trivy when the vulnerability scan ran |
| `engines` | the vulnerability engines whose results this run produced (`trivy`, `grype`, `cve-bin-tool`, `yocto`) |
| `data_sources.trivy_db` | the Trivy database's schema version, `updated_at` and `downloaded_at`, when the vulnerability scan ran |
| `outputs[]` | `role`, `path` (relative to the output folder), `sha256` and `bytes` of each file the run wrote |

## Run status

| `run.status` | When |
|---|---|
| `succeeded` | exit code 0, and every recorded step `ok`, `disabled`, or `skipped` because it had nothing to read (`no_input`) |
| `succeeded_degraded` | exit code 0, and at least one step `failed` or `degraded`, or `skipped` for any other reason (a step that was asked for and could not run: its tool not installed, its input over a limit, its image unavailable). The SBOM is valid; read `steps[]` to decide whether the failed step matters to you |
| `failed` | the run exited with a non-zero code (`reason` is `exit_code`) |
| `cancelled` | the run was stopped by a signal (exit code 130 or 143) |

A failed vulnerability scan never yields `succeeded`. Trivy writes an empty result with a `ScanError` when its database cannot be read; the manifest reports that as `scan-security` `failed`, with Trivy's message in `detail`, so "no vulnerabilities" and "the scan did not run" stay apart.

## Steps

Every step that applies to the scan's mode is recorded, also when it did not run. A step that does not apply to the mode at all (CPE enrichment of an AI model) is left out.

| `status` | Meaning |
|---|---|
| `ok` | ran and completed |
| `degraded` | ran, but with less than it needed (for example, the offline end-of-life data was missing) |
| `failed` | ran and failed; the SBOM is still written. Most post-process steps also add their name to the SBOM's `bomlens:pipeline-step-failed` property; the manifest is the complete record |
| `skipped` | could not run: its tool is not in the image, or its input is missing |
| `disabled` | a setting turned it off |

<!-- reasons:begin -->
| `reason` | Meaning |
|---|---|
| `failed` | the step returned an error |
| `timeout` | the step ran out of time |
| `not_installed` | the tool it needs is not in this image |
| `too_large` | the input was over the step's size limit |
| `fallback` | a simpler method was used instead (the SBOM came from the manifest-only fallback, direct dependencies only, or a Poetry project with no `poetry.lock` was resolved only in part: ranged or table dependencies left out, or the pins' own dependencies not resolved), or the step ran without the image it needs (`--deep-license` when the scancode image could not be pulled) |
| `unavailable` | the data the step reads was not available |
| `budget_exhausted` | the step stopped at its work limit |
| `no_input` | there was nothing for the step to read (no source tree, no signing key) |
| `no_components` | the source declares dependencies (a manifest or lock file lists some) but the SBOM has no component; `detail` names the manifests and the resolver steps that failed, if any. Recorded on `generate` |
<!-- reasons:end -->

No step reports `budget_exhausted` yet; it is reserved for a work limit a later release records.

Each step also has `stage` (1 for the SBOM a language image generated before this container started, 2 otherwise), `started_at`, `ended_at`, an optional `detail` of up to 500 characters, and for some steps `counts` (`generate` records `components`, and `unresolved` when it left out packages the generator saw but could not name, which `detail` then says).

<!-- steps:begin -->
| Step | What it does |
|---|---|
| `plan` | write the execution plan (`MODE=PLAN`, below) |
| `generate` | produce the SBOM (stage 1 for a source scan, where the language image ran first) |
| `os-licenses` | an image or root filesystem scan: the licenses of Debian packages from Trivy, which reads the license names, common-licenses references and license text in the copyright files syft leaves as a hash; `counts` gives `replaced` and `hashes_dropped`, `degraded` (`unavailable`) when Trivy could not read the target or gave no Debian package a license, `skipped` (`not_installed`) without Trivy, `disabled` with `BOMLENS_OS_LICENSES=false` |
| `vendored` | identify open source copied into the sources (`--identify-vendored`) |
| `suggest-vendored` | suggest that identification when a C/C++ project scanned near-empty |
| `cocoapods` | add CocoaPods dependencies from `Podfile.lock` |
| `stamp-metadata` | set the root component to the project name and version; the run stops if this fails |
| `docmeta` | record the document's author, tool and lifecycle phase |
| `license-registry` | ask the package registry for missing licences and check a single strong-copyleft or non-commercial one (`--license-registry`); `counts` gives `candidates`, `filled`, `superseded`, `confirmed`, `no_answer`, `not_found`, `non_standard`, `lookup_failed`, `budget_reached` |
| `normalize` | normalize licences, PURLs and duplicates |
| `enrich-cpe` | add CPE identifiers |
| `enrich-os-context` | record the operating system packages' distribution |
| `enrich-distro-supplier` | record the distribution as the OS packages' supplier |
| `enrich-maven-cpe` | add CPEs for Maven components |
| `enrich-github-cpe` | add CPEs for components named by GitHub repository |
| `enrich-interpreter-cpe` | add CPEs for language runtimes |
| `enrich-eol` | mark end-of-life versions (offline data) |
| `enrich-malicious` | mark known malicious packages (offline data) |
| `enrich-staleness` | measure how far behind each version is (opt-in, online) |
| `declared-sources` | apply the dataset sources an AI declaration names |
| `declared-service` | apply the AI service an AI declaration describes |
| `assess-ai-risk` | assess the AI model's risk |
| `resolve-purl` | look each PURL up in its package repository (`--resolve-purl`) |
| `describe-input` | record the supplier SBOM's own format and tool (`--analyze`) |
| `conformance` | check the SBOM against the minimum elements |
| `deep-license` | detect licences in the source files with scancode (`--deep-license`) |
| `source-file-tree` | record the scanned tree's file list |
| `source-snapshot` | keep the scanned files' content for the file viewer |
| `generate-notice` | write the open source notice |
| `scan-security` | match vulnerabilities with Trivy |
| `generate-risk-report` | write the risk report |
| `model-security` | check an AI model file for unsafe content |
| `verify-weights` | check that a model's published weights match their hashes |
| `enrich-aibom` | add details read from the model's hub page |
| `sign` | sign the SBOM with cosign (`--sign`) |
<!-- steps:end -->

## Output roles

| `role` | File |
|---|---|
| `sbom.cyclonedx` | `_bom.json` |
| `sbom.spdx` | `_bom.spdx.json` |
| `sbom.spdx3` | `_bom.spdx3.json` |
| `vulnerabilities.trivy` | Trivy's own result. This is `_security.json` when no other engine added results, and `_security_trivy.json` (Trivy's result kept apart before the merge) when one did |
| `vulnerabilities.all` | `_security.json`, Trivy's result with the other engines' results merged in |
| `vulnerabilities.other` | another engine's result (`_security_grype.json`, `_security_cvebintool.json`, `_security_yocto.json`) |
| `license-scan.scancode` | `_scancode.json` |
| `vendored.cyclonedx` | `_vendored.cdx.json` |
| `conformance` | `_conformance.json` |
| `input-description` | `_input.json` |
| `events` | `bomlens-events.jsonl` (`BOMLENS_EVENTS=file`) |
| `other` | any other file the run wrote (reports, sidecars) |

## Package identifiers

Operating system packages in `bom.json` carry PURLs in the form Trivy and the purl-spec use, so they join the same packages from a Trivy scan or a supplier SBOM:

- deb: the epoch is an `epoch` qualifier, not part of the version (`pkg:deb/debian/bsdutils@2.38.1-5?arch=amd64&distro=debian-12&epoch=1`).
- apk: `distro` is the release id (`distro=3.20.10`).
- deb, rpm, apk: no `upstream` qualifier; the source package is in the `aquasecurity:trivy:SrcName` property (with `SrcVersion`, `SrcRelease`, `SrcEpoch`), which is what Trivy matches distribution advisories on.
- Qualifiers are sorted by name.

A change to this form is a major version change (see below).
## Execution plan

A source scan runs in two containers: stage 1 resolves the dependencies in a cdxgen language image, stage 2 is this image in `POSTPROCESS` mode. A program that runs the containers itself (a Kubernetes Job, a hardened Docker runner) asks BomLens what to run with `MODE=PLAN`: mount the source read-only at `/src` and an output folder at `/host-output`, and the image writes `bomlens-plan.json` there and copies the files stage 1 mounts into `bomlens-plan/`. Nothing is scanned. The format is [`schemas/engine-plan-1.json`](https://github.com/sktelecom/bomlens/blob/main/schemas/engine-plan-1.json).

```bash
docker run --rm -v "$PWD/src:/src:ro" -v "$PWD/out:/host-output" \
  -e MODE=PLAN -e PROJECT_NAME=app -e PROJECT_VERSION=1.0 -e HOST_OUTPUT_DIR=/host-output \
  -e BOMLENS_IMAGE_REF=ghcr.io/sktelecom/bomlens:<version> -e BOMLENS_IMAGE_DIGEST=sha256:... \
  ghcr.io/sktelecom/bomlens:<version>
```

| Field | Meaning |
|---|---|
| `status` | `ok`, or `unsupported` with `reason` and `detail` (`android-sdk-image`: the Android SDK image is built by you and not published) and no stages |
| `input.detected_ecosystem` | the language detection result that chose the stage 1 image |
| `output_file` | the SBOM file name stage 1 writes and stage 2 reads |
| `stages[]` | `generate` (stage 1) and `postprocess` (stage 2), in order |

Each stage gives `image` and `image_digest` (stage 1 is always pinned by digest; stage 2 repeats `BOMLENS_IMAGE_REF` and `BOMLENS_IMAGE_DIGEST`), `user`, `entrypoint`, `args`, `workdir`, `env` (names and values to set), `env_passthrough` (names to pass from your own environment when set), `network` (whether it needs to reach the package registries) and `mounts`. A mount has a `role` (`source`, `output`, `plan-file` with a `source` path inside the output folder, the optional `guard-state`, an optional cache, or the optional `trivy-db`), a `target` and a `mode`. Mount a Trivy cache folder that holds a database (`db/trivy.db`) as `trivy-db`, read-only: with `GENERATE_SECURITY=true` (stage 2's report options are yours to set, as in the image reference), stage 2 then reads that database as it is, with no download, no update and no write, so it runs with no network and a read-only root. A `trivy-db` mount with no database fails `scan-security` with that reason; a database older than `BOMLENS_TRIVY_DB_MAX_AGE_DAYS` days (7, counted from `UpdatedAt` in `db/metadata.json`, when the database was built) records it as `degraded` (`unavailable`). Pass a value that fits how often you refresh the database. The source is writable in stage 1 only: the resolvers write lock files there, and stage 1 puts the tree back as it was when it finishes. A stage 1 that is killed (out of memory, a timeout) cannot; mount a folder of your own as `guard-state` and set `BOMLENS_GUARD_ID` to a unique id per scan, and after a kill run the same stage 1 again with `BOMLENS_GUARD_RESTORE_ONLY=1` to restore the source. Pass `HOST_UID` and `HOST_GID` to both stages so the files they write belong to your user rather than root. Stage 2 also runs as any user (`user` is `null`, so you choose) with a read-only root filesystem, given a writable `$TMPDIR` (default `/tmp`, a tmpfs) and an output folder that user can write; a home it cannot write is replaced with a folder in `$TMPDIR`, unless something is mounted under it. Without a `trivy-db` mount Trivy downloads its database there, several hundred MB, which a memory-backed tmpfs counts as memory: mount `trivy-db`. Stage 1 runs as root: the resolvers install packages and write into the source. It also runs with a read-only root filesystem given a writable `/tmp`, where `HOME` points (Gradle's files go there when the account's `~/.gradle` cannot be written).

Set `CDXGEN_IMAGE_PREFIX` for `MODE=PLAN` to name the stage 1 image from a registry mirror (for example `registry.example/mirror/cdxgen/`, in place of `ghcr.io/cdxgen/`); the digest stays the published one, so the mirror must hold the same image with the same digest: a pull-through cache, or a copy of every platform (`skopeo copy --all`, `crane copy`). A mirror filled with `docker pull`, `docker tag` and `docker push` holds one platform under another digest, and pulling the plan's `image@image_digest` from it fails with "manifest unknown".

`MODE=PLAN` exits 0 when it wrote a plan, `ok` or `unsupported`; an `unsupported` plan records the `plan` step as `skipped` in the result manifest, so the run reads `succeeded_degraded`. It refuses an empty source (usually a mount that did not reach the container) with a non-zero exit. Before writing, it removes an earlier plan and an earlier run's stage 1 outputs from the output folder, since stage 2 cannot tell a fresh SBOM from a leftover one. Stage 1 images are pinned for the cdxgen tag this BomLens release was tested with; overriding `CDXGEN_TAG` makes the language images `unsupported` (`no-pinned-digest`).

Run stage 2 whatever stage 1's exit code, and pass that code as `BOMLENS_STAGE1_EXIT`, `true` in `BOMLENS_STAGE1_OOM` when the stage 1 container was killed for memory, and the stage 1 log saved in the output folder as `BOMLENS_STAGE1_LOG` (a file name). When stage 1 failed or left no SBOM, stage 2 scans the source with syft instead (direct dependencies only), records the reason in `bomlens:sbom-tool-degraded` (`oom`, `disk-space`, `network`, `cdxgen-crash`, `cdxgen-unavailable`), and the result manifest records `generate` as `degraded` (`fallback`), the same as the CLI. For an `unsupported` plan, where no stage 1 ran, pass `BOMLENS_STAGE1_EXIT=127` (or `BOMLENS_STAGE1_REASON=cdxgen-unavailable`) with no SBOM: the reason is then `cdxgen-unavailable`.

## Restricted networks

What a scan reaches over the network, and the setting for each. The execution plan lists these names in `env_passthrough`, so a caller passes on the ones it has set.

| What | Stage | Setting |
|------|-------|---------|
| Proxy | 1, 2 | `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY` (and the lower-case forms) |
| Package registries (pip, npm, Maven and so on) | 1 | through the proxy; each package manager's own mirror settings work as usual |
| Licences looked up by cdxgen | 1 | `FETCH_LICENSE=false` turns it off |
| Trivy vulnerability database | 2 | the `trivy-db` mount (no network at all); or `TRIVY_DB_REPOSITORY` and `TRIVY_JAVA_DB_REPOSITORY` for a mirror. Trivy reads any other `TRIVY_*` variable set in the container (the CLI passes on all it has) |
| EPSS and CISA KEV | 2 | off in the plan (its stage 2 `env` sets `SECURITY_ENRICH=false`); the CLI and the image alone have them on. `EPSS_API` and `KEV_URL` point at a mirror |
| deps.dev (licence registry, version age) | 2 | off unless asked for (`LICENSE_REGISTRY`, `STALENESS_ENRICH`); `LICENSE_REGISTRY_API` points at a mirror |
| PURL repository check | 2 | off unless asked for (`PURL_RESOLVE`) |
| SCANOSS (vendored code identification) | 2 | off unless asked for (`IDENTIFY_VENDORED`); `SCANOSS_API_URL` points at a self-hosted endpoint |
| NVD (checking deep CVE matches) | 2 | off unless asked for (`SECURITY_NVD_VERIFY` with `DEEP_CVE`) |

End-of-life and malicious-package data are bundled in the image and need no network.

## Progress events

Set `BOMLENS_EVENTS=file` to have the run write one JSON object per line to `bomlens-events.jsonl` in the output folder as it goes, or `BOMLENS_EVENTS=stderr` to write them to stderr, where they share the stream with warnings and the bundled tools' own messages: read only the lines that start with `{"v":1`. Use them to show progress while the run is going; the result manifest is the final record, and where the two differ the manifest wins. Each line follows [`schemas/engine-event-1.json`](https://github.com/sktelecom/bomlens/blob/main/schemas/engine-event-1.json):

```json
{"v":1,"seq":12,"ts":"2026-10-11T03:04:05Z","type":"step.end","step":"normalize","stage":2,"status":"ok","reason":null}
```

| `type` | When |
|---|---|
| `run.start` | the run began |
| `step.start` | a step began (`step`, `stage`) |
| `step.end` | a step ended, with `status`, `reason` and `detail` as in the manifest. A step that was turned off or could not run has an end without a start |
| `run.end` | the run ended, with the manifest's `run.status`. A run that is stopped (`cancelled`) can leave a step with a start and no end |

`seq` rises by one per event, so a reader can tell a lost or reordered line. The file is listed in the manifest's `outputs` with the role `events`, and the manifest appears only once the events are complete. An events file left by an earlier run in the folder is removed when a run starts.

## Versioning

The contract version changes on its own schedule, not with each BomLens release.

- Major: a field, step id, output role or status value is removed, renamed, or changes meaning, or a change makes the same input produce a different PURL or licence id, or reports a failure as success.
- Minor: a new optional field, step id, reason, output role or status detail. A reader ignores values it does not know.
- Patch: no change a reader can see in the fields above.

Properties named `bomlens:*` in the SBOM, and the human-readable reports, are not part of the contract and can change in any release.
