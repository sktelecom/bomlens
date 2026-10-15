---
description: The result manifest (bomlens-result.json) every scan writes, for a program that runs the BomLens image as its scan engine.
---

# Engine contract

A program that runs the BomLens image as its scan engine reads `bomlens-result.json`, written to the output folder by every scan. It says how the run ended, which steps ran, were turned off, could not run or failed, and which file in the folder plays which role, so the program does not parse the log or guess file names.

The format is checked against [`schemas/engine-result-1.json`](https://github.com/sktelecom/bomlens/blob/main/schemas/engine-result-1.json) by `tests/test-engine-contract.sh` in CI. This page describes contract version `1.3.0`.

## The file

`bomlens-result.json` has a fixed name, so give each scan its own output folder. A manifest left in the folder by an earlier run is removed when the run starts, before anything else is checked, and the new one is written when the run ends, also when it stops early on an error. A folder with no manifest after the run means the engine was killed before it could write one.

The scan's exit code is unchanged by the contract. A run that produced its SBOM exits 0 even when a step failed along the way; the manifest is where that failure is reported. The one exception is a `--component-versions` file that is refused: every file is still written, and the run exits 1, since the versions it was given were not applied.

| Field | Meaning |
|---|---|
| `contract` | `name` is `bomlens-engine`, `version` the contract version (semantic versioning, separate from the BomLens version) |
| `engine` | `version` is the BomLens version built into the image. `image` and `image_digest` repeat `BOMLENS_IMAGE_REF` and `BOMLENS_IMAGE_DIGEST` when the caller passes them; the image cannot see its own reference |
| `input` | `kind` (`source`, `image`, `sbom`, `binary`, `rootfs`, `firmware`, `ai-model`, `dataset`), the `MODE` it ran in, `target` (the image reference for an image scan; paths are not recorded), and for an image scan `image` (below) |
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
| `fallback` | a simpler method was used instead (the SBOM came from the manifest-only fallback, direct dependencies only, or a Poetry project with no `poetry.lock` was resolved only in part: ranged or table dependencies left out, or the pins' own dependencies not resolved), or the step ran without the image it needs (`--deep-license` when the scancode image could not be pulled, `--deep-cve` when the grype image could not be pulled) |
| `unavailable` | the data the step reads was not available |
| `budget_exhausted` | the step stopped at its work limit |
| `no_input` | there was nothing for the step to read (no source tree, no signing key) |
| `no_components` | the source declares dependencies (a manifest or lock file lists some) but the SBOM has no component; `detail` names the manifests and the resolver steps that failed, if any. Recorded on `generate` |
<!-- reasons:end -->

No step reports `budget_exhausted` yet; it is reserved for a work limit a later release records.

Each step also has `stage` (1 for the SBOM a language image generated before this container started, 2 otherwise), `started_at`, `ended_at`, an optional `detail` of up to 500 characters, and for some steps `counts` (`generate` records `components`, and `unresolved` when it left out packages the generator saw but could not name, which `detail` then says). In `POSTPROCESS` mode `generate` also has `input_fingerprint`, `reused`, `reuse_unsafe` and, after an execution plan, `plan_mismatch` (see [Input fingerprint](#input-fingerprint)).

<!-- steps:begin -->
| Step | What it does |
|---|---|
| `plan` | write the execution plan (`MODE=PLAN`, below) |
| `generate` | produce the SBOM (stage 1 for a source scan, where the language image ran first); `degraded` (`failed`) when a step inside generation failed (a syft pass of a firmware scan, a resolver step of a source scan) and recorded itself only in the SBOM's `bomlens:pipeline-step-failed`, with those steps named in `detail`; when a firmware syft pass is among them and the amd64 image ran under emulation on an ARM host, `detail` also says so, and on an arm64 host names the `linux/arm64` image to use instead. The label of a post-process step (a step of its own in this table) is never counted here, even from an SBOM an earlier run left |
| `os-licenses` | an image or root filesystem scan: the licenses of Debian packages from Trivy, which reads the license names, common-licenses references and license text in the copyright files syft leaves as a hash; `counts` gives `replaced` and `hashes_dropped`, `degraded` (`unavailable`) when Trivy could not read the target or gave no Debian package a license, `skipped` (`not_installed`) without Trivy, `disabled` with `BOMLENS_OS_LICENSES=false` |
| `vendored` | identify open source copied into the sources (`--identify-vendored`) |
| `suggest-vendored` | suggest that identification when a C/C++ project scanned near-empty |
| `cocoapods` | add CocoaPods dependencies from `Podfile.lock` |
| `stamp-metadata` | set the root component to the project name and version; the run stops if this fails |
| `docmeta` | record the document's author, tool and lifecycle phase |
| `license-registry` | ask the package registry for missing licences and check a single strong-copyleft or non-commercial one (`--license-registry`); `counts` gives `candidates`, `filled`, `superseded`, `confirmed`, `no_answer`, `not_found`, `non_standard`, `lookup_failed`, `budget_reached` |
| `component-versions` | a firmware, root filesystem or binary scan: fill the versions given with `--component-versions`, record the reasons given as `bomlens:versionReason`, and write the components still missing a version and a reason to `_component-versions.template.csv`; `failed` when the file is refused, with the reason in `detail`, and the run then exits 1 |
| `normalize` | normalize licences, PURLs and duplicates |
| `enrich-cpe` | add CPE identifiers |
| `upstream-purl` | a firmware, root filesystem or binary scan: set the upstream source repository purl from the mapping table; `disabled` with `ENRICH_UPSTREAM_PURL=false` |
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
| `match-cpe` | a firmware, root filesystem or binary scan with `--security`: match the CPEs of components that have no package PURL against the NVD CPE index bundled in the image; `counts` gives `offered`, `components` and `cves`, `skipped` (`not_installed`) in an image without the index, `disabled` without `--security` or with `CVE_BIN_TOOL_MODE=components-only` |
| `reachability` | a Go source or Go executable scan: judge with govulncheck whether the code each Go advisory names is reached (`--reachability`, `REACHABILITY=true`); `counts` gives `exploitable`, `not_affected` and `components`; `skipped` (`unavailable`) when the Go vulnerability database could not be read, (`no_input`) when the SBOM has no Go component or stage 1 left no govulncheck output for this run, (`too_large`) when the source tree has more than 20 Go modules, `degraded` (`unavailable`) when a Go module builds for none of GOOS linux, darwin and windows and is not judged, (`not_installed`) in an image without govulncheck; `disabled` without the option |
| `scan-security` | match vulnerabilities with Trivy |
| `deep-cve` | with `--security`: match the components that carry a CPE, and the extra CPEs in `bomlens:cpeAlternates`, against NVD with grype (`--deep-cve`, the deep-cve image); `skipped` (`not_installed`) when asked for in an image without grype, `skipped` (`fallback`) when the CLI ran it without the deep-cve image, because that image could not be pulled or the scanner image is a local build, a version before 1.13.2 or not a BomLens image name (`detail` says which; a kept image that has grype, built with `SBOM_DEEP_CVE=true`, runs the match and records its real outcome), `disabled` when not asked for, without `--security`, and in a firmware or AI model scan |
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
| `vulnerabilities.trivy` | Trivy's own result. This is `_security.json` when nothing changed it, and `_security_trivy.json` (Trivy's result kept apart) when another engine added results or a finding was put under another id or moved to `Advisories` (see [the security report](../guides/reports.md)) |
| `vulnerabilities.all` | `_security.json`, Trivy's result with the other engines' results merged in, and findings filed under a distribution advisory number reported under their CVE or in the top-level `Advisories` list |
| `vulnerabilities.other` | another engine's result (`_security_grype.json`, `_security_cvebintool.json`, `_security_yocto.json`) |
| `license-scan.scancode` | `_scancode.json` |
| `vendored.cyclonedx` | `_vendored.cdx.json` |
| `vex.reachability` | `_reachability.cdx.json` (`--reachability`) |
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

## Image scans

In `IMAGE` mode syft reads the image first, and Trivy reads it again for the licenses of Debian packages (`os-licenses`), as does the file view. Those later reads take the image by the digest syft read, `<repository>@sha256:...`, so a tag that moves between the two reads cannot give them a different image. `input.image` records it:

```json
"image": {
  "reference": "alpine:3.20",
  "source": "registry",
  "digest": "sha256:45e09956dc667c5eff3583c9d94830261fb1ca0be10a0a7db36266edf5de9e1d",
  "platform": "linux/arm64/v8",
  "index_digest": "sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc"
}
```

| Field | Meaning |
|---|---|
| `reference` | the image reference as given (`TARGET_IMAGE`) |
| `source` | where syft read it: `registry` (the `registry:` scheme, or a plain name with no Docker socket), `daemon` (`docker:` and `podman:`), `archive` (`docker-archive:`, `oci-archive:`, `oci-dir:`), `other` (`containerd:`), or `null` when the run stopped before syft read the image. With the socket, syft reads a plain name from the daemon and falls back to the registry when the daemon cannot give it the image, and its record does not name which it used. It is then told from the record: a Docker Hub repository digest written in full (`index.docker.io/...`) means `registry`, a listed tag means `daemon`, and anything else is `unknown` |
| `digest` | for `registry`, the manifest digest of the image read, one platform; for `daemon` and `unknown`, the repository digest recorded for that repository, which for a multi-platform image is the digest of its index and names the same content in the daemon and in the registry. `null` for an archive, which is read as it is, and when no digest could be resolved: a repository with no repository digest (an image built locally and never pushed), a name that is not a plain image name, or a syft source record that could not be written. The later reads then use the reference as given, and the log says so |
| `platform` | `os/architecture[/variant]` of the image read, or `null`. The variant is syft's `architectureVariant`, or else the `variant` in the image config (Docker writes `v8` for arm64 images) |
| `index_digest` | `registry` only, present when the reference named an image index (manifest list) whose digest differs from `digest` |

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
| `input_fingerprint` | what stage 1 reads, as sha256 values (see [Input fingerprint](#input-fingerprint)); the same value as in the `generate` stage, and here also when there are no stages |
| `stages[]` | `generate` (stage 1) and `postprocess` (stage 2), in order |

Each stage gives `image` and `image_digest` (stage 1 is always pinned by digest; stage 2 repeats `BOMLENS_IMAGE_REF` and `BOMLENS_IMAGE_DIGEST`), `user`, `entrypoint`, `args`, `workdir`, `env` (names and values to set), `env_passthrough` (names to pass from your own environment when set), `network` (whether it needs to reach the package registries) and `mounts`. A mount has a `role` (`source`, `output`, `plan-file` with a `source` path inside the output folder, the optional `guard-state`, an optional cache (`cache-maven`, `cache-gradle`), an optional settings file (`maven-settings`, `maven-settings-security`, `gradle-properties`, `gradle-init-script`, `gradle-init-script-kts`, `gradle-init`), or the optional `trivy-db`), a `target` and a `mode`. Mount a Trivy cache folder that holds a database (`db/trivy.db`) as `trivy-db`, read-only: with `GENERATE_SECURITY=true` (stage 2's report options are yours to set, as in the image reference), stage 2 then reads that database as it is, with no download, no update and no write, so it runs with no network and a read-only root. A `trivy-db` mount with no database fails `scan-security` with that reason; a database older than `BOMLENS_TRIVY_DB_MAX_AGE_DAYS` days (7, counted from `UpdatedAt` in `db/metadata.json`, when the database was built) records it as `degraded` (`unavailable`). Pass a value that fits how often you refresh the database. The source is writable in stage 1 only: the resolvers write lock files there, and stage 1 puts the tree back as it was when it finishes. A stage 1 that is killed (out of memory, a timeout) cannot; mount a folder of your own as `guard-state` and set `BOMLENS_GUARD_ID` to a unique id per scan, and after a kill run the same stage 1 again with `BOMLENS_GUARD_RESTORE_ONLY=1` to restore the source. Pass `HOST_UID` and `HOST_GID` to both stages so the files they write belong to your user rather than root. Stage 2 also runs as any user (`user` is `null`, so you choose) with a read-only root filesystem, given a writable `$TMPDIR` (default `/tmp`, a tmpfs) and an output folder that user can write; a home it cannot write is replaced with a folder in `$TMPDIR`, unless something is mounted under it. Without a `trivy-db` mount Trivy downloads its database there, several hundred MB, which a memory-backed tmpfs counts as memory: mount `trivy-db`. Stage 1 runs as root: the resolvers install packages and write into the source. Stage 1's `env` also keeps the Go caches under `/tmp/sbomhome` (`GOPATH=/tmp/sbomhome/go`, `GOMODCACHE=/tmp/sbomhome/go/pkg/mod`, `GOCACHE=/tmp/sbomhome/go-build`), so `go mod tidy` runs with a read-only root filesystem and a writable `/tmp`, where the image's default `/go/pkg` cannot be created. A Go toolchain that `go.mod` asks for is downloaded into `GOMODCACHE`, which counts against a memory-backed `/tmp`. There is no Go cache mount role; mount a folder of your own at `/tmp/sbomhome/go` if you want the module cache kept between scans. `cache-maven` is a `.m2`-shaped folder (the Maven repository in `repository/`, and a `settings.xml` there is read when no `maven-settings` is mounted), and `cache-gradle` is a Gradle user home. Mount folders of the engine's own there, not a user's `~/.m2` or `~/.gradle`: root-owned files there would break that user's own builds, and with `HOST_UID` and `HOST_GID` stage 1 hands what it wrote in these two mounts back to that user. Mount the user's settings files read-only under their own roles, which sit outside the cache folders, so no mount point is created inside them: Maven reads `maven-settings` and `maven-settings-security` in place of the cache's own, and the Gradle ones are copied into the Gradle user home before the first Gradle run and removed afterwards (a file the home already has is not replaced, and a copy that changed during the scan is kept). Scans that share one `cache-gradle` at the same time share the copies, and the last of them to end removes them; a scan that was killed leaves its copies for a day. Use the Gradle settings roles together with `cache-gradle`. The CLI mounts `${XDG_CACHE_HOME:-~/.cache}/bomlens/m2` and `.../bomlens/gradle` (`%LOCALAPPDATA%\bomlens\cache` on Windows) as the caches, and `~/.m2/settings.xml`, `~/.m2/settings-security.xml`, `~/.gradle/gradle.properties`, `~/.gradle/init.gradle`, `~/.gradle/init.gradle.kts` and `~/.gradle/init.d` read-only when they exist. It also runs with a read-only root filesystem given a writable `/tmp`, where `HOME` points (Gradle's files go there when the account's `~/.gradle` cannot be written).

Stage 2's image is the one you name in `BOMLENS_IMAGE_REF`, whatever options you give stage 2. `DEEP_CVE=true` needs grype and `DEEP_LICENSE=true` needs scancode, which only the `bomlens-deep-cve` and `bomlens-deep-license` images have, so run stage 2 on that image and name it in `BOMLENS_IMAGE_REF`. Neither image has both tools: to have both, first remove an earlier `<prefix>_scancode.json` from the output folder, then run `/usr/local/lib/sbom/deep-license.sh /src /host-output/<prefix>_scancode.json` in the deep-license image (entrypoint `bash`, the same mounts, `HOST_UID` and `HOST_GID` so the file is yours), then stage 2 on the deep-cve image with `DEEP_LICENSE=true` and that script's exit code as `BOMLENS_DEEP_LICENSE_RC`, and optionally when it started and ended as `BOMLENS_DEEP_LICENSE_STARTED` and `BOMLENS_DEEP_LICENSE_ENDED` (`YYYY-MM-DDTHH:MM:SSZ`). When the output folder is inside the source tree, set `DEEP_LICENSE_EXCLUDE` to its folder name (folder names separated by spaces, left out at any depth) so the licence scan does not read the results. The script removes its output file when it does not finish (any exit code other than 0 or 6), and stage 2 keeps the file only for 0 and 6, removing it otherwise, and records the `deep-license` step from the code. The CLI does this with both options. On an image without the tool, the result manifest records the step (`deep-cve` or `deep-license`) as `skipped` (`not_installed`) and the run as `succeeded_degraded`. `SECURITY_NVD_VERIFY=true` with `DEEP_CVE=true` reads `NVD_API_KEY` in stage 2, which the plan lists in `env_passthrough` by name only.

Set `CDXGEN_IMAGE_PREFIX` for `MODE=PLAN` to name the stage 1 image from a registry mirror (for example `registry.example/mirror/cdxgen/`, in place of `ghcr.io/cdxgen/`); the digest stays the published one, so the mirror must hold the same image with the same digest: a pull-through cache, or a copy of every platform (`skopeo copy --all`, `crane copy`). A mirror filled with `docker pull`, `docker tag` and `docker push` holds one platform under another digest, and pulling the plan's `image@image_digest` from it fails with "manifest unknown".

Set `CYCLONEDX_SPEC_VERSION` (`1.6`, the default, or `1.7`; the CLI's `--spec-version`) for `MODE=PLAN` to plan a CycloneDX 1.7 SBOM. The plan gives it to stage 1 as the last argument of `build-prep.sh` and to stage 2 as `CYCLONEDX_SPEC_VERSION` in its `env`, so the stage 2 fallback (syft) writes the same version and stage 2 raises an SBOM written at 1.4, 1.5 or 1.6 to 1.7 (1.3 and older keep their version). It is part of the input fingerprint (`CDX_SPEC_VERSION`). Any other value stops `MODE=PLAN` with a non-zero exit.

`MODE=PLAN` exits 0 when it wrote a plan, `ok` or `unsupported`; an `unsupported` plan records the `plan` step as `skipped` in the result manifest, so the run reads `succeeded_degraded`. It refuses an empty source (usually a mount that did not reach the container) with a non-zero exit. Before writing, it removes an earlier plan and an earlier run's stage 1 outputs from the output folder, since stage 2 cannot tell a fresh SBOM from a leftover one. Stage 1 images are pinned for the cdxgen tag this BomLens release was tested with; overriding `CDXGEN_TAG` makes the language images `unsupported` (`no-pinned-digest`).

A plan's stage 1 does not run govulncheck, so Go source reachability is not judged on this path: with `REACHABILITY=true`, stage 2 records the `reachability` step as `skipped` (`no_input`).

Run stage 2 whatever stage 1's exit code, and pass that code as `BOMLENS_STAGE1_EXIT`, `true` in `BOMLENS_STAGE1_OOM` when the stage 1 container was killed for memory, and the stage 1 log saved in the output folder as `BOMLENS_STAGE1_LOG` (a file name). When stage 1 failed or left no SBOM, stage 2 scans the source with syft instead (direct dependencies only), records the reason in `bomlens:sbom-tool-degraded` (`oom`, `disk-space`, `network`, `cdxgen-crash`, `cdxgen-unavailable`), and the result manifest records `generate` as `degraded` (`fallback`), the same as the CLI. For an `unsupported` plan, where no stage 1 ran, pass `BOMLENS_STAGE1_EXIT=127` (or `BOMLENS_STAGE1_REASON=cdxgen-unavailable`) with no SBOM: the reason is then `cdxgen-unavailable`.

## Input fingerprint

The plan's `generate` stage has `input_fingerprint`: a sha256 over the whole source tree and what stage 1 runs with. When it is the same as the `sha256` of an earlier scan whose stage 1 exited 0, you may skip stage 1 and give stage 2 that scan's stage 1 outputs instead: the SBOM (`output_file`, and `_conda.cdx.json` when there was one) in the output folder, its exit code as `BOMLENS_STAGE1_EXIT` and its log as `BOMLENS_STAGE1_LOG`, with `BOMLENS_STAGE1_REUSED=1`. Reuse only a stage 1 that exited 0; a failed one is run again. Stage 2 always runs: the licence scan of the source files, the registry lookups, the version age and the vulnerabilities depend on the files and on the day, not only on stage 1, so `--deep-license` can stay on.

The fingerprint errs on the side of not reusable: when a check cannot tell whether stage 1 would give the same result, `reusable` is `false`.

```json
{"algorithm": "bomlens-input-1", "sha256": "9e61...", "reusable": true, "reasons": [],
 "components": [{"kind": "file", "name": ".", "sha256": "a729...", "count": 1840}, ...]}
```

| Field | Meaning |
|---|---|
| `algorithm` | `bomlens-input-1`. Compare it along with `sha256`: two values from different algorithms never match |
| `sha256` | the fingerprint, or `null` when `reusable` is `false` |
| `reusable` | whether stage 1's result for this input can be reused at all |
| `reasons` | why not, when `reusable` is `false` (below); one entry per reason |
| `components` | each input, as `kind` (`file`, `engine`, `image`, `setting`), `name` and `sha256`. A value is only ever given as its sha256 |

The components, sorted by kind and name:

- `file`: the source tree as one component, named `.`. Stage 1 runs cdxgen over the whole tree with no type filter, and cdxgen reads many kinds of file (its own `.cdxgenrc`, archives, installed package metadata, build files of many tools), so every file counts except any folder or file named `.git` (a worktree's `.git` file names an absolute path). Nothing else is skipped: `node_modules`, `vendor`, virtual environments, hidden folders and the non-shipped folders are hashed too. Its `sha256` is taken over one line per file, `<path><TAB><mode><TAB><sha256 of the content>`, with paths relative to the source and sorted byte by byte (`LC_ALL=C`). `<mode>` is `755` when the file can be executed and `644` otherwise (build-prep runs `./gradlew` only when it can), with an `l` in front for a link, so a link and a copy differ. `count` is the number of files. A change to any file, a README or a source file as much as a lock file, changes the value; a change to `.git` does not. A link is followed to a regular file inside the source. A path that cannot be hashed (an unreadable file or folder, a link that is broken or leads outside the source, a folder link, a FIFO, socket or device, a name with a tab or line break) is also listed as its own `file` component with `sha256` `null`, and the tree's `sha256` is then `null`. A tree with an installed pnpm `node_modules` (made of folder links) or a virtual environment (whose links lead outside the source) is therefore not reusable. The walk stops after `BOMLENS_FINGERPRINT_MAX_FILES` entries, files and folders counted together (200000), or after `BOMLENS_FINGERPRINT_TIMEOUT` seconds (300); the component then has `truncated: true` and `sha256` `null`. The whole computation, the checks below included, is stopped 30 seconds after that limit, and the fingerprint is then the not-reusable value with `unhashable-input` and no components. The checks read at most 4 MiB of a file; a manifest, lock file or Go source over that cannot be judged and makes the value `unhashable-input` (it is still hashed in full). In the result manifest of a CLI source scan, the run's own output folder is left out of the walk when it is inside the source (the default), since it holds this run's results, but the value is then not reusable (`unhashable-input`, with the folder listed with `sha256` `null`): stage 1 ran before the folder was cleaned and may have read an earlier run's files there. Put the output folder outside the source (`--output-dir`) to get a reusable value on the CLI path.
- `engine`: the files stage 1 runs from BomLens, as the sha256 of their content: `build-prep.sh` and `identify-conda.py`, and the file that sets stage 1's arguments and environment, `make-plan.sh` in a plan. In the result manifest of a CLI source scan that file is `scan-sbom.sh` instead, and `build-prep.sh` and `identify-conda.py` are the CLI's own copies it mounted, so a CLI value is comparable only with other CLI values.
- `image`: `stage1`, the stage 1 image's digest, and `bomlens`, `BOMLENS_IMAGE_DIGEST` (`null` when it is not passed; the files it would cover are already `engine` components). A CLI scan records the digest the stage 1 image was pulled at; a locally built image has none.
- `setting`: `detected_ecosystem`, `PROJECT_NAME`, `PROJECT_VERSION`, `FETCH_LICENSE`, `HOST_GOTOOLCHAIN`, `CDX_SPEC_VERSION` (stage 1's `--spec-version`), and the build-prep options `BOMLENS_KEEP_BUILD_OUTPUT`, `BOMLENS_MAVEN_FULL_GRAPH`, `BOMLENS_ANDROID_FULL_GRAPH`, `BOMLENS_NODE_FULL_GRAPH`, `BOMLENS_PHP_FULL_GRAPH`, `BOMLENS_INCLUDE_NON_SHIPPED`, `BOMLENS_INCLUDE_DEV_DEPENDENCIES`, `BOMLENS_NO_COPYRIGHT`, `BOMLENS_NO_CARGO_LICENSE` and `BOMLENS_PREP_TIMEOUT`, as the sha256 of the value (of an empty value when unset). `FETCH_LICENSE` and `HOST_GOTOOLCHAIN` are the values in the stage 1 `env`. `MODE=PLAN` reads the build-prep options from its own environment, so give it the same values you give the stages; the plan's stage 2 `env_passthrough` lists them too.

Not components: absolute paths, the time, the scan id, the proxy settings (`HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY` and the lower-case forms), `GOPROXY`, `GOSUMDB`, `TRIVY_*`, `CDXGEN_IMAGE_PREFIX` (a mirror serves the same digest), `HOST_UID`/`HOST_GID`, and `SRC_TREE_EXCLUDE`, which only stage 2 reads. Stage 1's fixed arguments and environment are covered through the `engine` file that defines them.

Two things stay the caller's responsibility:

- What you mount into stage 1 besides the source is not covered: the `cache-maven` and `cache-gradle` mounts, and what they hold, such as a Maven `settings.xml` or a Gradle `init.d` script or `gradle.properties`, and the settings file mounts (`maven-settings`, `maven-settings-security`, `gradle-properties`, `gradle-init-script`, `gradle-init-script-kts`, `gradle-init`). Change those and the same fingerprint can stand for a different result.
- With `FETCH_LICENSE=true` cdxgen looks the licences up online. The fingerprint has the setting but still counts the result as reusable, on the assumption that the licence metadata of a published version rarely changes.

The checks below ask whether an identical tree would still give a different stage 1 result, because a resolver asks the registry again. Go, Maven and Gradle are resolved from the root over the whole tree, so they are judged everywhere (Go leaves out what the go tool does: `testdata`, `vendor` and names starting with `.` or `_`). For the other languages the folders a source scan skips (`node_modules`, `vendor`, `.venv`, `site-packages`, and the non-shipped folders unless `BOMLENS_INCLUDE_NON_SHIPPED=1`) are not judged, though they are hashed.

Decide on reuse from the result manifest, not only from the plan: store a stage 1 for reuse only when the `input_fingerprint` in its result manifest is `reusable`. Stage 2 adds `stage1-degraded` there when stage 1 came out short although it exited 0.

<!-- fingerprint-reasons:begin -->
| `reasons` | Meaning |
|---|---|
| `no-lockfile` | a manifest that declares a dependency has no lock file in its own folder: Node.js `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, `pnpm-lock.yaml`, `bun.lock` or `bun.lockb`; Python `poetry.lock`, `uv.lock` or `Pipfile.lock`; Rust `Cargo.lock`; Go `go.sum` (every `go.mod` with a `require` needs its own); Ruby `Gemfile.lock`; PHP `composer.lock`; Swift `Package.resolved` or `Podfile.lock`. A lock in a folder above covers only a declared workspace member: npm, yarn, pnpm or bun `workspaces` (or `pnpm-workspace.yaml`), and Cargo `[workspace] members`. Gradle: every build script (and every project `settings.gradle` includes, when the root declares dependencies in `subprojects {}` or `allprojects {}`) needs its own `gradle.lockfile` with at least one `group:artifact:version=` entry (one with only `empty=` lines locks nothing), and the file counts only when locking is on (`lockAllConfigurations()` or `activateDependencyLocking()`, comments aside): in the project's own build file, or for a subproject inside the root's `subprojects {}` or `allprojects {}` block. Locking at the top of the root build file locks the root project only. .NET: a project needs its own `packages.lock.json` or `obj/project.assets.json`, or a `paket.lock` above it, and a tree with .NET projects and none of these anywhere is `no-lockfile`. A `requirements*.txt` (or a `.txt` under `requirements/`) counts as locked only in pip's hash-checking mode: every requirement `name==version` with `--hash`, and no include (`-r`, `-c`), editable, URL, path or `${VARIABLE}` requirement. No other lock covers it, since stage 1 installs it with pip from the registry |
| `unpinned-versions` | Maven, in addition to `registry-resolution` (below): an element of the tree's own poms holds, as written, a version range, a `-SNAPSHOT`, `LATEST` or `RELEASE`. Properties are not expanded, so a version set through a property is not judged here; the tree is not reusable either way. .NET: a floating or range version (`*`, `[1.0,2.0)`, an MSBuild `$(property)`) in a project, `.props` or `.targets` file. Versions in the poms of the dependencies themselves are not visible and are not checked |
| `registry-resolution` | stage 1 resolves again from the registry although the tree has not changed. Maven: any `pom.xml`, since no lock covers the transitive graph and a range in a dependency's own pom cannot be seen. Node.js: a root `package.json` with no `package-lock.json` (a yarn, pnpm or bun project, or one with only `npm-shrinkwrap.json`) that is not a workspace root, unless `BOMLENS_NODE_FULL_GRAPH=1`, because the production filter has npm resolve it; and an npm lock that does not match its `package.json` (the dependency specs in the lock's entry for it, or with lockfile version 1 every dependency name, differ). Ruby: a `Gemfile.lock` whose `DEPENDENCIES` lacks a gem the `Gemfile` names. Swift: a `Package.resolved` that does not pin every remote package `Package.swift` names. Go: a `.go` file imports a module the `go.mod` does not require, so `go mod tidy` adds its newest version. An import counts as covered when a required module path is a prefix of it (a `/vN` major version after the prefix does not count); an import that a required path covers by prefix but that lives in a separate, unrequired module is not detected |
| `unsupported-ecosystem` | the language is not one stage 1 resolves reproducibly: `unknown`, a Conan or vcpkg manifest anywhere, a Modelica library (`package.mo`), or a Swift project with only an Xcode project |
| `plan-unsupported` | the plan's `status` is `unsupported` |
| `stage1-degraded` | in the result manifest only: the stage 1 SBOM records a failed step (`bomlens:pipeline-step-failed`) or a fallback (`bomlens:sbom-tool-degraded`), or `generate` is `degraded` or `failed` |
| `unhashable-input` | an input could not be hashed: a file or folder that cannot be read, a link that is broken or leads outside the source, a folder link (cdxgen may follow it), a FIFO, socket or device, a path with a tab or line break, a walk stopped at its file count or time limit, a CLI output folder inside the source (or a flat output into it), or a file a requirements file includes that is missing or outside the source |
| `unknown-stage1-image` | the result manifest does not know the stage 1 image's digest: the CLI's stage 1 image has no RepoDigest (a locally built one), or a stage 2 run with no plan was not told |
<!-- fingerprint-reasons:end -->

When the plan is `unsupported` there are no stages, and the fingerprint is only in the plan's top-level `input_fingerprint`, with `plan-unsupported`.

In a `POSTPROCESS` run the result manifest's `generate` step has the fingerprint stage 2 computes again from the source with its own code; a file in the output folder is never taken as it is.

- After an execution plan (`bomlens-plan.json` in the output folder, written for the same `output_file`), stage 2 takes stage 1's image digest, settings and `--spec-version` from the plan, or the digest from `BOMLENS_STAGE1_DIGEST` when you pass it, and hashes the `engine` files from the `bomlens-plan/` copies. The value then equals the plan's, and `plan_mismatch` is `false`. When it differs (the source changed after the plan, or the plan is a leftover from another scan), the step has the computed value and `plan_mismatch: true`. Stage 2 writes into the output folder, so keep it outside the source; one inside it changes the tree.
- After a CLI source scan, stage 2 uses what the CLI passes on: the stage 1 image's RepoDigest, the sha256 of the files it ran, and the output folder to leave out (`BOMLENS_FINGERPRINT_EXCLUDE`, a path relative to the source).

`reused` is `true` when you passed `BOMLENS_STAGE1_REUSED=1`. `reuse_unsafe` is `true` when you did so although the fingerprint is not `reusable`, is missing, or does not match the plan's: the SBOM may not be the one stage 1 would give now.

`algorithm` changes when the kinds or the list of components change, or when the same input would give a different `sha256`. A new reason does not change it. A fingerprint for image input is not part of this version.

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

- Major: a field, step id, output role or status value is removed, renamed, or changes meaning, or a change makes the same input produce a different package PURL (one with a package ecosystem type, such as `pkg:npm` or `pkg:deb`) or licence id, or reports a failure as success.
- Minor: a new optional field, step id, reason, output role or status detail, or a PURL added or replaced on a component that had no package PURL (none, `pkg:generic`, `pkg:opkg`), as firmware, root filesystem and binary scans do. A reader ignores values it does not know.
- Patch: no change a reader can see in the fields above.

Properties named `bomlens:*` in the SBOM, and the human-readable reports, are not part of the contract and can change in any release.
