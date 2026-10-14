# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [v1.13.3] - 2026-10-14

### Upgrade note

- Firmware, root filesystem and binary scans now give a component identified with no package PURL (none, `pkg:generic` or `pkg:opkg`) the upstream source repository PURL when it is in `docker/lib/upstream-purl-map.json`, for example `pkg:generic/openssl@1.0.2h` becomes `pkg:github/openssl/openssl@OpenSSL_1_0_2h`; the replaced one is kept in `bomlens:originalPurl`. A tool that joins these scans with an earlier BomLens SBOM by PURL sees these components as new once. Set `ENRICH_UPSTREAM_PURL=false` to keep the earlier PURLs. The engine contract counts this as a minor change: the version rules now name package PURLs.
- A step that failed while the SBOM was generated, and was until now recorded only in the SBOM's `bomlens:pipeline-step-failed` (a resolver step in build-prep such as `go-mod-tidy`, `cargo-lockfile` or `npm-production-set`, or a firmware syft pass), now makes `run.status` in `bomlens-result.json` read `succeeded_degraded` instead of `succeeded` (engine contract 1.3.0). This is common in offline scans, where the resolver steps cannot reach their registries; a caller that treats `succeeded_degraded` as a failure will see more of them.

### Added

- The execution plan's `generate` stage has `input_fingerprint`: a sha256 over the whole source tree (every file and its execute bit, except any `.git`), the files stage 1 runs from BomLens, the stage 1 and BomLens image digests and the stage 1 settings, with whether the result can be reused and why not (`no-lockfile`, `unpinned-versions`, `registry-resolution`, `unsupported-ecosystem`, `plan-unsupported`, `unhashable-input`, `unknown-stage1-image`, and `stage1-degraded` in the result manifest). A caller that kept an earlier stage 1's SBOM with the same value may skip stage 1; stage 2 always runs. The result manifest's `generate` step carries the value stage 2 computes again from the source, with `plan_mismatch` when it differs from the plan's, `reused` when the caller passes `BOMLENS_STAGE1_REUSED=1`, and `reuse_unsafe` when that reuse was not allowed. Engine contract `1.3.0`.
- `IMAGE` mode reads the image again by the digest syft read (`<repository>@sha256:...`) for Trivy's Debian package licenses and the file view, so a tag that moves during the scan cannot give them a different image. A registry read uses the platform manifest digest, a Docker daemon read the repository digest; an archive is read as it is, and when no digest can be resolved (an image built locally and never pushed) the reference is used as given, with a warning. When syft cannot write the record the digest comes from, the scan goes on without it. An image name starting with `-` is refused, by the CLI and in `IMAGE` mode, since the scan tools would read it as an option. The result manifest records the image read in `input.image`: `reference`, `source` (`registry`, `daemon`, `unknown`, `archive`, `other`), `digest` (`null` when not resolved), `platform` (`os/architecture[/variant]`) and, for a registry read through an image index, `index_digest`. Engine contract `1.3.0`.
- A directory `--target` that is not a source tree (no manifest, lockfile, build file or `.git` at its top level) and directly holds one root filesystem or one firmware image, such as a release `images/` folder, is scanned as that root filesystem (`ROOTFS`) or image (`FIRMWARE`), with a notice naming the path. A file counts as a firmware image by a firmware or filesystem signature, or by an extension used for firmware (`.bix`, `.trx`, `.chk`, `.dlf`, `.ubi`, `.ubifs`, `.squashfs`, `.sqsh`, `.rom`, `.fw`, `.jffs2`, `.cramfs`); `.bin` and `.img` count only with the signature. A folder with executables, shared libraries, `.asar`, `node_modules`, model weights or tokenizer files at its top level, or with more than 20 top-level files, such as an unpacked desktop app, a model snapshot or a build output staging folder, is scanned as source. Several such entries stop the scan with the `--target` to use for each. `--as-source` scans the folder as source as before. When the chosen root filesystem has no package database, the warning lists the files over 1 MiB beside it (at most five) as `--target "<file>" --firmware` commands.
- `.bix` firmware image files are recognized as firmware and routed to `FIRMWARE` without `--firmware`.
- Firmware, root filesystem and binary scans add the upstream source repository purl (`pkg:github/<owner>/<repo>@<tag>`, `pkg:sourceforge`, `pkg:gnu`) to components identified with no purl, a `pkg:generic` one or a `pkg:opkg` one, so tools that look components up by purl can identify them. The table, `docker/lib/upstream-purl-map.json`, covers BusyBox, curl, OpenSSL 1.x, OpenSSH, Linux, zlib, U-Boot, Net-SNMP, ncurses, net-tools, libxml2, SQLite, glibc, Dropbear, Mbed TLS, Python, Boa and readline, each with the release tag form of its repository (`busybox 1.22.1` becomes `pkg:github/mirror/busybox@1_22_1`; a Linux or glibc `5.4.0` takes the `5.4` tag). A name not in the table keeps its identifier. The version, CPE and evidence are kept; the new purl is marked `bomlens:purlSource=upstream-map` and a replaced one is kept in `bomlens:originalPurl`. `ENRICH_UPSTREAM_PURL=false` turns it off.
- `--component-versions <file>` takes a CSV file (`name,version`) with the versions of components a firmware, root filesystem or binary scan found without one. A version the scan read is kept and a warning shows both; a name the scan did not find is added as a supplier-declared component (`bomlens:identifiedBy=supplier-declared`), and a filled version is marked `bomlens:versionSource=supplier-declared`. These scans list the components still missing a version on the console, counting a placeholder `UNKNOWN` as missing, and write them to `<Project>_<Version>_component-versions.template.csv` in the same format; a name the format cannot hold is listed on the console only. Rows left empty are skipped. A refused file fails the `component-versions` step, and the scan writes its files without those versions and exits 1 with the reason.
- The `skt-submission` conformance profile adds two required rows, "version needed" and "no upstream purl", that list the components behind each failure, accepts `pkg:sourceforge` and `pkg:gnu` as purl types, and states in the summary (and `submitFile` in the JSON) that `<Project>_<Version>_bom.json` is the one file to submit. Under `--analyze` the two rows say to ask the supplier for a corrected SBOM.
- Root filesystem and binary scans with `--security` match the CPEs of components that have no package PURL (none, `pkg:generic`, or a source repository PURL such as `pkg:github`) against the NVD CPE index, as firmware scans do. A binary syft identifies by its version string, such as OpenSSL or BusyBox in an embedded root filesystem with no package database, now gets its CVEs. The index (`cpe_match.sqlite`, about 146 MB) is built into the base image and the images built from it, so the match works offline; `--build-arg SBOM_CPE_INDEX=false` leaves it out. The step is `match-cpe` in the result manifest, with `offered`, `components` and `cves` counts. Where cve-bin-tool is not installed, versions are compared with a letter release as later than its base version (`1.0.2 < 1.0.2h < 1.0.2i < 1.0.3`, `6.2 < 6.2p2`), a pre-release word (`rc`, `beta`, `alpha`, `pre`, `dev`) as earlier (`2.0.0rc1 < 2.0.0`), and trailing zero components as equal (`1.0` = `1.0.0`). A component with no version is matched with its CPE's version.
- The security report lists the components no check could reach, with the reason (`no-version`, or `no-identifier` for no package PURL and no matched CPE), under "Components that could not be checked", and `_security.json` keeps them as `UncheckedComponents`. A version in the component's CPE counts as its version, and the recipes of a Yocto build whose cve-check judgements were read (`_yocto_vex.json`) are not listed. The risk report's vulnerability section names them too, in English and Korean.
- `--spec-version 1.7` (or `CYCLONEDX_SPEC_VERSION=1.7`, or the web UI's CycloneDX version option) writes the SBOM as CycloneDX 1.7. An SBOM that reaches the last step at 1.4, 1.5 or 1.6 is labelled 1.7 there, `$schema` included, and a 1.4 or 1.5 property without a name (required from 1.6 on) is removed; 1.3 and older keep their version. The default stays 1.6, and AI model and dataset SBOMs are always 1.7. A Dependency-Track server older than 4.14.4 or 5.1.0 refuses a 1.7 SBOM with HTTP 400. When the server's `/api/version` names such a version, or none, the upload is sent once more as a 1.6 copy, in which a license list that mixes licenses and an expression is rewritten in a form 1.6 allows and the fields only 1.7 has are removed; the saved SBOM stays 1.7. If the copy is refused too, both responses are printed. NOTICE, the security report, the conformance check and the web UI read either version.
- A component without a supplier gets one from its own package metadata: the publisher (a Maven POM's organization, an npm publisher), its authors (PyPI, RubyGems, Composer) or the older author field, with email addresses and URLs removed wherever they appear (`Jane Doe jane@example.org` gives `Jane Doe`, `Bob <b@x.org>; Carol <c@y.org>` gives `Bob; Carol`); parentheses that hold anything else, as in `Example (Holdings), Inc.`, are kept. `bomlens:supplierSource` names the field used. Nothing is guessed. Distribution and firmware packages (`pkg:deb`, `pkg:rpm`, `pkg:apk`, `pkg:alpm`, `pkg:opkg`, `pkg:generic`) and operating-system components are not given one, and a supplier SBOM under `--analyze` and the output of `--merge` are left as written.
- `--reachability` (and the web UI's Go reachability option): for Go source and Go executables, govulncheck judges whether the code each Go advisory names is reached (the source's call graph, run in the Go image of stage 1 for each Go module in the tree, up to 20, and for GOOS linux, darwin and windows, or the executable's symbols). An advisory reached in any module or on any GOOS counts as reached. The modules are those the SBOM reads. A GOOS a module does not build for is left out and named in the VEX; a module that builds for none of the three is not judged and the step is `degraded`. Code built only under a custom build tag, or called only from tests, is not covered, and the VEX says so. Judgements are written to `{Project}_{Version}_reachability.cdx.json` as a CycloneDX VEX: `not_affected` with `code_not_present` or `code_not_reachable`, or `exploitable` with the call path. The security report and the web UI mark each finding (`bomlens:reachability` in `_security.json`), list the unreachable ones in their own section and leave them out of the totals, as the risk report and `--fail-on vulnerability=` do. The step is `reachability` in `bomlens-result.json`; without access to the Go vulnerability database it is skipped (`unavailable`). The scanner image now carries a pinned govulncheck.

### Changed

- Bundled tools are updated: Trivy 0.75.0, syft 1.54.1, grype 0.120.1 (deep-CVE image), cdxgen 13.3.0 (language images, digests and the AI SBOM image) and docker CLI 29.9.0.
- Components named net-snmp, ncurses, readline, dhcpcd or quagga (and their `lib` names) get a CPE from `docker/lib/cpe-name-map.json`, so a firmware, root filesystem or binary scan matches their CVEs once they have a version.

### Fixed

- With only `SBOM_SCANNER_IMAGE` set to a BomLens image under a registry path, `--deep-license` now runs on `bomlens-deep-license` with the same registry path and tag instead of the scanner image, which has no scancode. The firmware, AI SBOM and deep-cve images follow it the same way, in the CLI, the desktop app and the web UI started with `docker run -e MODE=UI`. A short local name such as `sbom-scanner:local` and a version tag before 1.13.2 keep the earlier defaults. A digest-only reference gives the opt-in images `:latest` (the app's own version in the desktop app), and each `SBOM_*_IMAGE` still takes precedence; the desktop app treats an empty one as unset. The desktop app now pins the deep-cve image to its own version too.
- The result manifest now records `generate` as `degraded` (reason `failed`, the failed steps named in `detail`) when a step inside generation failed and was recorded only in the SBOM's `bomlens:pipeline-step-failed`, such as a firmware syft pass or a resolver step in build-prep, so the run reads `succeeded_degraded` instead of `succeeded`; in a `POSTPROCESS` run the same stage 1 also gets `stage1-degraded` in `input_fingerprint.reasons`. The label of a post-process step is not counted, also when it comes from an SBOM an earlier run left (a reused stage 1), and `ANALYZE` and `MERGE` do not read the labels of the SBOMs they are given. When a firmware syft pass failed and the amd64 image ran under emulation on an ARM host, `detail` says so, and on an arm64 host names the `linux/arm64` image to use.
- A firmware scan tries a failed syft pass once more, except one that ran out of its time limit (exit 124) or was killed, as for running out of memory (exit 137). When the amd64 image runs under emulation on an ARM host, syft runs with `GOGC=off`, `GOMEMLIMIT` at 75% of the container's memory limit (or of the machine's memory when there is none) and a 30-minute limit when `timeout` is installed; once a pass has failed there, the remaining passes (the extra roots) run once each. A pass that still fails says so, and on an arm64 host gives the `linux/arm64` image of the same version as an example to use instead.
- A firmware scan matched CPEs against the NVD index before the CPEs from `cpe-name-map.json` were added, so components identified by name and version, such as OpenSSH and BusyBox, were reported with no vulnerabilities. The match now runs over the final SBOM after every CPE enrichment step, once.
- The security report said "No known vulnerabilities found." when some components could not be checked at all (no version, or no package PURL and no matched CPE). It now says how many could not be checked and lists them.
- A Debian package whose copyright file names several licenses, for example `BSD-2-Clause` and `GPL-2.0-only`, could be judged compatible with a permissive product license (`bomlens:licenseConflict`, the risk report's conflict section and `--fail-on license-conflict`): the licenses were read as a choice, so the most permissive one decided. They usually belong to different files and all apply, so the least compatible one now decides, and a license with no rule makes the package `unknown`. The SBOM still lists each license as its own entry. A choice the copyright file states (`GPL-2+ or Artistic`) is also read as licenses that all apply, since Trivy lists it the same way. Several licenses on a Maven package are still read as a choice. Debian's `MIT-X11` license (on ncurses) is now classed as permissive.
- A source scan with `--deep-cve` ran its post-processing stage on the base image, which has no grype, so the grype CPE match did not run and no `_security_grype.json` was written. That stage now runs on the deep-cve image, with `NVD_API_KEY` passed by name (also when the scanner image is the deep-cve image itself; the execution plan lists `NVD_API_KEY` in stage 2's `env_passthrough`). When the image cannot be pulled (offline, `SBOM_PULL=never`), the scan goes on without the match, says so, and the result manifest records the new `deep-cve` step as `skipped` (`fallback`); an image without grype records it as `skipped` (`not_installed`). When `SBOM_SCANNER_IMAGE` is a local build (`bomlens:dev`), a version before 1.13.2 or not a BomLens image name and `SBOM_DEEP_CVE_IMAGE` is not set, post-processing stays on that image instead of mixing in `bomlens-deep-cve:latest`, with a one-line note; the step is `skipped` (`fallback`), or runs as usual when that image has grype (built with `SBOM_DEEP_CVE=true`; read from the new `com.sktelecom.sbom.deep-cve-tools` image label, or from a short container start for an image without it), also with `--deep-license`. With `--deep-license` as well, the licence scan runs first in the deep-license image and post-processing then runs on the deep-cve image, so both `_scancode.json` and `_security_grype.json` are written; the web UI does the same when it runs from the deep-license image. That licence scan stops on Ctrl+C (CLI) or a cancelled scan (web UI), and a `_scancode.json` from an earlier run is removed when it does not finish. A first pull of an opt-in image shows docker's progress with no time limit and happens once with `SBOM_PULL=always`, which uses the copy already here when the pull fails. The `deep-cve` step is `disabled` without `--security` and in a firmware or AI model scan, and the CLI no longer hands those scans `DEEP_CVE=true`, which made them `succeeded_degraded`.
- Ctrl+C (or `kill`) during a CLI scan stopped the running container but then went on to the next stage, so a cancelled source scan still post-processed. The CLI now stops the container before it removes the temporary folders, and exits with 130 (143 for `kill`). A `kill` sent to the script during a stage that runs in the foreground takes effect when that container ends.
- A binary that syft identifies by its signature, such as `openssl` in a firmware or root filesystem scan, was listed twice: once as the identified component and once as a `file` component for the same path, with no PURL and no version. The file entry is now dropped, its hashes are moved to the identified component when it has none, and references to it are removed from `dependencies`.
- A source scan no longer lists the Gradle wrapper jar (`gradle/wrapper/gradle-wrapper.jar`) as a component. The `gradle/wrapper` folder joins `.github/workflows` in the paths left out by default and recorded in `bomlens:excluded-paths`; `BOMLENS_INCLUDE_NON_SHIPPED=1` keeps it.
- Development-only components that cdxgen marks (npm, pnpm, yarn and bun development packages, uv and Poetry dependency groups, Cargo dev-dependencies, sbt, Crystal and Gleam development dependencies) are dropped, together with the dependencies only they reach, when nothing else in the dependency graph reaches them. A marker with several values counts only when every value is a development one, so a crate in both `[dependencies]` and `[dev-dependencies]` stays. A Python package that a `pyproject.toml` names in `[project]` `dependencies` or `optional-dependencies`, or in `[tool.poetry.dependencies]`, stays even when a dependency group lists it too, and no Python package is dropped when those files cannot be read, or when a `requirements*.txt`, `setup.py`, `setup.cfg` or `Pipfile` outside `vendor` and the non-shipped folders may declare production dependencies elsewhere (the log names the file), or the project has folders deeper than the 8 levels searched. A workspace member keeps what it depends on, so the dev-dependencies of a Cargo member crate and the dependency groups of a uv member stay; npm development packages are dropped even when a member lists them, since cdxgen 13.3.0 sets that marker over the whole workspace. A component the root does not reach keeps what it depends on. The dropped components are recorded in `bomlens:excluded-components`. `BOMLENS_INCLUDE_DEV_DEPENDENCIES=1` keeps them all, and `BOMLENS_NODE_FULL_GRAPH=1` keeps the npm ones.
- A source scan no longer lists gems a Gemfile declares only in its `development` and `test` groups (a `group ... do` block or a `group:`/`groups:` option), along with what only those gems need, unless a production gem also needs them. The Gemfile is read conservatively: a condition, `gemspec`, `eval_gemfile`, a declaration over several lines, or a Gemfile.lock that names a gem the Gemfile does not leaves every gem in place, and so does another Gemfile or Gemfile.lock below the scan root or a `.gemspec` file in the project (searched 8 folders deep, skipping `vendor`, `node_modules`, `.git`, `.venv` and `venv`; a deeper folder also leaves every gem in place). The dropped gems are recorded in `bomlens:excluded-components`, and `BOMLENS_INCLUDE_DEV_DEPENDENCIES=1` keeps them.
- When the Maven non-deployed-module filter dropped components, `bomlens:excluded-components` kept only its own entries and lost what an earlier filter had recorded there. It now keeps both.
- A source scan of a tree with no dependencies wrote a root component without a type, which fails CycloneDX schema validation. It is now `application`.
- An SBOM whose `metadata.tools` is the older flat array (CycloneDX 1.4 and before) got BomLens added to it with component fields (`type`, `publisher`), which fails schema validation. It is now added as a tool, with `vendor`, `name` and `version`.
- A CycloneDX 1.4 SBOM post-processed at the default version stayed 1.4 but got `metadata.lifecycles` and, without a tools list, a `metadata.tools` object, both of which 1.4 does not define. It now keeps its version and gets neither the lifecycle nor the object form: BomLens goes into the flat tools array.
- A binary scan no longer writes syft's own messages into the SBOM, which broke the scan when syft could not reach the network for its update check.

## [v1.13.2] - 2026-10-12

### Upgrade note

- Operating system package PURLs change form to the one Trivy and the purl-spec use: a deb epoch moves from the version into an `epoch` qualifier (`bsdutils@1:2.38.1-5` becomes `bsdutils@2.38.1-5?...&epoch=1`), the `upstream` qualifier is no longer written for deb, rpm and apk (the source package stays in `aquasecurity:trivy:SrcName`), an apk `distro=alpine-3.20.10` becomes `distro=3.20.10`, and qualifiers are sorted. Trivy finds the same vulnerabilities (checked on Debian and Alpine packages). A tool that joins this scan's components with an earlier BomLens SBOM by PURL sees these packages as new once; `--merge` treats both forms as the same package. grype, which some users run on BomLens SBOMs, needs `distro=alpine-<release>` to match Alpine advisories and falls back to CPE matching on the new form.
- `--deep-cve` no longer adds grype's matches on deb, rpm and apk packages. Those packages are matched by Trivy against the distribution's own advisories; a CPE match on them reported CVEs the distribution had already patched.
- `_scancode.json` paths are now relative to the scanned tree (`src/app.js` becomes `app.js`), the same as `_files.json`; the source file viewer reads them either way.
- `--deep-license` now scans only the project's own files: dependency folders (`node_modules`, `vendor`, virtual environments), build output and tool folders are left out of `_scancode.json`, and a tree with more than 20,000 such files is not scanned. Set `BOMLENS_DEEP_LICENSE_ALL=1` to scan everything, or raise `DEEP_LICENSE_MAX_FILES`.
- A source scan now also leaves out manifests under `sample`, `bench`, `benchmark`, `demo` and `demos` folders. A project with dependencies declared only there shows fewer components than before; set `BOMLENS_INCLUDE_NON_SHIPPED=1` to keep them.

### Added

- The scan containers now get the proxy settings (`HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY`), Trivy's settings (`TRIVY_*`, for example a database mirror in `TRIVY_DB_REPOSITORY`) and the EPSS and KEV endpoints (`EPSS_API`, `KEV_URL`) by name, and the execution plan lists them. `SBOM_TRIVY_CACHE` keeps Trivy's database in a host folder, so it is downloaded once rather than on every scan. The engine contract has a section on what a scan reaches over the network and how to turn each off or point it at a mirror.
- A Trivy database mounted read-only at `/trivy-db` (the execution plan's new `trivy-db` mount) is read as it is, with no download or update, so the post-processing stage runs with no network and a read-only root. A mount with no database fails the security step with that reason, and a database older than `BOMLENS_TRIVY_DB_MAX_AGE_DAYS` (7) days degrades it. The plan's stage 2 now turns the EPSS and KEV lookups off.
- `CDXGEN_IMAGE_PREFIX` names where the cdxgen images come from (default `ghcr.io/cdxgen/`), for a network that reaches a registry mirror but not ghcr.io. The CLI, the web UI's source scans (from `--ui`, `sbom-ui.bat` and the desktop app), the Android SDK image's build and the execution plan use it. The plan keeps the published digest, so the mirror must be a pull-through cache or a copy of every platform.
- `IMAGE` mode no longer needs the Docker socket: without it, syft reads the image straight from the registry (as in a Kubernetes job), or from an archive named with its scheme (`docker-archive:`, `oci-archive:`, `oci-dir:`), which the CLI mounts into the container. A private registry takes `SYFT_REGISTRY_AUTH_*` or a docker config file (`DOCKER_CONFIG`); the CLI passes those variables on by name. When the image cannot be read, the error now shows syft's own message.
- `BOMLENS_EVENTS=file` (or `stderr`) writes progress events as the run goes, one JSON object per line (`bomlens-events.jsonl`, `schemas/engine-event-1.json`): `run.start`, `step.start`, `step.end` with the step's status and reason, and `run.end` with the run's status. A numbered `seq` lets a reader tell a lost line; the result manifest stays the final record.
- Every scan writes `bomlens-result.json` to its output folder: how the run ended, each step's outcome (`ok`, `degraded`, `failed`, `skipped` with a reason such as `not_installed`, or `disabled` by a setting) with its time span, the tool versions, the Trivy database date, and the role, sha256 and size of each output file. It is written also when a run stops early. A step that was asked for but could not run (its tool not installed, its input over a limit, its image unavailable) makes the run `succeeded_degraded`, so a scan that skipped a requested detection never reads as a plain success. A failed Trivy scan is reported as a failed `scan-security` step, so a run whose vulnerability scan did not run is never reported as a plain success. The format, `schemas/engine-result-1.json`, is documented as the engine contract, version `1.2.0`, and checked by a new test. The scan's exit code is unchanged.
- `MODE=PLAN` writes the execution plan of a source scan (`bomlens-plan.json`, `schemas/engine-plan-1.json`): the stage 1 cdxgen image pinned by digest (`docker/lib/cdxgen-images.json`, refreshed with `scripts/update-cdxgen-digests.sh`), its arguments, mounts and environment, and stage 2. A program that runs the containers itself (a Kubernetes Job, a hardened Docker runner) runs what the plan says. When it passes stage 1's exit code (`BOMLENS_STAGE1_EXIT`), stage 2 runs the manifest-only fallback itself when stage 1 left no SBOM, as the CLI does.
- When another engine adds results to the security report, Trivy's own result is kept as `_security_trivy.json`.
- A new opt-in image, `ghcr.io/sktelecom/bomlens-deep-license`, carries scancode for `--deep-license`, for linux/amd64 and linux/arm64. A CLI source scan with `--deep-license` runs its post-process step on it and pulls it automatically (`SBOM_DEEP_LICENSE_IMAGE` overrides it; an `SBOM_SCANNER_IMAGE` you set is still used, as before). When it cannot be pulled (an offline host, `SBOM_PULL=never`), the scan runs on the base image without the licence scan, and the result manifest records the step as `skipped` (`fallback`) with the run `succeeded_degraded`. The image carries LGPL components (7-Zip on linux/amd64, intbitset, chardet 6.x); the source for 7-Zip and intbitset is in the image under `/usr/share/bomlens/sources/`, checked against pinned sha256 values at build time. `THIRD_PARTY_LICENSES.md` lists its contents.
- `--deep-license` is bounded: scancode is stopped after `DEEP_LICENSE_TIMEOUT` seconds (default 600), and each run writes to its own temporary file instead of a fixed `/tmp/scancode.json`. The result manifest records the step as `skipped` (`not_installed`, `no_input`, `too_large`) or `failed` (`timeout`).
- `--license-registry` (`LICENSE_REGISTRY=true` on the image) asks the package registry, through deps.dev, for the licence of a component that has none, and checks a component whose only licence is strong copyleft or non-commercial (GPL, AGPL, SSPL, BUSL, CC-BY-NC; `LICENSE_REGISTRY_VERIFY` changes the list). A generator that read one licence file can record a single GPL for a package the registry lists otherwise, and that reading is what blocks a release. When the registry disagrees, its answer replaces the recorded one and the old value is kept in `bomlens:license:superseded`; when it agrees (also under a deprecated id such as `GPL-2.0+`), lists a non-SPDX licence, or has no answer, nothing changes. A licence that carries its text, a url or a concluded acknowledgement is never checked, and a supplier's SBOM (`--analyze`) only has missing licences filled. Off by default; uses the network, and `LICENSE_REGISTRY_API` points it at a deps.dev-compatible mirror or proxy. The result manifest counts what was filled, replaced and confirmed, and records the step as degraded when lookups failed.

### Changed

- A Rust project's committed `Cargo.lock` is used as it is. Before, `cargo generate-lockfile` ran on every scan and moved crates to the newest compatible release, so the SBOM could list versions the project does not build with (a committed `syn 3.0.6` came out as `3.0.7`). The documentation already said the lock is resolved only when none is committed.
- deb, rpm and apk PURLs are written in the Trivy and purl-spec form (see the upgrade note), and an apk PURL with `distro=<release>` is recognized when the operating system component is filled in.
- A yarn, pnpm or bun project (no `package-lock.json`) keeps its production packages. The production-scope filter compared exact versions, but without a `package-lock.json` the production set came from npm's own resolution of `package.json`, whose newest releases differ from the project's lock, so production packages were dropped (a `yarn.lock` pinning lodash 4.17.20 left no component at all). Without a `package-lock.json` the set is now compared by name (a dev tool that shares a name with a production package is then kept). A yarn, pnpm or bun workspace root without a `package-lock.json` keeps the full graph, since the members' own dependencies cannot be resolved from the root alone.
- A Poetry project with no `poetry.lock` is scanned from the exact pins in `[tool.poetry.dependencies]` (written to a temporary `requirements.txt` that is removed after the scan). Before, it came back with no components. Ranged (`^2.0`) and table dependencies are still left out; the log counts them, and the result manifest records `generate` as degraded (`fallback`).
- A CLI source scan of a conda project keeps its `environment.yml` dependencies. The sidecar build-prep writes for them was removed by the leftover cleanup at the start of the post-process step, and since cdxgen's python cataloger is turned off when that file is parsed, the Python dependencies were missing altogether.
- A source scan that finds manifests or lock files declaring dependencies but produces no component now says so: the SBOM carries `bomlens:sbom-empty-with-manifests` with those files, the closing summary warns, and the result manifest records `generate` as degraded with the new reason `no_components`, so the run is `succeeded_degraded`.
- `--deep-license` runs only in a source scan, on the scanned tree. Before, it scanned whatever was mounted at `/src` in any mode, which in the web UI could be the server's own folder for an SBOM analysis.
- `--resolve-purl` now stops waiting at `PURL_RESOLVE_BUDGET`. Before, the budget only limited when lookups were started, so a slow repository could hold the scan far longer; identifiers that have not answered are reported as unchecked.
- The non-shipped folder list gains the singular and short spellings `sample`, `bench`, `benchmark`, `demo` and `demos`, next to the plural forms it already had.

### Fixed

- A project named `app` or `src` stopped every scan: the names scanners give a project they cannot name were refused even when the caller chose them. They are now refused only when the SBOM is uploaded (`UPLOAD_ENABLED` is not `false`), where they collide on an SBOM import platform; otherwise the name is kept with a warning.
- A Gradle project scanned with a read-only root filesystem (as an execution-plan caller runs stage 1) came back with no components: Gradle keeps its files under the account's `~/.gradle`, not `HOME`, and failed at once when it could not write there. It now uses `$HOME/.gradle` in that case; a writable `~/.gradle`, such as the CLI's mounted Gradle cache, is still used. When a source that declares dependencies yields none, the result manifest's `generate` detail now also names the resolver steps that failed.
- A Python project scanned from its `pyproject.toml` could list `pkg:pypi/unknown@latest`, linked from the project: a package cdxgen could not name in its own environment, not one of the project's. It is now left out, and the result manifest says so: `generate` counts it as `unresolved` and its `detail` names it.
- An image or root filesystem scan gave Debian packages whose copyright file is not machine-readable (libc6, libgnutls30, base-files and others) the file's hash as their license. Their licenses now come from Trivy's license scan of the operating system packages, which reads the license names, common-licenses references and license text in those files: libc6 reads `GPL-2.0-only` and `LGPL-2.1-only`, and some of Debian's short names become SPDX ids (`GFDL-NIV-1.3` reads `GFDL-1.3-no-invariants-only`). A package Trivy gives no license keeps syft's, less any hash; apk and rpm packages keep syft's licenses. The result manifest records the new `os-licenses` step (engine contract `1.2.0`); `BOMLENS_OS_LICENSES=false` turns it off, since it reads the image a second time. Firmware scans are not covered.
- The post-processing stage run as a user with no writable home (any UID, as a Kubernetes job runs it, or a read-only root filesystem) failed the `--deep-license` scan: scancode could not create its cache folder. Such a home is now replaced with a folder in the temporary directory, which also lets Trivy download its database there.
- The result manifest now records `generate` as `degraded` (`fallback`) when a lock-less Poetry project's pins could not be resolved further (`poetry-graph` failed, for one with no network), so the run reads `succeeded_degraded`; before, only the SBOM said so.
- A stage 2 told that stage 1 never ran (exit code 127, as for an `unsupported` plan, or `BOMLENS_STAGE1_REASON=cdxgen-unavailable`) records the fallback reason as `cdxgen-unavailable` instead of `cdxgen-crash`; the CLI reads exit code 127 the same way. A supplier SBOM under `--analyze` that carries these Poetry marks no longer degrades the analysis run.
- The CLI's manifest-only fallback, used when cdxgen fails, now runs inside the post-processing step, the same code a caller of the execution plan gets. It now honours `BOMLENS_INCLUDE_NON_SHIPPED=1` (it used to leave test and sample manifests out regardless). The "Manifest-only fallback used" warning now appears after post-processing, once the fallback has succeeded.
- When cdxgen exited without error but left an empty SBOM, the CLI stopped with "SBOM not found"; it now takes the manifest-only fallback, as the execution plan path does.
- When cdxgen fails and the post-processing image is older than the CLI (it cannot run the fallback), the CLI now says so and names the image to pull, instead of stopping on a missing SBOM.
- A Poetry project with no `poetry.lock` came back with its exact pins unlinked and without their own dependencies, so the conformance check on transitive dependencies failed. The pins are now linked from the project root, with their dependencies, resolved by a second cdxgen run on the temporary `requirements.txt` alone (the source tree is not touched). When some entries were left out, or that run fails (no network), `compositions` declares the graph `incomplete`.
- When the conformance check on transitive dependencies fails and the SBOM declares its graph completeness `unknown`, the detail no longer adds "not a defect", which read as if the failure itself were not a problem. A passing check keeps the note.
- When the dependency analysis gave no result (`cdxgen-unavailable`), the web UI's result overview asked to make sure Docker is available, also when cdxgen ran and left no SBOM. It now says the SBOM was built from the manifests only, that the scan log gives the reason, and asks to check Docker only for a scan that could not reach it.
- The published images' `org.opencontainers.image.source` and `org.opencontainers.image.url` labels now give `https://github.com/sktelecom/bomlens`.

## [v1.13.1] - 2026-10-10

### Upgrade note

- An AI declaration can now hold a `service` and the model keys `inputModality`, `outputModality`, `trainingComputeFlops`, `trainingComputeBasis` and `adversarialTesting`. BomLens v1.13 and earlier refuse such a file with "unknown key(s)" rather than dropping the values, so read it with this version or remove the keys.
- G7 counts change when a service or these model values are declared. The system data flow, data usage, input/output properties and application area leave the "need review" count and join the denominator once the SBOM holds a value, and the system name, producer and version can be met by the service, so the same model can show more elements present and fewer review items than before. Without a declaration the results are unchanged.
- The G7 system data flow element now accepts CycloneDX serviceData (`services[].data[]` with a `flow`) from any tool, and data usage a data flow with a `description`. An SBOM checked with `--analyze` whose services carry them can read better than with an earlier version.

### Added

- The AI declaration takes the service a model runs in (`service`): its name, version, address, provider and release date, which SPDX requires of it, and optionally what it is for, its fields of use, whether a person is involved in its decisions (`autonomyType`), its input and output kinds, its data flows (`dataFlows[]`, in the shape of CycloneDX serviceData), the standards it follows and a public disclosure page. The SPDX 3.0.1 document writes it as an `ai_AIPackage` with the purpose `application` that depends on the model at runtime; the model stays the document's root. A declaration without a service gives the same document as before.
- A declared service can list the AI models it calls through an API (`service.externalModels[]`, with a key, name, provider, version and endpoint). They are recorded by identity only, as a `software_Package` with the purpose `model` in the SPDX 3.0.1 document and as services in the CycloneDX SBOM; nothing is read about them, and they are not judged by the risk assessment.
- The declaration's `model` takes its input and output kinds and three values for regulatory filings: training compute in FLOPs as a decimal string (`trainingComputeFlops`, such as `"3.2e24"`), how it was counted (`trainingComputeBasis`), and whether adversarial testing was done (`adversarialTesting`). The AI model guide names the EU AI Act and Korean AI Basic Act provisions they relate to, as reference only.
- A new step after the declared dataset sources, and before the risk assessment and the G7 checks, writes the declared service into the CycloneDX SBOM: `services[]` with its data flows, endpoints and disclosure page, its dependency on the model and the external models in `dependencies[]`, and its standards as `declarations.claims[]`. The model component gains the declared regulatory values as `bomlens:regulatory:*` properties and its input and output kinds in `modelCard.modelParameters`, unless the scan already recorded them. Everything written is marked as the publisher's declaration (`bomlens:origin=declared-input`, `bomlens:declared`, `bomlens:declared:observedKept`), and only a declaration the SPDX 3.0.1 converter accepts is applied. The SPDX check reports whether the SBOM follows the current declaration (`service.state`: `none`, `applied` or `pendingScan`). The SPDX 2.3 export and `--diff` do not carry services.
- The G7 system-level checks read the declared service: the system name, producer and version when the SBOM's root does not give them, and the system data flow, data usage, input/output properties and application area, which were review-only before. An element met this way reads "present (publisher's declaration, not verified by BomLens)". A `modelCard.modelParameters` created only to hold declared formats does not count as a model card.
- The web UI's questions gain an optional Service step (the service, its data flows and the external models it calls), the model step a folded group for regulatory filings and the model's input and output kinds, and a dataset's known bias moves to its main questions. Models & datasets shows the declared service with a "Publisher's declaration" badge, and a service saved after a scan is flagged until a new scan brings it into the CycloneDX SBOM and the G7 checks.

## [v1.13.0] - 2026-10-10

### Upgrade note

- An AI model scan now reads the datasets a dataset's card names as its sources (`source_datasets`) and judges them with it, so a model whose training data contains a source under stricter terms can grade lower than before (for example `caution` where it was `ok`). Compare with an earlier result using `--diff`. `AIBOM_DATASET_DEPTH=0` restores the previous behaviour.

### Added

- An AI model scan follows the sources a dataset's card names (`source_datasets`), up to three levels and 40 dataset lookups per scan (`AIBOM_DATASET_DEPTH`, `AIBOM_DATASET_MAX_LOOKUPS`). Each source becomes its own `data` component linked from the dataset in `dependencies[]`, with `bomlens:dataset:derivedFrom` on the dataset and `bomlens:dataset:depth` on every traced dataset. Only a value shaped like a HuggingFace dataset id is looked up; a source named in words is kept verbatim as `bomlens:dataset:sourceDataset:unverified`. A cycle, the depth limit and the lookup limit are recorded on the dataset where the walk stopped. The strictest verdict among a dataset's sources becomes part of that dataset's verdict (`bomlens:assessment:sources`), and through it the model's datasets axis. A source that could not be read, declares no license or is named only in words, and a dataset whose sources lie past the depth limit, read review. Placeholders such as `extended` alone, `unknown` or `N/A` are not looked up. Dataset lookups use `HF_ENDPOINT` and `REQUESTS_CA_BUNDLE` when they are set. The web UI shows traced sources as indented rows in the datasets table.
- AI model and dataset scans also write the result as an SPDX 3.0.1 document with the AI and Dataset profiles (`{Project}_{Version}_bom.spdx3.json`), with a check of where each field came from and which required fields are still open (`_spdx3-check.json`, `_spdx3-check.md`) and an empty declaration for the publisher to fill (`_ai-declaration.template.json`). The documents pass the official SPDX 3 validator (SHACL model), checked nightly. Values the scan does not hold are not estimated: until the required ones are declared the document is marked a draft. `--sign` covers it, and `--no-spdx3` skips it. The CycloneDX ML-BOM stays the primary record.
- `--ai-declare <file>` applies the publisher's declaration (release dates, makers, how each dataset was used, base model revisions, the distributed weights, and the judgments only the publisher can make) to the SPDX 3.0.1 document. A declaration that names something the scan did not find, or a value outside a field's list, is refused with the reasons and the document stays a draft. An accepted declaration is kept as `_ai-declaration.json` and applied again on a re-scan.
- The web UI shows the SPDX 3.0.1 document's state on Models & datasets and asks for the open fields step by step (**Fill in empty fields**), saving them as the declaration (`POST /ai-declaration`). The Artifacts screen gains cards for the document and the declaration, with actions to write the document (`GET /spdx3-export`) and to upload an edited declaration. A declaration saved earlier that no longer fits the scan is reported until it is fixed.
- A model that has no hub repository or file yet can be described from its publisher's declaration alone: `--ai-declare <file>` without `--model`, `--model-file` or `--target`, or the web UI's **Enter model information** tile, which asks the questions and starts the scan with the answers. Its base models and datasets are read from the hub by id; the declared values go into the SPDX 3.0.1 document. The SBOM's lifecycle phase is `design`, and without `--sbom-author` its author is the declaration's `document.createdBy`. A declaration that does not fit is refused before the scan, with the reasons.
- The AI declaration can name a dataset's sources (`datasets[].sources[]`, and a "Where this data came from" row in the web UI's questions). A source given by its HuggingFace id is read from the hub on the next scan, before the risk assessment, and judged with the dataset; one known only by name is written to the SPDX 3.0.1 document with the licence given, marked as not verified. A dataset with no source on record is listed in the SPDX check for review.
- The AI declaration takes the model's own licence (`model.license`, a hub licence tag or SPDX id, and a "Licence of the model" question in the web UI). A model described from the declaration alone carries it in its SBOM and is judged on it instead of reading `review`; for a scanned model it fills the SPDX 3.0.1 document only when the scan read no licence or only `other`, and one that differs from the scanned licence is listed for review.
- `--model` and the web UI's AI-model field take a HuggingFace dataset as `datasets/<owner>/<name>`, its `https://huggingface.co/datasets/...` address or `hf:<owner>/<name>`, and describe it as the SBOM's root `data` component in the base image, with its sources traced and judged the same way as a model's datasets. A bare `owner/name` is still a model id. `HF_TOKEN` is passed by name for a gated dataset, and a dataset that cannot be read ends the scan with the reason.
- An AI model scan records each weight file's name next to its SHA-256 (`bomlens:weights:file`), the gate kind, the time of the revision it read, the hub's relation to the base model (`bomlens:lineage:relation`), a merged model's other parents, and the distributed weights scope (`bomlens:weights:scope`: full, adapter, quantized or merged) when the hub's signals agree. When no other tool supplied a pedigree, the base-model chain is written to `pedigree.ancestors[]` without a version.

### Fixed

- The note that names dataset names dropped from a model card's prose no longer disappears when the same SBOM is enriched a second time.
- Source scans no longer list an extra unversioned component for every licence file inside a package manager's install directory (`node_modules/`, a Composer or Go `vendor/`, SwiftPM's `.build/` and the like). The cdxgen language images were pulled by the `v13` tag, which cdxgen rebuilds nightly, and builds since 2026-10-05 began reporting those files; `examples/nodejs` went from 120 to 554 components. The images are now pinned to the 13.2.0 release, and such components are also dropped after generation. Vendored code in the project's own tree is kept.
- Two scans running at once no longer read each other's vulnerability-scanner errors: each run keeps them in a file of its own instead of a shared `/tmp/trivy.err`, so a retry is decided on the run's own error.

### Security

- Every image bundles docker CLI 29.8.1, whose newer Go toolchain fixes eight high-severity standard-library vulnerabilities.
- The AI SBOM image upgrades npm to 11.20.0 and cdxgen to 13.2.0, and overrides vulnerable pins in the OWASP AIBOM Generator's requirements (among them anyio 4.14.2 for critical CVE-2026-63374, urllib3 2.8.0, starlette 1.3.1, python-multipart 0.0.31, aiohttp 3.14.3, fsspec 2026.6.0 with datasets 5.0.1, transformers 5.10.4 and torch 2.13.0). The build fails if an upstream pin it replaces has moved, so an override never downgrades a package.
- The firmware image raises httplib2 to 0.32.0 and pyOpenSSL to 26.4.0.
- Rebuilt images pick up Debian security updates for OpenSSL, PCRE2, libheif, jq, xz and libpng.

## [v1.12.1] - 2026-09-23

### Upgrade note

- The conformance report's `os-purl-namespace` check is now `purl-namespace`, since it no longer covers only OS packages, and its detail reads "N without namespace" rather than "N without distribution". Anything that reads the report by that id needs the new one. Nothing else in the report's shape changed.

### Added

- A source scan that runs a Maven or Gradle build (CLI, web UI and desktop app) now warns before the build starts when the Docker engine has less than about 4 GB of memory, and names the setting to change for Colima, Docker Desktop and Rancher Desktop. The scan is not stopped.
- The CLI now ends every software scan by stating what the result holds: the number of components identified, the share with a purl and with a declared license, and a warning line when no software was identified, no component declares a license, the analysis was reduced (with its reason), or post-processing steps failed. The numbers are the scan's own conformance measurement. The exit code is unchanged.
- `--fail-on <condition>` makes a scan exit non-zero when a condition is met (exit 4) or cannot be judged from what the scan produced (exit 5). It can be repeated. The conditions are a closed list: `vulnerability=<critical|high|medium|low>`, `malicious-package` and `license-conflict`. A vulnerability scan that did not complete, or a license conflict with no `--license`, is reported as "cannot be judged" rather than passing. The CI/CD guide uses it in place of the `jq` step.
- `--fail-on empty-result` fails a scan that identified no software (operating-system and file entries are not counted), and `--fail-on license-coverage=<0-100>` fails one where fewer than that percent of components declare a license (the value is required, there is no default). Both read the scan's own conformance report and report "cannot be judged" (exit 5) when it is missing or has nothing to measure. The conformance report gains top-level `emptyResult`, `softwareComponentCount` and `licenseCoverage` fields; its checks and verdict are unchanged.
- The web UI can export the CVE judgements you recorded as a CycloneDX 1.6 VEX document (**Export VEX** on the Vulnerabilities screen, `GET /vex-export`), so another tool can read them. The four states map to CycloneDX `analysis.state` values, and each entry points at a copy of its component held in the document, so the file stands alone. The judgements and the export also get their own card on the Artifacts screen.
- The web UI can import a CycloneDX VEX document a supplier sent (**Import VEX** on the Vulnerabilities screen, `POST /vex-import`). Statements that apply to a component of the scanned SBOM show on their rows with a separate "Supplier VEX" label and never replace your own judgement. A document for a different product or version is refused.
- `--vex <file>` reads a supplier's CycloneDX VEX document during a CLI scan and keeps the statements that apply to the scanned SBOM in `{Project}_{Version}_vex_imported.json`. The SBOM and the security report are unchanged (the security report is turned on too, since the statements are shown on its findings), and a document for a different product or version is reported and skipped.
- A firmware scan now records how much of the image the unpacker could open, as `bomlens:firmware:*` properties on the firmware component (unrecognized share and bytes, encrypted regions, extraction steps that did not complete and their formats, missing extraction tools). The risk report adds a "Firmware analysis scope" section and the web UI Overview a matching note when part of the image went unopened, so a clean vulnerability count reads as covering only what was opened. Shown only for a scan that unpacked the image itself, not for a merged or submitted SBOM.
- `--analyze` and the web UI upload accept CycloneDX XML (1.0 to 1.6, UTF-8 or UTF-16; a version before 1.2 is written as 1.2, the first with a JSON form). The document is rewritten as CycloneDX JSON before validation, keeping component hashes, the root component, the dependency graph including the nested form, the supplier's compositions, and the manufacturer, authors and lifecycle fields the conformance checks read. The services, vulnerabilities, pedigree, evidence and formulation sections and the like are not carried over, and the scan log names any that were skipped wherever they sit. A document that declares a DTD or an entity is refused. SPDX RDF/XML is still not supported.
- The web UI and the desktop app can now hand a problem over: the result screen of a finished scan, succeeded or failed, has a Report a problem panel that shows a diagnostics summary (versions, container engine, options, per-stage results, warnings) built from a fixed list of fields, with home-directory user names and credential-shaped text masked, and copies it in one press. The run log has a Copy log button (credential-shaped text masked), and the Help menu, the desktop app's menu and its start screen link to a new issue form that asks for the command, scan mode, container engine and image tag. Nothing is sent anywhere.
- The conformance screen of the web UI and the desktop app no longer shows a plain green pass for a result that found no software or where no component declares a license (0% coverage). It shows a warning explaining what the pass does and does not mean, changes the verdict badge to "Pass, see the note below", and shows the share of software components that declare a license whenever there are components. An SPDX document holding only the package it describes now counts as empty, as the CycloneDX equivalent does. Reports written before these fields existed, and AI SBOMs, are unchanged.
- A source scan now fills the `copyright` of npm, Python (pip), Go and Rust components from the license files the installed package ships, so the NOTICE prints an attribution line for them. A component that already has a copyright is left alone, a package with no usable line stays empty, and each value set carries `bomlens:copyrightSource`. `BOMLENS_NO_COPYRIGHT=1` turns it off.
- A Rust source scan now fills each crate's license from `cargo metadata`, which reads the crate's own manifest. cdxgen reads only `Cargo.lock`, so the bundled example had a license on 1 of 147 libraries; it now has 146. A license the SBOM already has is left alone, a crate that declares none stays empty, and each value set carries `bomlens:licenseSource`. It needs a route to the crate registry; without one the step is recorded as failed on the SBOM and the licenses stay as before. Alternatives are written in a fixed order (`Apache-2.0 OR MIT`), a value that is not an SPDX expression is kept as a license name, and the crate's own workspace members are filled from their local manifests. `BOMLENS_NO_CARGO_LICENSE=1` turns it off, and so does `FETCH_LICENSE=false` on the command line. A `WITH` exception in an expression is no longer cut down to its base license by the normalize step. The `[cpe] filled a confirmed SPDX license` count now counts only licenses that step filled.
- The conformance check now reports an identifier whose purl type requires a namespace but carries none, for every such type rather than for OS packages alone. A `pkg:maven` identifier without its groupId, or a `pkg:github` identifier without its owner, is well-formed text that resolves to no package, and the syntax check cannot see it because the namespace is optional for npm and pypi. Which types require one is read from `docker/lib/purl-types.json`, which mirrors purl-spec's own type definitions. `pkg:golang` and `pkg:huggingface` are reported on a separate advisory row that never fails the SBOM, since an identifier of either can legitimately have no namespace (a Go module path can be a bare host, and a model published outside an organization has no owner segment).
- `--resolve-purl` asks each package repository whether the identifiers in a submitted SBOM name packages that exist, and adds the answer to the conformance report as an advisory row (`--analyze` only, off by default, the only part of the check that uses the network). It catches what no format check can: an artifactId that repeats its groupId, or a vendor display name sitting in the namespace slot. Both are well formed and resolve to nothing. The row never fails an SBOM, because a package published only to an internal repository answers the same way; `PURL_RESOLVE_IGNORE` leaves those namespaces out of the lookup, and `PURL_RESOLVE_BUDGET` caps the time the step may take. The coordinate is checked, not the version, so a vendor rebuild version is not reported as missing.
- The conformance check now reports a purl type that purl-spec does not define, such as `pkg:applications`. A generator that rebuilds identifiers from a component's display name can invent one, and until now only `pkg:generic` was recognized as untraceable. It warns under the default profile and fails under `skt-submission`, like the `pkg:generic` row.
- Modelica libraries identified from `uses()` now carry a license when the library is in BomLens's known-library table and the version is one whose upstream license was confirmed (Modelica Standard Library 3.2.3 and later: `BSD-3-Clause`; Buildings 13.0.0 and later: `BSD-3-Clause-LBNL`). Other libraries and older versions stay without a license.

### Fixed

- A source scan of a Python project no longer leaves a `*.egg-info` directory behind in the scanned project. A directory that did not exist before the scan is removed afterwards; one you already had stays, though the install can still rewrite files inside it.
- A PHP project with no `composer.lock` is now resolved without its `require-dev` section and without `config.lock=false`. A library whose dev tools could not be resolved (for example one that requires the library itself, or PHP extensions the image lacks) used to give an empty SBOM, and a resolvable one carried its dev tools as if they shipped. Your `composer.json` is put back right after the resolve, and `BOMLENS_PHP_FULL_GRAPH=1` still resolves the full manifest. The PHP version is not enforced during this resolve, so a dependency version that needs a newer PHP than the project declares can be picked.
- A source scan no longer leaves `vendor/` (PHP), `obj/` and `bin/` (.NET) behind in the scanned project. Directories that did not exist before the scan are removed afterwards; ones you already had are kept.
- A project or version name that starts or ends with a character outside `A-Za-z0-9.-` (for example `@acme/lib`) no longer fails the CLI with "SBOM not found on host". The script now names the files it looks for with the same rule the scanner container uses.
- A source scan launched through the web UI or the desktop app, in any language, could fail outright ("argument list too long") once `build-prep.sh` grew past the kernel's single-argument limit (128KiB on Linux, which every Docker host uses under the hood). It now runs from a file on the same shared mount the scanned tree already uses, instead of being passed inline as a single `sh -c` argument. The CLI path was unaffected (it already bind-mounts the file).
- A Swift source scan no longer lists a resolved package a second time. The versionless `pkg:generic` and purl-less copies that the import scan adds for a package `Package.resolved` already names are dropped, and dependency edges that pointed at them now point at the resolved package. On the bundled example the component count goes from 10 to 6 and license coverage from 20% to 33%.

### Changed

- The conformance check accepts CycloneDX 1.7 for every kind of SBOM, not only for AI SBOMs. 1.7 has been released since October 2025 and generators emit it, so a submission at 1.7 is a current document. What BomLens writes is still 1.6, because the bundled vulnerability scanner cannot read 1.7.
- `scripts/check-setup.sh` now speaks English and Korean (`SBOM_LANG`, else the locale), checks the Docker engine's memory for Maven and Gradle builds as `check-setup.bat` now does, and tells apart a blocking problem (exit 1) from problems that do not block (exit 2, with their number in the result line). It used to exit 0 in both cases. `scripts/check-ux-heuristics.sh` keeps the message sets of the two scripts equal.
- A PHP (Composer) source scan whose root `composer.json` has no committed `composer.lock` now resolves one itself (`composer update --no-dev --no-scripts --no-interaction`), the same as Ruby's `bundle lock` step already does for a missing `Gemfile.lock`. Previously nothing resolved it, and cdxgen came back with zero components and no indication anything was wrong. A resolve failure is now recorded on the SBOM instead of failing silently.

## [v1.12.0] - 2026-09-15

### Added

- The Overview screen now shows when a best-effort post-process step (CPE/EOL/malicious enrichment, conformance validation, notice generation, and the like) failed during a scan, naming which one, instead of a valid but silently incomplete SBOM giving no visible sign of it.
- The Overview comparison card's added/removed/version-changed component names and new/resolved CVE ids now link into Components/Vulnerabilities filtered to that one name, instead of leaving the reader to retype it into the section's own search box.
- The conformance report (JSON/Markdown/HTML) now names any post-process step that failed during generation, so a passing result is not read as a guarantee that every step ran cleanly. Does not affect the pass/fail result or any individual check's status.
- The web UI's conformance panel now shows the same failed-post-process-step note the Overview screen already carries, naming which step, instead of only Overview showing it. On a document someone else supplied for review, the note suggests asking the supplier to regenerate it instead of re-scanning.
- `--fail-on-conformance` makes the scan itself exit non-zero when this run's own conformance report says "fail" (2), or produced none to judge (3), instead of a separate step having to inspect the report for CI gating.
- The web UI's New scan advanced options now has an SBOM author field (`--sbom-author`/`SBOM_AUTHOR` on the CLI), so a supplier scanning through the web UI can declare who generated the SBOM without dropping to the command line. Hidden for ANALYZE, where the document already has its own author.
- Re-scanning with scan-sbom.sh, the web UI or the desktop app removes the previous run's artifacts from the output folder before writing new ones; other files in the folder are kept. A scanner image called directly with `docker run` is unaffected.
- A source scan of a directory that comes back with 0 components now names a root-filesystem-shaped subfolder one or two levels below it, when there is one, instead of leaving the reader to guess why a plainly-named delivery folder produced an empty SBOM.
- The Overview screen's notice about a direct-deps-only fallback now has dedicated wording for a scan tool crash (a dedicated reason, distinct from disk space, memory, network, or the tool being unavailable), naming neither the tool nor its raw error output.
- An rpm, deb, or apk component now gets its `supplier` filled with the distro project's name (Debian, Alpine, or Rocky so far), read from the same distro context the scanner already infers for CVE matching. Left blank for a distro not yet confirmed, a mixed-distro SBOM, or a component that already carries one.
- A scan that fails with no other classified reason now shows the scanner's own `[ERROR]` block(s) from the log on the Overview screen, deduplicated and capped, instead of only a generic "something went wrong, check the log" line with the actual cause buried in the collapsible log below it. Credential/token-shaped text (a URL's embedded userinfo, an `Authorization`/`Bearer` value, a `token=` parameter, a long hex or base64 blob) and any raw upstream HTTP response body are never included.
- A Maven component with no `<licenses>` of its own now inherits one from an ancestor POM that does declare it, read from the reactor or the local repository, when its own pom.xml has none either. Left untouched when no ancestor declares one, or when the component already carries a license.
- Every generated SBOM now declares how complete its dependency graph is (CycloneDX `compositions[0].aggregate`: `complete`, `incomplete`, or `unknown`), using `complete` only when there is positive evidence the graph actually resolved rather than just an absence of failure. The conformance report's transitive-dependency check notes the declared value in its detail text without affecting the pass/fail result. A supplier's own `compositions` declaration on an analyzed document is left untouched.
- The web UI's Vulnerabilities screen now lets you record your own judgement of a CVE (affected, not affected, fixed, or under investigation, with an optional note), shown separately from the vendor/advisory status Trivy already reports. Saved to the scan's own result folder (`{Project}_{Version}_vex.json`); the generated SBOM is not rewritten. Every CVE row can now be expanded to reach it, including one with no CVSS, description, or reference links of its own.
- Conda (`environment.yml`) source projects now identify the conda- and pip-declared dependencies directly, since cdxgen has no conda cataloger and previously returned zero components. cdxgen's own Python detection is skipped for the same project once this succeeds, so a co-located `setup.py` no longer produces an unrelated, separate set of Python components.

### Changed

- A source scan leaves out the manifests under test, fixture, example, benchmark and demo folders and the GitHub Actions workflows in `.github/workflows` by default, and records the patterns and the files it left out in the `bomlens:excluded-paths` and `bomlens:excluded-manifests` properties. `BOMLENS_INCLUDE_NON_SHIPPED=1` keeps them.
- A web UI scan now generates its conformance report, security report, AI-profile report and the model/dataset risk assessment's reason text in whichever language the web UI is currently showing (English or Korean), the same as `--lang` on the CLI, instead of always English. The generated SBOM and its third-party notice are unaffected, those are not localized either way.
- A Maven source scan now also leaves out a reactor module that is never deployed (`maven-deploy-plugin`'s `skip` resolving to `true`), and a dependency only that module needs, unless a deployed module in the same reactor declares it at any scope, and records the excluded modules and the components dropped because of them in the `bomlens:excluded-modules` and `bomlens:excluded-components` properties. `BOMLENS_MAVEN_FULL_GRAPH=1` (the same switch the existing Maven scope filter uses) keeps them.
- A Rust source scan now also leaves out a Cargo workspace member registered in `Cargo.lock` whose own directory sits under an excluded tree (test, fixture, example, benchmark or demo), and a dependency only that member needs, unless a kept member reaches it too, and records the excluded members and the components dropped because of them in the `bomlens:excluded-members` and `bomlens:excluded-components` properties. `BOMLENS_INCLUDE_NON_SHIPPED=1` (the same switch the file-level exclusion above uses) keeps them.
- An npm source scan now also leaves out a workspace member registered in `package-lock.json` whose own directory sits under an excluded tree (test, fixture, example, benchmark or demo), and a dependency only that member needs, unless a kept member reaches it too, and records the excluded members and the components dropped because of them in the `bomlens:excluded-members` and `bomlens:excluded-components` properties. `BOMLENS_INCLUDE_NON_SHIPPED=1` (the same switch the file-level exclusion above uses) keeps them.
- A dependency that an excluded npm workspace member hoisted into shared `node_modules`, and that no shipped member needs, is no longer left in the production dependency set the same npm source scan filters to.
- A pnpm source scan now also leaves out a workspace member registered in `pnpm-lock.yaml` whose own directory sits under an excluded tree (test, fixture, example, benchmark or demo), and a dependency only that member needs, unless a kept member reaches it too, and records the excluded members and the components dropped because of them in the `bomlens:excluded-members` and `bomlens:excluded-components` properties. `BOMLENS_INCLUDE_NON_SHIPPED=1` (the same switch the file-level exclusion above uses) keeps them.
- A Node/npm source scan that falls back to syft (direct dependencies only, no cdxgen) now fails with guidance instead of completing if the result covers none of the project's declared dependencies, on every path that can reach this fallback, not only the cdxgen-crash case below: a project with no committed lockfile and no cdxgen available (for example the web UI without Docker access) previously scanned "successfully" to a near-empty SBOM built from none of its own dependencies.
- The CLI no longer prints the dependency resolver's own output during SBOM generation; it goes to a log file named on screen instead.
- A deb, rpm, or apk component's `cpe` no longer carries the distro's own epoch or package-revision suffix in its version field; the component's own `version` and `purl` are unaffected. `libssl3` and `libcrypto3` now map to the `openssl` CPE.
- The web UI's toggle-style controls (New scan's source picker, the Dependencies Graph/Tree switch, Recent scans' type filter, the severity/license/conformance filter chips) now show a selected item the same way everywhere (a ring), instead of three different conventions (a tinted border, a filled segment, a ring) across screens. Overview's "Needs attention" card and the Licenses list's clickable rows also pick up hover/accent treatment already used elsewhere in the UI, for the same reason.

### Fixed

- The desktop app's declared minimum `electron` and `electron-builder` versions fell inside ranges with known vulnerabilities (a critical Electron advisory, high-severity advisories in electron-builder's dependencies). Both are now pinned to exact versions past their fixed versions.
- The desktop app's Docker-missing screen ran shell commands into plain sentences instead of showing them as code.
- Cancelling a scan from the CLI or the web UI stops its containers within a grace period and restores the scanned source tree.
- A firmware scan whose syft package pass fails prints syft's error in the scan log and records the failed pass in the SBOM as `bomlens:pipeline-step-failed` (`firmware-packages` or `firmware-extra-roots`).
- The Overview comparison card's "more severe than before" text failed WCAG AA contrast in light mode. A token-lint rule now catches a risk-severity color token used on body text instead of its text-safe variant.
- Language detection recognizes an Android project that uses the Kotlin DSL, declares the Android plugin in a version catalog or keeps `AndroidManifest.xml` under `app/src/main`, and a .NET solution whose projects sit in subfolders or that uses `.slnx`, so each is scanned with its own resolver image.
- A web UI scan that runs `--deep-cve` on a grype-less base image swaps to the deep-cve image in a sibling container, which was not forwarded `PURL_MIN_PCT`, `LICENSE_MIN_PCT`, `HASH_MIN_PCT`, `FIELD_MIN_PCT`, the New scan "Deep license (ScanCode)" toggle (`DEEP_LICENSE`) or the "Reproducible output" toggle (`BYTE_STABLE`), so an operator's conformance-threshold overrides, and a checkbox the reader had just turned on, silently reverted to the built-in defaults for exactly that scan. Forwarded now, on any mode `--deep-cve` can route to a sibling (SOURCE, IMAGE, ROOTFS, BINARY, ANALYZE), the same as the CLI already does. A malformed threshold value (not an integer, or outside 0-100) is now dropped rather than forwarded, on both the in-process and sibling paths: the in-process one previously crashed the conformance step on a non-numeric value. The published `bomlens-deep-cve` image does not currently bundle ScanCode, so `DEEP_LICENSE` forwards cleanly but has nothing to run there yet (the pipeline already logs this and skips rather than failing).
- A scan of a folder that never got the chance to restore its own build artifacts (a forced kill, an out-of-memory kill, a host crash) now has them cleaned up by the next scan of the same folder, from the CLI, the web UI, or the desktop app.
- A source scan's dependency-resolution steps (Cargo, Go, Bundler, pip, npm, Swift, Gradle/Android) had no time limit and discarded their own error output, so a stuck or failing step left no trace and the SBOM looked complete. Each step is now bounded (`BOMLENS_PREP_TIMEOUT`, default 900s / 1800s for Gradle and Android) and a failure or timeout is logged with the step's own output and recorded on the SBOM as `bomlens:pipeline-step-failed`.
- The web UI's estimated download size for an opt-in firmware/AI/deep-cve image always read the amd64 entry off the image's manifest, so an arm64 host (Apple Silicon Mac, arm64 Linux) saw the wrong size once an image also publishes an arm64 variant. It now matches the size to the daemon's own reported architecture, falling back to the amd64 entry when that architecture has not been published yet.
- A source scan whose dependency resolver crashes internally (an unhandled exception, or its own document validation rejecting the result) now falls back to a manifest-only scan (direct dependencies, no transitive resolution) and records `bomlens:sbom-tool-degraded=cdxgen-crash`, instead of a raw stack trace and no SBOM at all. The CLI did not fall back at all before this; the web UI already did for other cdxgen failures, and now does for this one too. For Node/npm, the fallback is discarded and the scan fails with guidance if it covers none of the project's declared dependencies, rather than reporting a misleadingly complete-looking SBOM built from none of the actual dependency tree.
- The small "Scan failed" badge next to the result heading failed WCAG AA contrast in light mode.
- The Vulnerabilities table's upgrade-bundle grouping ("one upgrade fixes N CVEs") keyed only on package name, installed version, and fixed version, so two different components (different ecosystems, or an unrelated package) that happen to share all three were bundled together as one upgrade. Each vulnerability row now also carries the affected component's purl when Trivy resolved one, and the grouping (and the table's row identity) uses it to tell such components apart; a row with no purl falls back to the previous name-based behavior. The Vulnerabilities table may now show more, smaller bundles than before on an SBOM with such collisions.
- A web UI scan that runs `--deep-cve` on a grype-less base image swaps to the deep-cve image in a sibling container, which was not forwarded an operator's `SECURITY_ENRICH`, `ENRICH_MALICIOUS`, `STALENESS_ENRICH`, or `SECURITY_NVD_VERIFY` (with `NVD_API_KEY`) container-level settings, so they silently reverted to the built-in default for exactly that scan. Forwarded now, the same as `PURL_MIN_PCT` and friends already are.
- PHP (Composer) source scans no longer inflate the SBOM with the require-dev toolchain (PHPUnit and its own dependencies, PHP_CodeSniffer, and the like). cdxgen already tags each composer component with its resolved scope, the same way it does for Maven, so the scan is scoped to the required set using that tag, the same mechanism the Maven fix above reuses rather than duplicates. Set `BOMLENS_PHP_FULL_GRAPH=1` to keep the require-plus-require-dev graph.
- Dependency-graph completeness detection (`compositions[0].aggregate`) now finds a `composer.lock` or a .NET `packages.lock.json` in a subdirectory, the same way an existing `Package.resolved` search already did, instead of checking only the scan root. A PHP or .NET project laid out as a monorepo with no lockfile at the root no longer reads as `unknown` when its components do have one.

## [v1.11.11] - 2026-09-14

### Added

- The Dependencies tree now has a search box, and a vulnerable package's row in Vulnerabilities/Components carries a "View in Dependencies" link that jumps straight to it in the tree, ancestors already expanded, instead of leaving the reader to hand-expand branches looking for it.
- The Vulnerabilities screen now shows a bundle summary when two or more CVEs on the same installed package share the same fixed version, naming the single upgrade that resolves all of them, instead of leaving the reader to notice the coincidence by comparing the Fixed column row by row.
- The Overview comparison against the previous scan of the same project now names what changed (components added/removed/version-changed, vulnerabilities new/resolved), instead of only a net component-count delta and a worst-severity direction that a like-for-like swap could leave looking unchanged.
- `--conformance-profile` (`CONFORMANCE_PROFILE`) selects `default` or `skt-submission`. `skt-submission` requires 100% PURL coverage and fails on any `pkg:generic` purl. The conformance report records the profile, and the web UI's New Scan advanced options can set it. Operating-system components no longer count toward the PURL and name-version coverage denominator.

### Fixed

- `BOMLENS_MAVEN_FULL_GRAPH`, `BOMLENS_NODE_FULL_GRAPH`, `BOMLENS_ANDROID_FULL_GRAPH` and `BOMLENS_KEEP_BUILD_OUTPUT` are passed to dependency resolution from the CLI and the web UI, and count as set only for `1` or `true`.
- A Go source scan could not resolve dependencies when `go.mod` required a newer Go than the cdxgen Go image carries (for example `go 1.26.0`): `go list` failed, leaving only the modules named in `go.mod`, or no SBOM. The required toolchain is now downloaded (`GOTOOLCHAIN=auto`), the host's `GOTOOLCHAIN`, `GOPROXY` and `GOSUMDB` are passed to dependency resolution, and a failed toolchain download is reported in the scan log.
- A scan's run log could show a literal, unrendered ANSI color code (`[1;35m...[0m`) instead of stripping it.
- A failed git clone showed the raw git error to the user; the web UI now classifies a missing/private repository or a network failure into a plain-language message, with the raw detail still available behind "Show detail".
- Overview could show two contradictory banners at once: "no components were found" alongside "direct dependencies only" (which implies dependencies WERE found). The second banner now stays hidden at zero components, and its cause is folded into the first banner's message instead.
- `--branch`/`--ref` accept a commit SHA, retrying as a full clone when the shallow clone can't resolve it.
- A Yocto build directory scanned through its manifest fallback, with no SPDX document, produces no conformance-report warning.
- A current-folder scan's source-tree listing excludes the scan's own output subfolder, from the CLI and from the web UI's Current folder target alike.
- `bsi:component:filename` is derived from a Maven purl's type and classifier when no location property exists. The signature check accepts an adjacent `<sbom>.sig` file and reports a same-run signing failure separately.
- A malicious-package advisory limited to a version range marks only versions inside that range. A version that cannot be compared against the range is marked `bomlens:malicious:rangeUnknown` instead.
- `scan-sbom.sh --help` output is English only. `docs/reference/cli.md` documents `CVE_BIN_TOOL_DISABLE_SOURCES`'s actual default (`GAD,OSV`) and adds `SBOM_BASH`.

## [v1.11.10] - 2026-09-13

### Added

- `--diff <old.json> <new.json>` compares two already-generated AI-model SBOMs and reports drift: a `bomlens:assessment:*` verdict that got worse, a changed declared license, or a SHA-256 weight-file hash that no longer matches under the same model name/purl/HuggingFace id. Needs no `--project`/`--version` or scan target; writes `<new>_model-diff.json`.
- `--verify-weights`, opt-in with `--model`: downloads only the repo's pickle-format weight files (`.bin`/`.pt`/`.pth`/`.ckpt` — the ones that execute code on load) and runs the same local picklescan verification `--model-file` already runs, instead of only trusting HuggingFace's own scan. Stamps `bomlens:localscan:*` on the model component, worst-status-wins across files.
- The model-file reader (`--model-file`) now recognizes Keras `.h5`/`.keras` files and checks them for a `Lambda` layer, the marshalled-code equivalent of a pickle-format risk; recognizes an ONNX external-data reference that escapes the model's own directory; and checks a GGUF chat template for known Jinja2 sandbox-escape gadget patterns. All three are static, header/config-only checks — no code is executed, unmarshalled, or rendered.
- The submission-format conformance check now also runs on the SBOM a scan itself generates (SOURCE, POSTPROCESS, ROOTFS, IMAGE, BINARY, FIRMWARE, MERGE), not only when validating an already-supplied document with `--analyze`. A scan's own output can now be checked before submission without a separate `--analyze` pass.
- The SBOM Validation section (renamed from "SBOM conformance") now shows for every scan, self-generated ones included, and its intro line states up front that it checks the SBOM's own fields against format and regulatory requirements rather than judging the scanned software. A self-generated AI SBOM's G7 minimum-element disclosure stays on Models & datasets only, so it isn't shown twice.
- An AI scan's Overview now leads with a summary card: risk verdict, G7 headline, and regulatory crosswalk.
- The web UI diagnoses why a sibling container scan failed (out of memory, network, or disk, via `docker inspect`) instead of surfacing a bare exit code, and a real pipeline defect (an empty dependency graph) now surfaces as a causal Overview banner.
- Conformance thresholds (`PURL_MIN_PCT`, `LICENSE_MIN_PCT`, `HASH_MIN_PCT`, `FIELD_MIN_PCT`) are now tunable from the CLI/web UI instead of fixed, and documented.
- A scan now stamps `bomlens:os-context-ambiguous` when packages from more than one OS were voted on during distro detection, and `bomlens:os-context-unmatched` when rpm/deb/apk packages exist but none carry a distro version.
- A CycloneDX/SPDX XML input is now named and refused with a clear message ("XML SBOMs are not supported yet") instead of the generic "unrecognized SBOM format" error, in both the CLI and the web upload handler.

### Fixed

- The top-bar External lookup icon did not respond while a scan was running, because the hash router ignores navigation during a run the same way it does for New scan.
- `--target <directory>` always fell through to ROOTFS unless it looked like a Yocto build directory, so cdxgen never ran on a plainly named source folder, silently dropping resolved licenses, hashes, and the dependency graph.
- The SBOM Validation filter chip labels read as vague and bureaucratic in Korean; reworded to match the wording already used elsewhere in the docs.
- A ROOTFS scan's syft failure was silently discarded instead of stating its cause, and a `--target` directory that routes to ROOTFS with no package database now warns, matching the existing archive-path warning.

## [v1.11.9] - 2026-09-09

### Added

- The CycloneDX `specVersion` literal, previously hardcoded in about 30 places across the scanner, is now a single source of truth, and the generated SBOM body is capped at 100 MB with a stamped warning above that — neither the CLI path nor the web UI's read paths had a size guard before.
- The web UI's scan listing is now cached instead of re-parsing every past scan's SBOM and security report on every request, and a picked-then-abandoned upload is swept automatically after a configurable TTL (`SBOM_UPLOAD_TTL_HOURS`, default 24h).

### Fixed

- A zip-slip guard on archive ingestion could be bypassed by an entry name containing a space, since the column-based parser it used split on whitespace the same way its own table format did.
- Archive extraction now also rejects member names containing characters Windows forbids in a path, closing a gap the existing zip-slip guard didn't cover.
- The web UI's upload handler destroyed non-ASCII filenames with an ASCII-only sanitizer, affecting the common case of a Korean project archive.
- A value in `bomlens.settings.txt` (the no-CLI Windows settings file) containing shell metacharacters could inject into the commands the launcher assembles from it; such values are now rejected.
- `scan-sbom.bat`'s delayed-expansion mode, needed for its Git Bash discovery loop, ate a literal `!` in arguments forwarded to the underlying script.
- The web server accepted any `Host`/`Origin` header, so DNS rebinding could reach a loopback-bound instance from a browser tab on an unrelated domain; a request now must name the server's own address.
- The project name was interpolated unescaped into the `<title>`/meta line of generated HTML reports, and in the web UI that name is user-supplied.
- A component carrying both a precise SPDX license id and a generic PyPI trove classifier for the same grant (e.g. `BSD-3-Clause` + "BSD License") was pulled down to Uncategorized instead of keeping its real permissive classification.
- The EOL and known-malicious-package checks exited silently when their offline data bundle wasn't built into the image, leaving a scan that never actually checked indistinguishable from one that checked and found nothing; both are now stamped as unavailable instead.
- Generated artifacts (the BOM, NOTICE, security report) now sync to the host incrementally as each is produced rather than only in one copy at the very end, so a container killed partway through a scan no longer loses artifacts that had already finished.
- A DATASET-mode scan logged a spurious "no lifecycle phase defined" warning on every run.
- The set of artifact suffixes tracked by the scanner, the web server, and the docs reference had drifted; `_yocto_vex.json` in particular was a real deliverable the web UI never surfaced (not listed, not downloadable, not deletable).
- Corrected several guide examples (the CI/CD pipeline snippets, the server-SBOM merge workflow, the reports quick-start) that referenced output paths from before scans moved into a per-run subfolder, and filled gaps in the Korean docs — a missing artifacts-reference table section, and links that pointed to the English page instead of its Korean mirror.

## [v1.11.8] - 2026-09-07

### Added

- The web UI can look up a CVE/GHSA/etc. advisory id, or check a package version for known vulnerabilities, on demand against OSV.dev, reachable from the top bar or from a search whose term looks like an advisory id, with or without a scan loaded, and as a shareable link. `EXTERNAL_LOOKUP=false` removes it entirely for a closed network.

### Fixed

- A scan started from the New scan screen that then failed left every "New scan" control (the top bar, the rail, and the error card's own button) unresponsive: the hash never moved off `#/new`, so none of them fired the navigation event the reset depended on. Clicking any of them now resets the form regardless.
- The CLI's own scanner image, the web UI's container, and the sibling firmware/AI-model/deep-CVE images it launches reused a cached image forever once one had been pulled, even after the registry published a newer one (a stale local image once caused a scan to fail outright). Each now quietly checks for an update before a run, bounded so a slow or offline registry never delays or blocks the scan.
- Creative Commons licenses (`CC-BY-4.0` and its variants), common on datasets and AI models, always fell to Uncategorized in the license-risk classification because it only recognized software copyleft families. Share-Alike variants now classify as weak-copyleft and plain attribution as permissive.

## [v1.11.7] - 2026-09-04

### Added

- Modelica (`.mo`) source projects now identify the libraries declared in a package's `annotation(uses(...))` block (e.g. `uses(Modelica(version="4.0.0"))`), since cdxgen has no Modelica cataloger and previously returned zero components. Direct declarations only — no lockfile, no transitive resolution.
- The conformance report now fails an SBOM whose OS package identifiers carry no distribution (`pkg:rpm/bind@9.11.36-16.el8_10.6` instead of `pkg:rpm/rhel/bind@...`). purl-spec requires that namespace for `rpm`, `deb` and `apk`, and vulnerability matching keys on it, so such an identifier is well formed and still matches nothing: a supplier's server SBOM passed every check with 261 identified packages and resolved zero. The check runs on CycloneDX, SPDX JSON and SPDX Tag-Value, and reports not-applicable when the SBOM carries no OS packages.

- The conformance screen carries the Korean wording for every check rather than only the registry rows, and gives the reader a way through its ninety-one checks instead of one long list.
- The AI screens fill the space their software counterparts already used, and four contrast failures on them are corrected.

### Fixed

- The desktop app ran whatever `main` had built that day. It pinned `ghcr.io/sktelecom/bomlens:latest` regardless of its own version, so a result could not be reproduced from the version a user reported. An installed build now pins the base and sibling images to its own version, falling back to `:latest` only when that version cannot be read. A missing tag is reported as its own pull failure rather than sending the user to look at the network.
- The desktop app told a user who already had Docker installed to install it again. Any non-zero exit from `docker version` counted as "not installed", including the common case of an engine that is installed but not started. The two are now separated, and an engine that exists only inside WSL2 is named as something this app cannot reach rather than recommended as a fix it could never detect.
- The result screens printed counts the scan had never measured. Checks marked as having nothing to measure reached the web UI as ordinary warnings, so an ML-BOM with no packages drew seven package-coverage rows as gaps and reported 6/8 mandatory instead of 6/6. An AI scan also labelled the root model a transitive dependency of its own SBOM.
- The web UI offered the deep-license toggle on an image that cannot run it. The toggle is now gated on a capability the server reports and hidden when the image lacks it.
- Source scans collected `.DS_Store`, `Thumbs.db` and their kin from any folder someone had browsed. They carry nothing an SBOM needs and are now excluded.
- Two different license counts were both labelled "Unknown", and two different training-data axes shared a name. Each now says which one it is.
- AI verdict badge tones follow the pipeline's own ranking, the fixed wording in assessment reason text is localized, and a model's limitations come from the card's own list rather than being inferred when the card states none.
- The `PURL syntax` row rendered in English on the Korean report. Its label had been reworded in the code without updating the translation catalogue's exact-match key.

## [v1.11.6] - 2026-09-01

### Added

- `GET /image-status` now reports the version baked into a firmware/AI-model/deep-CVE sibling image that is already on disk, read via `docker image inspect`. The scan form's "ready" indicator shows it, so a stale cached sibling image (one a `docker pull` never refreshed) is visible even when the app's own version is current.

## [v1.11.5] - 2026-08-31

### Added

- The web UI and desktop app now show the running BomLens version as an always-visible badge, not only inside the help menu. A build from `latest` stamps the real commit id instead of the literal string "latest", and the same value is mirrored into the image's OCI version label.
- The Windows settings file (`bomlens.settings.txt`) now accepts `UI_BIND_ADDRESS`, matching what the launcher scripts already read.

## [v1.11.4] - 2026-08-29

### Fixed

- The desktop app now refreshes its bundled scanner image when a newer one is published to the registry, instead of staying pinned to whatever was pulled once.

- A malformed or unusual SBOM (a mistyped CycloneDX `specVersion`, or one mixing multiple OS package types) no longer causes the security scan to silently return zero findings; the scan retries after normalizing or splitting the input.

- A CVE without grype's primary identifier is now recovered through its aliases instead of being dropped.

- The curated CPE maps used to attach NVD-only CVEs to GitHub- and Maven-coordinate components were expanded and corrected: Tor's release-tag prefix is stripped before matching, Go's "go1.x" tag no longer floods every Go CVE into scan results, several mismapped Maven groupIds now resolve to their real NVD vendor, and projects NVD has split across more than one CPE vendor over their history (Spring Framework, Spring Security, Jetty) now carry every relevant vendor's CVEs. Apache ActiveMQ's Artemis and Classic lines, which share a Maven groupId but are different NVD products, are now told apart by artifact name.

### Added

- Firmware scans now read the kernel version from outside the root filesystem when the kernel image lives there, so kernel CVE identification no longer silently comes up empty for those images.

## [v1.11.3] - 2026-08-20

### Fixed

- A Python component whose installed license file bundles a primary license followed by third-party notices in the same file (numpy, pandas, and similarly-packaged distributions) could resolve to a bundled license instead of its own. The scanner now reads only the leading license block and cross-checks it against the PyPI license classifier before accepting it. A batched `pip install -r` failure on one pinned dependency no longer drops installed-license evidence for every other dependency in the same file; each line is retried individually and pip's own error reaches the scan log.

## [v1.11.2] - 2026-08-17

The local web UI now answers only on the machine that started it.

### Changed

- `scan-sbom.sh --ui`, `sbom-ui.bat` and the desktop app publish the web UI on 127.0.0.1 rather than on every interface of the host. The UI container is given the engine socket so that it can start sibling scan containers for firmware and AI-model inputs, which makes reaching that port enough to start a scan. If you open the UI from another machine, set `UI_BIND_ADDRESS=0.0.0.0` and put something that authenticates in front of it; both launchers read the variable, and the Windows settings file accepts it as a key. (reference/ui.md)

- The scanner image carries syft 1.51.0 and grype 0.117.0.

### Added

- A release carries `bomlens-source-<version>.cdx.json`, a CycloneDX SBOM of what the source bundles ship, and `SHA256SUMS.txt` comes with a keyless signature (`.sig` and `.pem`) from the release workflow. The checksum file already covers every asset, so verifying that one signature covers the release. The scanner image keeps its own signed SBOM attestation.

## [v1.11.1] - 2026-08-16

Reading a scan result, rather than producing one. The components table on a
real image was hard to work through: Korean headers split down the middle of a
word, rows changed height with their contents, and scrolling right lost track
of which row was which. The controls above it had grown into four stacked
lines with no common axis.

An AI model scan also had its own section come up empty. A model SBOM names the
model as the document's own component and lists only its datasets underneath,
and both the scan list and the model view read the list alone.

### Fixed

- The Models & datasets section renders the model card when the model is the document's own component rather than an entry in the component list, which is the shape a model scan actually produces. The section showed its empty state on exactly the scans it exists for, while the rail badge beside it counted one.

- The scan list labels such a scan as an AI model scan and counts the model, instead of calling it a plain SBOM and reporting one component fewer than the scan's own page.

- Table headers stay on one line. Korean text breaks between any two characters, so a two-character header in a narrow column stacked itself vertically.

- Rows keep an even height. A component carrying many licences wrapped its badges over several lines; the first few are shown now, with the rest folded into a count that the expanded row already spells out in full.

### Added

- The name column stays in place while the table scrolls sideways, so a wide table can be read across without losing the row.

- Columns can be hidden from a menu, and the choice is remembered in the browser for next time — the same local storage the theme and the language already use.

- The overview names the components carrying the most risk and links into what put them there, instead of stopping at a count. It states how many affected components sit behind the list, and is absent when nothing carries a vulnerability.

- The comparison with the previous scan of the same project moves from a line of text into a card, and the scan list carries it too: the change in component count and the direction of the worst severity, on the rows that have an earlier run to compare against.

- Empty sections say why they are empty. A vulnerability list that ran and found nothing now reads differently from one that was never produced — the second says so, because an empty section is not the same as a clean result.

### Changed

- The components toolbar is a single row: search, the type and licence filters, the filter and column menus, the export button, and the row count. The state toggles moved into the filter menu, and the ones that are on appear as removable chips under it.

- A truncated component list says how many rows it is showing rather than only that it was truncated.

## [v1.11.0] - 2026-08-15

The web UI is the headline. A scan result was already thorough; this release is
about what a reader can do with one — reach it by keyboard, narrow it and send
someone the link, take a filtered list into a spreadsheet, and read the source
it was built from. Alongside that, an AI model file can now be scanned directly
from disk rather than only by HuggingFace id.

Three accessibility defects are fixed rather than added to: a progress bar that
announced nothing, and two labels rendering under the contrast minimum.

### Changed

- The Components and Vulnerabilities sections link to each other. A component's expanded detail opens the vulnerability list filtered to that component, and a vulnerability's detail opens the component list filtered to its package. Moving between the two lists meant retyping the name into the other section's search box. The links sit in the expanded detail because each table row is itself the expand control, and a control nested inside a control is not announced reliably by screen readers.

- The source viewer highlights what it is showing. A scanned file was rendered as numbered plain text, which is readable but says nothing about what is code and what is a comment. Grammars load only when a file that has one is opened, so a session that never opens a file carries none of them, and a file with no grammar — a licence, a binary, an unfamiliar extension — is shown as plain text rather than guessed at.

- Severity labels read from design tokens rather than colours written into the badge component. The five severity badges and the muted one each carried a light shade and a dark one as palette classes, kept in step by hand; the colours are unchanged, but they now live where every other colour in the app lives.

- The top bar has a help menu: documentation, the live demo, and the version that is running. Every link out of the app was inside a scan form before, so getting to the docs meant starting a scan first. The version comes from the running image; a local build that carries no version stamp says so rather than showing a blank.

- Korean text in the web UI is set in Pretendard, bundled with the app. It fell back to whatever the operating system supplied — Apple SD Gothic on macOS, Malgun Gothic on Windows — so a Korean screen looked different on each platform and its letterforms did not line up with the Latin text beside them. Latin still uses Inter; Korean falls through to Pretendard, which is drawn to match it. The face is split across unicode ranges, so a screen loads the ranges it actually shows.

- The Components and Vulnerabilities lists export to CSV, carrying whatever the table is currently showing rather than everything. Getting a filtered list into a spreadsheet meant copying rows out of the browser by hand. The file is written in the browser, so nothing about the scan leaves the machine, and it opens with the right characters in Excel.

- The dependency graph has zoom, fit-to-view and save-as-PNG controls. It could only be driven by a trackpad gesture before, which left a mouse or keyboard user with no way to change what was in view.

- Collapsible sections show that they can be opened. The conformance crosswalk row and its "Met with:" and "Example:" toggles were bare text with no chevron, so the way to see which requirements a count stood for was to guess that the label was clickable. Every folding surface in the app now carries the same turning chevron.

- Sections with nothing to show say so the same way everywhere. The dependency graph's "no relationships" and "too large" notes, its error, and the empty artifacts list were bare paragraphs while the rest of the app used a shared empty state.

- A file can be dropped onto the upload sources instead of picked through a dialog, and the upload reports how far along it is. The field was a bare file input: the firmware images and model weights these sources take run to gigabytes, and once the run started there was nothing on screen to say whether anything was moving. The chosen file now shows its name and size with a way to replace or remove it, and a percentage while it uploads.

- The progress bar reports its position to screen readers. It was rendered without its value reaching the underlying control, so it moved on screen while announcing nothing — this affected the scan progress bar as well.

- A narrowed table is somewhere you can return to. Filtering, searching or sorting the Components, Vulnerabilities or Licenses list writes that state into the URL, so reloading keeps it and the address can be handed to someone else as a link to exactly that view — "the critical CVEs in this scan" rather than "open this scan, then filter". The filters were held in memory before, so a reload dropped them and there was no way to point at a filtered view at all. Typing in a search box replaces the address rather than pushing it, which keeps the Back button meaning the previous screen instead of the previous keystroke.

- The global search takes Cmd/Ctrl+K from anywhere in the app and shows that shortcut in the box, and its results walk with the arrow keys. Reaching the search needed a mouse or a long tab sequence, and the result list could only be clicked: it carried a listbox role but no options to move between, so a keyboard user could type a query and then have nowhere to go. The list follows the ARIA combobox pattern now — focus stays in the input and the active result is named by `aria-activedescendant` — with Home and End for either end, Escape to close, and Enter still taking the first result when nothing is active.

- The fixed-version column reads in a darker green. The previous shade measured 3.77:1 against the light background, below the 4.5:1 minimum.

- The model integrity check reads in the same green as every other success mark. It used a shade that measured 3.77:1 on the light background, under the 4.5:1 minimum, and carried no dark-mode pair at all, so it stayed dark green against the near-black canvas.

- Deleting a scan asks for confirmation first, naming the scan it is about to remove. The delete control in the scan table and the one in the top bar's scan menu both removed a scan's output folder on a single click, and because the files are gone from disk with no copy kept, a mis-click could not be taken back. The prompt opens on Cancel, and a confirmed delete says so. Modal dialogs also hold the keyboard now: focus moves into the panel when one opens, Tab stays inside it, and it returns to whatever opened the dialog on close.

### Added

- A scanned AI model file is checked for whether loading it runs code. Pickle-format weights (`.pkl`, and the pickle inside a PyTorch archive or an `object`-dtype `.npz` member) are analyzed with picklescan, now installed in the base image, and the verdict feeds the file-security axis of the model risk assessment: a dangerous global reads `caution`, globals that need a human reads `review`, and a format that cannot execute code on load reads `ok`. BomLens reported this for models on HuggingFace by reading the Hub's own scan; a file that was never published had no such record and therefore no verdict at all. A clean result states its scope — it is a pickle analysis, not a malware scan — and a scan that could not run leaves no security axis rather than implying the file is safe.

- An AI model file can be scanned directly: `--model-file <path>` on the CLI, or the Model file tile in the web UI (up to 8 GB). The file's own header is read — GGUF, safetensors, PyTorch, pickle, npz, npy and ONNX are recognized by their magic bytes rather than their extension — and the result is the same CycloneDX 1.7 ML-BOM, with the same G7 conformance check and risk assessment, produced offline in the base image. Until now an AI SBOM required a HuggingFace model id, which left out weights a supplier delivers, internal models that were never published, and machines with no network. What each format can fill differs and is reported as such: GGUF declares a name, a license and an architecture, safetensors usually declares only tensor shapes, and a field the file does not carry is left empty rather than guessed. Every format contributes a SHA-256 over the whole file.

## [v1.10.5] - 2026-08-12

### Changed

Three changes alter what an AI-model scan writes, so a consumer of those artifacts sees different output than it did on v1.10.4. They are corrections rather than new behaviour, which is why this is a patch, but they are listed first because a tool reading the output has to know.

- The model is the subject of the ML-BOM. It moves to `metadata.component`, where CycloneDX names what a document describes, and the datasets it references stay under `components[]`. The generator had put its own scan job (`job-<timestamp>`) at the subject and left the model in the component list, so the document stated that it described a generator run. A tool that looked for the model in `components[]` has to look at the subject instead.

- The conformance report distinguishes a check with nothing to judge from one that is unmet. Such a check carries `naKind: "not-applicable"` in the JSON and leaves both sides of every coverage fraction, so the denominators move: an SBOM whose only subject is a model no longer collects format checks for having no packages to measure. Reports and the web UI label the state separately and count it on its own line.

- A model card whose license is `other` now carries the license the card declares, as a license name with a link to the file, rather than an SPDX identifier.

- Updated cdxgen to 12.8.3, which carries the BSD license-name correction from v1.10.4 in its own data: `0BSD` now covers only "Zero-Clause BSD", and "new BSD" resolves to `BSD-3-Clause`. BomLens still corrects the tables before a scan, because the sibling images pinned to an earlier cdxgen release ship the old ones. Running the correction against the 12.8.3 tables leaves both files byte-identical.

### Fixed

- A dataset a model card declares carries the repository owner as its producer. The owner was recorded only inside `componentData.governance`, which the conformance checks do not read, so every dataset arrived without one. The effect ran backwards: a card that declared its training data added a component per dataset with no producer and scored lower on the 2026 minimum elements than a card that declared none.

- The license of a model card tagged `other` is no longer guessed from the LICENSE text. With no identifier to copy, the generator matched its mapping table against the file body as a substring, and `mit` matches the `limited`, `submit` and `submitted` that ordinary license prose contains — an Apache-2.0-derived custom license was emitted as MIT, dropping the obligations the real terms carry. The discarded value is kept as a property so the correction is traceable.

- Dataset names scraped out of a model card's prose no longer count as declared training data. The generator fills `modelCard.modelParameters.datasets` from the card text, so a sentence reading "pretrained on approximately 12.5 trillion tokens" left a dataset named `approximately`, and a footnote left `only`; neither is a repository. A name survives when the card frontmatter declares it or the datasets API resolves it, and what was dropped is recorded on the model.

- An AI SBOM that follows the CycloneDX shape — a supplier submission, or a hand-written one, naming the model as the document's subject — is analyzed as an AI SBOM. Every model lookup expected the generator's layout, so such a document fell through all of them and was treated as ordinary software: no G7 minimum-element checks, no model risk assessment, no AI compliance profile.

- A dependency-graph check no longer fails a document that has no parts to relate, and the stale dependency root the generator emitted — keyed on an identifier nothing in the document defines — is folded into the model's own entry. A document that does have parts and no edges still fails.

- An SPDX document with no packages reports its name+version and PURL coverage as not-applicable, the way a CycloneDX document with no components does. Both checks had stayed "met" on an empty denominator, so a document that named nothing counted toward coverage on one format but not the other.

- A model card that publishes an evaluation table can satisfy the operational-KPI element. The check read its own path over `components[]`, which is the one place the model no longer sits now that it is the subject of its own ML-BOM, so no card could meet it.

- A Python component's license and version come from the installed distribution's own metadata, read through `importlib`, rather than from a filesystem guess at the `.dist-info` directory name.

## [v1.10.4] - 2026-08-10

### Fixed

- A BSD-3-Clause component is no longer reported as 0BSD. The two license-name tables the SBOM generator resolves against both mapped the generic BSD names — "BSD", "BSD License", "new BSD" — onto 0BSD, a license that carries no conditions at all, so components that require the copyright notice and license text to be shipped came out requiring nothing, and the notice generated from them left that attribution out. PyPI files every BSD variant under the single classifier "BSD License", which put most Python projects in reach of this; Maven poms naming "New BSD License" put Java ones there too. The tables are corrected before generation runs, which is the only point where the original name still exists — once the SBOM is written, a mislabelled component is indistinguishable from one that really is 0BSD. "new BSD" now resolves to BSD-3-Clause. "BSD" and "BSD License" resolve to nothing: the clause count cannot be known from those strings, so they reach the SBOM as a license name for a person to settle rather than as a wrong identifier.

- A Python component's license is settled on the installed distribution's own metadata — its PEP 639 license expression, the license text it ships, then its declared license name, in that order — rather than on the summary PyPI serves. That summary's license field increasingly holds the entire license text, which the generator scanned for the first license name it recognised: numpy and pandas were reported as Apache-2.0, off a bundled-dependency notice inside a BSD-3-Clause file. Evidence that settles on more than one answer, as a genuinely dual-licensed component does, keeps the upstream value for a person to read. Where a license was settled this way, the component records what settled it.

- The notice marks a license group whose name is not an SPDX identifier — "BSD License", "Dual License" — as unverified, instead of printing prose where a license belongs.

## [v1.10.3] - 2026-08-08

### Added

- The regulatory crosswalk's framework row opens to the requirements it counted. The table stated four numbers per framework and left the reader to work out which requirement each one was; the rows were already in the payload and nothing read them.

- A conformance element that is already met is one line. Its description and the values that satisfied it are folded away rather than dropped, because a reader who has just been told the element is met is not reading either again. Measured on an AI SBOM, the section went from 12,999 to 11,379 pixels — the elements that need attention had been sharing the page with forty that did not.

- The conformance screen leads with what blocks the SBOM. A line at the top says how many mandatory checks failed, how many advisory elements are short, and how many need a person, and the mandatory checks themselves now come first — they used to sit below every advisory row, which on an AI SBOM meant the bottom of a page twelve thousand pixels long. The rail badge counts the mandatory checks too, so it means the same thing on every scan instead of showing AI coverage on one and every-check passes on another.

- The 2026 SBOM minimum elements are their own block on that screen, grouped the way the guidance groups them, and their rows carry what the AI elements have carried all along: how the value was established, the fragment that would satisfy it, and — for the elements no scan can settle — what a person has to check. They had been rendering as three bare lines in the middle of the format list, because a row only did any of that for elements whose id began "g7-". Each of the 23 elements also has a plain-language description of what it is and what would satisfy it, in English and Korean.

### Fixed

- The regulatory crosswalk no longer reports failures as advisories. The table showed four counts and derived one of them as the remainder of the other three, which is the failure count; it was labelled "advisory", so the most serious category appeared under the mildest name on the page.

- The conformance report's regulatory crosswalk states how many requirements an SBOM fails, as its own column. The table carried present, gap and review, so a failure fell outside all three and the columns did not add up to the total. The four counts now account for every mapped requirement, and a regression test holds them to it.

- The conformance report explains what a person still has to check, and does so in the markdown as well as the HTML. The signing this tool offers is detached — the signature is a file beside the SBOM — and a report that reads one file cannot see it, so that row now says as much instead of reading as unsigned. A signature carried inside the document is still read and credited. The same notes cover the four practices no scan can settle: whether the SBOM covers everything, how corrections are issued, how it reaches the people who need it, and how often it is reissued.

- A binary or firmware SBOM now records the hash of the file that was scanned, on the component the SBOM is about. A recipient can hash their copy and tell whether it is the copy the SBOM describes. Scans with no single artifact — a source tree, a container image, an installed OS package spread across a root filesystem — record no hash rather than one computed over something that is not the artifact.

- The conformance report measures the target component alongside the components enumerated under it. The 2026 minimum elements describe their data fields over both, and measuring only the enumerated ones let an unidentified root pass without mention. The component hash algorithm is now checked against the recognized algorithm names rather than only for being non-empty, since a digest labelled with something unrecognized cannot be recomputed.

- A generated SBOM now states why a field is empty when it is empty. The 2026 minimum elements ask an author to distinguish a value they could not establish from one they are withholding, and a scan only ever produces the first — it writes what it managed to read and has no second set of findings to hold back. The statement is made once for the document rather than repeated on every empty field, which on a firmware image would mean thousands of properties saying the same thing. The conformance element that asks for it is measured automatically now instead of being left to a human reader, so a received SBOM that says nothing about its absences is reported as a gap.

- A component whose version the scan could not establish is no longer counted twice. Such a component is already marked as present with its version unestablished, and that marking is exactly the statement the minimum elements ask for, so the component-version element reads it instead of listing the component as missing the field.

- The conformance report now measures an SBOM against the 2026 SBOM minimum elements — 17 data fields and 6 practices, published by CISA, the NSA and the FBI with fifteen international partners including Germany's BSI, Japan's METI and Korea's KISA, replacing the NTIA elements of 2021. Every CycloneDX SBOM is measured, not only AI ones. The elements are advisory and none of them changes the pass or fail verdict, which stays with the submission criteria. Five of the six practices describe how an organisation operates rather than what a document contains, so they are surfaced as needing human review instead of being scored or quietly dropped.

- What counts as identifying a component is wider under this baseline than under the submission criteria: a PURL, a CPE, or an intrinsic identifier such as a hash. A firmware file entry that carries only a hash is identified here even though the submission criteria still ask for a PURL, so the report can say both things at once instead of only the stricter one.

- The regulatory crosswalk's US baseline was rewritten for the 2026 document. It previously mapped the 2021 elements onto the format checks; those mappings moved to the new elements, so a requirement is counted once rather than once per row.

- Every generated SBOM now records at which lifecycle phase it was produced, and with which tool at which version. A scan that reads source manifests is marked `pre-build` and one that reads a built artifact — an image, a binary, a firmware image, a root filesystem, a model — is marked `post-build`, which is the distinction a reader needs to know what the component data can mean. BomLens names itself among the tools that produced the document, alongside the scanners it drove, and a tool whose version was not recorded now says so instead of leaving the field empty. A merged SBOM claims no phase, because its inputs may each have had a different one.

- `--sbom-author` (or `SBOM_AUTHOR`) records the organisation or person that generated the SBOM. This is the entity running the scan, which is neither the tool nor the author of the software being scanned, and nothing in a scan can discover it. Left unset, the field is omitted rather than filled with a placeholder — and the generator's own default, which named the SBOM tool's publisher as the document's author, is no longer carried through.

### Fixed

- A binary or firmware SBOM is no longer marked short on fields its file entries cannot carry. Such a scan lists the delivered files alongside the packages it identified, and a file on disk has no package version and no PURL type, yet every one of them sat in the denominator of the name/version and PURL coverage checks. A firmware image whose packages were all identified reported 10% PURL coverage on that basis, and a binary reported 39 of 415 components named. Measured over the packages alone, the same two SBOMs report 18% and 39 of 39. Files are still expected to be identified, by the identifier they do carry: a new recommended check reports how many of them have a hash, and names the ones that do not.

- An SBOM whose only components are files now fails instead of passing. Once file entries stopped counting toward package coverage, a scan that recovered nothing but a file listing had an empty denominator and was reported as fully covered — the checks would have certified an SBOM that identified no package, which is what the submission criteria are asking about. An SBOM with no components at all, or one whose components are all datasets, is unaffected and reports no coverage complaint, as before.

## [v1.10.2] - 2026-08-05

### Added

- A desktop application's codec plugins now yield the libraries linked into them. A player ships each codec as a plugin that links the library statically, so the library is not a file of its own and nothing catalogs it — but the library stamps its own name and version into the plugin. Four such stamps are read now: a subtitle codec, a Dirac codec, the Theora reference library, and the runtime compiler the Dirac plugin carries inside it. Only the Theora entry carries a vulnerability identifier; the other three name products that exist in the vulnerability index as something else entirely, and attaching those would hand a codec another project's advisories.

### Fixed

- A firmware image shipped as a zip can now be uploaded through the web UI. Vendors commonly distribute firmware that way and the CLI has always unpacked it, but the upload form refused the extension while accepting every other compressed form, so a scan the CLI could run had no path through the UI at all.

- A component whose release could not be read is no longer reported as if its version were known. The scanner writes `UNKNOWN` in that case — a kernel module with no version in its metadata, a Go binary built without module information — and carrying it through made the conformance report count those components as versioned. The field is removed now and the component is marked as present with its version not established. On one switch OS this moves 3,581 components out of the "version known" count, where they never belonged. Which components are reported, and which vulnerabilities, is unchanged.

- A firmware SBOM now carries the dependency graph. What each installed package depends on is read out of the package database, but the step that assembles the SBOM from several identification passes took only the components, so the graph was dropped and the conformance report failed its transitive-dependency row on every firmware scan. References are followed to the record that survived the merge, and an edge whose endpoint did not survive is dropped rather than left pointing at nothing. The SPDX export carries it too.

## [v1.10.1] - 2026-08-04

### Added

- Firmware analysis opens more of what an image carries. Besides a container image store, a second filesystem with its own package database and an interpreter's installed library set are now cataloged when they sit beside the root filesystem rather than inside it. Each is recognized by the record of what is installed in it, not by a directory name. Set `FW_EXTRA_ROOTS=false` to read only the root filesystem.

- The frameworks an iOS app ships are now identified. A package holds one bundle per framework, each stating its name and version, and those are read as components. A framework that is the app's own code split into a bundle is marked with `bomlens:appOwnedFramework` rather than dropped, because the identifier that decides it is written by hand and can be spelled in a way the rule misses. No package identifier is written, since nothing in the bundle says which ecosystem the framework came from.

- An Android or iOS app package is now unpacked and read instead of being treated as one file, and the libraries an Android app declares about itself are identified. Gradle records each library that ships in the package under `META-INF`, one file per library holding its version, which gives a Maven coordinate the vulnerability step can use. Pass the `.apk` or `.ipa` as the target; the opt-in firmware image does the unpacking, and without it the scan says so.

### Fixed

- The conformance report no longer calls a package identifier without a version malformed. The version is optional in the identifier format, so a syntax check has nothing to say about a missing one, and two other rows already report it — one as a required failure, one as a warning that the identifier cannot be traced. A firmware image whose kernel modules carry versionless identifiers was failing a syntax row that had nothing to do with syntax.

- An SPDX export of a firmware scan now carries the container images the device holds and the distribution it runs. The converter writes a package only for what it counts as software, so both were absent, and so was the record of which container each package belongs to. They are packages in the SPDX file now, and the membership is a `CONTAINS` relationship. Which software the two formats list is unchanged.

- Packages installed inside a container carried by a firmware image are now matched against vulnerability data. A package database read out of a container layer gives a name and a version but no package identifier, because the identifier depends on which distribution the container runs and that is recorded inside the layer rather than at the root of what was scanned. The distribution is now read from the layer and the identifier written from it, including the source package the advisories are keyed on. Which components a scan reports is unchanged.

- A scan that cannot reach the upload server now says so and keeps its artifacts. It used to end on the transport's own exit code with nothing but a warning, which read as a failed scan even though every file had been written. The message names the server and says how to scan without uploading. A reply that carries no status code is reported the same way instead of ending the run mid-comparison.

## [v1.10.0] - 2026-08-03

### Added

- Yocto builds are analysed from the build directory itself, not only from an SPDX file handed over separately. The CLI takes the directory, the web UI recognizes one picked in the browser, and an uploaded SPDX archive is accepted. Where a build published no usable SPDX 3.0, the SPDX 2.x manifests it deploys are read instead.
- A firmware image's container image store is now catalogued. When the store sits beside the root filesystem rather than inside it — the usual layout on a switch OS, where most of what runs is in a container — its packages reach the SBOM, and each one records the container image and layer it came from. The images themselves appear as `container` components. `FW_EXTRA_ROOTS=false` reads only the root filesystem.
- Components a firmware carries but does not version are now reported. A library linked into someone else's binary is read from the symbols that binary exports; a program is read from the name it is installed under; the C library filling a `libc` slot is named from the marker inside its own file; a version stamped in an RCS keyword is read; and FRRouting is told apart from the quagga it forked from. Each judgement records the evidence behind it, and a component with no version recovered is marked as such so a clean vulnerability result is not read as covering it.
- Components that are known-malicious packages are flagged separately from vulnerabilities, since the response is removal and credential rotation rather than an upgrade. The check runs offline from a bundled snapshot of the advisories OSV publishes and matches by PURL only. `ENRICH_MALICIOUS=false` skips it. Each flag records the advisory id and the snapshot date.
- Dependencies are checked against the licence the project itself ships under, so a combination that cannot legally ship is visible before delivery. Declare it with `--license <spdx-id>` or `PROJECT_LICENSE`; every component gains a verdict with the reasoning recorded, and the risk report and the web UI list the clashes. Advisory only — nothing is stamped when no outbound licence is declared, and an absent verdict means "not assessed".
- The web UI accepts a build artifact where it previously accepted only source: `.jar`, `.war`, `.ear`, `.deb`, `.rpm` and `.whl`. A supplier who cannot hand over a source tree can often hand over what they ship.
- The result screens show what a scan looked at. The Source tree section pairs the file list with the file itself, for source trees, directory and rootfs scans, firmware, container images and archives. The capture is bounded — text only, per-file and total size caps — and says what it left out and why.
- A scan of someone else's SBOM now describes that document: its format and spec version, name and identifier, creation time, producing tool and the supplier it names, read before conversion. Fields the supplier left empty are omitted rather than shown blank.
- The Overview says what was scanned, and the left rail names the way out of a scan.
- Firmware analysis, AI-model SBOMs and deep CVE matching each need their own image, and the web UI and desktop app now offer to download it before the feature is used, with the download size and a count of the layers done. An unpulled image is still fetched on first use, and that download reports layer counts too.
- Installers are unpacked instead of read as a single file: `.exe`, `.msi` and `.dmg`, in the CLI and as a web-UI upload. What such a file carries is inside it, so the components were not visible before. Unpacking uses the opt-in firmware image; without it the file is read as before and the scan says what it looked at and what unpacking needs.
- Kernel advisories are matched. The bundled CPE index now also carries the Linux kernel, which every root filesystem holds. They are reported apart from the severity figures and in a list of their own, because a kernel accumulates thousands of advisories and most concern subsystems a given device never built.
- OS-context synthesis covers Debian/Ubuntu and Alpine packages as well as rpm, so OS packages in a supplier SBOM or rootfs scan get distro vulnerability matches.
- The documentation site's demo covers a container image, an AI model and a firmware image.

### Changed

- Vulnerability severity grades and licence classification names stay in English on the Korean UI and in the Korean report. They are the vocabulary of the advisory and of the classification itself, the generated reports already printed them untranslated, and the screen and the report now agree. The surrounding Korean is unchanged.
- Every distribution ships this project's own LICENSE and NOTICE, and the web UI reproduces the notices of the npm packages it bundles.
- The Android SDK images are no longer published, because publishing them redistributed the SDK. Build one locally, or point `ANDROID_IMAGE_PREFIX` at an image built elsewhere; the images published up to v1.9.0 are left in place so released versions keep working.

### Fixed

- Firmware unpacking reaches images it previously walked past: a filesystem image that was carved out but never extracted, a vendor squashfs whose magic is byte-swapped, an extraction that aborted on extended attributes, a Windows installer, and an image whose text carries one byte that will not decode. An archive is routed by what it holds rather than by its extension, and an empty result now says which of the possible reasons it was.
- A firmware image that nests bundled sub-packages is read from the real root filesystem rather than from whichever candidate the filesystem happened to list first, which was neither depth order nor stable between machines.
- Firmware identification no longer reports the same component twice, no longer carries an identifier built out of a kernel module's own name, and lets a versionless judgement yield to a versioned one even when the two spell the name differently. The caps whose warnings tell you to raise them now actually reach the scan.
- The NOTICE lists what a notice is for. A firmware's kernel modules fold into one line per licence naming their count and their kernel, and the file entries a scan records as inventory fold the same way instead of appearing as components with no attribution beneath them.
- A source scan no longer modifies the project it scans. Files the resolvers own are snapshotted and put back, and build directories that were not there before are removed; nothing that already existed is deleted, and the restore runs on an aborted scan too. `BOMLENS_KEEP_BUILD_OUTPUT=1` keeps the resolved tree. The generated SBOM is no longer written into the scanned tree first.
- Web UI corrections: the licence list is back in the Licenses section, the rail no longer clips "SBOM conformance", a scan is typed by what it scanned rather than by its SBOM's root, the risk colour tokens work with an opacity modifier, the licence distribution tint is softer, the regulatory crosswalk shows its advisory count, the result subtitle drops a redundant word, and the demo's install link follows the UI language.
- A CPE upstream-version pattern was wrong, and the message about a PURL failure now says when the components carry a CPE instead. The unpack path no longer leaks into firmware component names, and zstd's broken-pipe noise stays out of the scan log.
- The demo bundle and the release assets no longer publish the contents of other people's files or the scratch directories a build leaves behind.
- `--help` no longer runs a command while printing its own text, and the words it dropped are back.
- Vulnerability matching by CPE covers every component that carries one, not just those the signature pass identified, and reaches the components a purl cannot serve. Version comparison is stricter: release prefixes such as `go1.25.6` and `v0.37.0` are read as the numbers they are, and a value that cannot be compared as a version no longer satisfies every advisory bound.

## [v1.9.0] - 2026-07-25

### Added

- `--model` scans now carry a risk assessment beside the inventory: each model and dataset is given a usability verdict — `ok`, `conditional`, `caution` or `review` — so a development team can tell at a glance whether a HuggingFace model is usable and under what conditions. Three axes feed the verdict. The license axis matches every HuggingFace license tag against a curated terms registry (`docker/lib/ai-risk-knowledge.json`) that records whether commercial use, redistribution and derivatives are allowed, the conditions that apply, and a link to the license text; a `license: other` model has its LICENSE file read and any restrictive wording quoted verbatim, and a fine-tune whose declared license conflicts with an inheritable base-model license (Llama, Gemma, the RAIL family, non-commercial CC) is flagged. The file-security axis reads HuggingFace's own per-file scan results (ClamAV and picklescan) over the metadata API without downloading a weight, and records whether the weights use a pickle-format that can execute code on load. The datasets axis rolls up each referenced dataset's license and its declared risk markers (personal data, access-restricted repositories). `--usage internal|product|redistribute|outputs-only` tailors the verdict to how the model will actually be used, so only the conditions that bind that scenario decide it. The verdicts are stamped into the SBOM as `bomlens:assessment:*` properties, summarized in the AI compliance profile and shown as grade badges in the web UI, always with the note that the assessment is guidance, not legal advice. An unrecognized license always falls to `review`, never a guess. (#473, #474, #475, #476, #478, #479)
- The conformance report now maps every SBOM — not only AI ones — to the EU Cyber Resilience Act (through BSI TR-03183-2) and the NTIA minimum SBOM elements, so a plain software SBOM shows which baseline documentation elements it already satisfies. Reference only; it does not certify compliance. (#462)
- An AI model card names its training datasets and stops there. BomLens now resolves each id against the HuggingFace datasets API into its own CycloneDX `data` component — the declared license, content digests and upstream provenance — linked to the model as a dependency, which is what the G7 dataset cluster asks for and what a provider writes an EU AI Act training-content summary from. A dataset that cannot be read (withdrawn, renamed, or private to someone else) is kept with an explicit unresolved marker rather than a fabricated license. (#456)
- The AI compliance profile's rollup — G7 status by cluster, the regulatory crosswalk and the licenses flagged for review — now opens the conformance report itself, so the two artifacts no longer restate each other; the standalone AI-profile HTML is gone while the JSON and Markdown digests remain. (#455)
- The conformance HTML report was reworked to be read at a glance: numbered rows, a distinct colour for review-only elements, each requirement's regulatory provisions carried on its own row, and the fill-in guidance shown inline per row instead of in a separate section. The web UI conformance section is labelled "SBOM conformance" and states that a single mandatory-format failure — not an advisory G7 gap — is what fails an SBOM. (#454, #463)
- The conformance and AI compliance profile reports render in Korean with `--lang ko` (`REPORT_LANG=ko`); the machine-readable JSON stays English as a contract. (#447)
- The open-source risk report (`_risk-report.md`/`.html`) now renders in English by default and in Korean with `--lang ko`, matching the conformance and AI-profile reports. A global user no longer receives a Korean-only risk report, and the model risk assessment disclaimer prints in both languages.
- `--deep-cve` recovers NVD-only Maven CVEs that Trivy misses for older Java libraries, matching by CPE with grype in an opt-in `bomlens-deep-cve` image pulled on demand. Findings not verified against the live NVD version range are flagged version-unverified in the report. The web UI offers the same deep CVE matching for an uploaded SBOM. (#465, #472)
- A supplier SBOM that lists every rpm/deb package but omits the operating-system component now gets one synthesized from the dominant distro PURL, so Trivy can select the right advisory database instead of returning zero findings for valid PURLs. Skipped for AI SBOMs; disable with `ENRICH_OS_CONTEXT=false`. (#464)
- Supplier SBOM analysis (`--analyze`) now accepts UTF-16 and BOM-prefixed files and SPDX 3.0 JSON-LD, so an SBOM exported by a tool that writes those parses instead of failing. (#468)
- The Windows launchers (`sbom-ui.bat`, `check-setup.bat`) now speak English as well as Korean, following the same rule as the desktop app: `SBOM_LANG` wins, otherwise the Windows display language, and anything that is not Korean gets English. This also removes the boxes-instead-of-text problem on a Japanese console, where the font has no Hangul glyphs and no codepage can help.
- `bomlens.settings.example.txt`: environment variables do not survive a double-click, so `UI_PORT`, `SBOM_LANG`, `SBOM_PULL`, `SBOM_IMAGE_TAR`, `SBOM_SCANNER_IMAGE`, `SBOM_OUTPUT_DIR` and `SBOM_UI_MOUNT_DIR` are now also read from a text file beside the scripts (or `%USERPROFILE%\.bomlens\settings.txt`). A real environment variable still wins.
- Offline install: `SBOM_IMAGE_TAR` loads a `docker save` tar instead of pulling, and a `bomlens-image.tar` next to the scripts is picked up automatically. With `SBOM_PULL=never` the launcher never touches the network — a USB stick with the `.bat` and the `.tar` needs no registry, no command line and no proxy setup. `SBOM_PULL=always` refreshes a cached `:latest`, which previously stayed pinned forever once pulled.
- `sbom-ui.bat` picks a free port instead of failing: a busy **or Hyper-V/WSL-reserved** port now moves to the next free one. The reserved-range case was the common false green light — nothing is listening, yet Docker still cannot bind.
- The desktop app shows aggregate pull progress (layers complete, elapsed time) with a heartbeat, so the multi-GB first download no longer looks frozen during the long silent stretches, and both start screens gained an "Open log folder" button so a failing user can hand over `startup.log`.
- Pull failures are now classified (proxy, DNS, auth, disk, timeout) and the screen explains the actual fix. The proxy text states the thing that trips people up: the image is fetched by the Docker daemon, so setting proxy variables for the app has no effect.

### Changed

- Updated cdxgen to 12.8.0 and syft to 1.48.0. (#432, #433)
- Documentation: the AI model guide gained a worked conformance example with openable sample reports and now covers the model risk assessment, `--deep-cve` and the generalized regulatory crosswalk are documented, the architecture and pipeline diagrams were redrawn as authored SVG legible at page width, and the getting-started pages and environment-variable reference were synced across English and Korean. (#443, #445, #446, #448, #449, #469, #470, #471, #477, #481)

### Fixed

- Web UI / desktop firmware and AI-model scans no longer report failure after generating every artifact. These run as a sibling container, which inherited the entrypoint's upload-on default and then exited with "API_KEY and API_URL are required" because no credentials were forwarded — so the scan stream reported `ok:false` despite a complete result set. The sibling is now told generate-only by default (matching the in-process path); when an upload is configured, the destination is forwarded with the API key by name only, keeping it off the argv.
- `--identify-vendored` (SCANOSS) no longer reports a false "no vendored open source found" when the search response could not be processed. One malformed record in the remote response (a `purl` returned as a string) aborted the whole transform, discarding every genuine match and labelling the result "no-match"; the fields are now guarded and an unprocessable response reports "search didn't complete" so the user retries.
- `--sign` now fails loudly instead of exiting 0 when cosign cannot produce a signature (wrong or encrypted key), rather than leaving the user to believe an unsigned SBOM is signed.
- Firmware unpackers (unblob, BANG, unsquashfs, binwalk) run under a wall-clock `timeout` (`FW_UNPACK_TIMEOUT`, default 900s) so a decompression-bomb or malformed image cannot hang the scan; firmware input is attacker-supplied.
- The CLI forwards `API_KEY`, `SCANOSS_API_KEY` and `COSIGN_PASSWORD` to the container by name only, so a scan secret no longer sits on the `docker run` argv where a local `ps` could read it — matching the web-server path.
- The web UI no longer hangs or breaks its recent-scans list on a malformed uploaded SBOM. A supplier SBOM (the untrusted ANALYZE input) with a non-object component — or a component whose `properties`/`licenses` is not a list — made the result-summary raise, so the scan never reported completion and one poisoned scan folder crashed the whole recent-scans sidebar. Malformed component entries are now skipped, valid ones still summarize, and the scan stream always terminates. The uploaded docker-image reference is validated like every other scan target, and the tarball-upload guard now also rejects a symlink member whose target escapes the extraction directory.
- The AI model risk assessment badges read consistently: the `ok` grade now uses the same visual weight as the other grade badges, so the risk colour draws the eye rather than a solid-green "ok" outshouting a "caution" beside it.
- `THIRD_PARTY_LICENSES.md` now attributes grype and the `bomlens-deep-cve` opt-in image (Apache-2.0) added for `--deep-cve`, which had shipped without an entry.
- The downloadable CLI bundles (`bomlens-cli-linux.tar.gz`, `bomlens-cli-windows.zip`) now carry the host-side files `scan-sbom.sh` needs — `docker/lib/source-detect.sh` (sourced on the host) and `build-prep.sh` — so an extracted bundle runs standalone. A bundle was previously missing `source-detect.sh`, so even `scan-sbom.sh --help` exited before any scan; the release build now extracts each bundle and runs it as a gate so this class of packaging gap cannot ship again.
- Conformance no longer fails PURL coverage when there is nothing to measure. An SBOM whose only components are datasets (no packages) counted an empty denominator as 0% and failed an otherwise complete AI SBOM. (#457)
- The first-run download figure is now the measured one. Every surface said the scanner image is "about 3-4 GB", which is its uncompressed size on disk rather than what is transferred: the registry manifest puts the actual download at about 250 MB. The launchers, the desktop app and the docs now say 250 MB, and they add the part that was missing — the first scan of a project fetches a language image as well (0.6-1.7 GB, once per language). The AI model guide's comparison figure was corrected the same way (3.5 GB to download).
- Container start failures no longer leak Korean strings into the English UI. `lib/container.mjs` threw hardcoded Korean text that bypassed i18n, so an ordinary port conflict or start timeout produced `Startup failed: docker run 실패: ...` for a non-Korean user. Errors now carry a code that `i18n.mjs` translates, and a test asserts no Hangul in the English dictionary.
- `sbom-ui.bat` no longer closes its window silently. Any failure after the Docker check — port conflict, bad mount, container crash — used to vanish instantly with no message; every path now explains itself and holds the window, and the container exit code is reported.
- A stopped Docker engine is no longer reported as "Docker is not installed" by the Windows launchers, which sent users off to reinstall Docker they already had.
- `SBOM_UI_MOUNT_DIR` handling: a trailing backslash mangled the whole `-v` argument, and a path containing `&` was executed as a command rather than printed. Trailing separators are stripped and unsafe paths are rejected with an explanation.
- No timeouts existed on the desktop app's Docker calls, so a wedged daemon or a firewalled registry hung on a live-looking window forever. Status checks are now bounded and the pull aborts when it genuinely stops making progress (a stall timeout, not an absolute one, so a slow but healthy download is not killed).
- The desktop app falls back to known Docker install paths when `docker` is missing from `PATH`. Installing Rancher Desktop without restarting Explorer left the app reporting "Docker isn't installed" while the engine ran visibly in the tray.
- `check-setup.bat` and `bomlens.settings.example.txt` now ship in the Windows release zip. The launchers' own error messages tell users to double-click `check-setup.bat`, which was not in the archive.
## [v1.8.3] - 2026-07-20

### Added

- AI-model scans can now read a private or gated HuggingFace repository. Set `HF_TOKEN` (read scope; `HUGGING_FACE_HUB_TOKEN` is accepted as an alias) and `--model` resolves repositories that are not public yet — the case that matters when you are checking your own model before publishing it. The value is passed to the container by name only, so it never appears in the process list, the SBOM, or any report. The web UI inherits the variable from the environment that launched it rather than accepting a token over HTTP, and `/capabilities` exposes only a boolean saying whether one is present. (#434)
- The conformance report now says how to close each G7 gap, not just which elements are missing. For every advisory element that has an automated source and is absent, `_conformance.md` and `.html` print the CycloneDX fragment that would satisfy it plus a link to the authoritative documentation, and `_conformance.json` carries the same under an optional `guidance` key. The guidance registry lives in `docker/lib/g7-guidance.json` (override with `G7_GUIDANCE`), keyed by element id like the regulatory crosswalk, and is the single source the web UI now reads too. Passing and review-only elements are excluded, so a well-documented model adds no section at all. The AI compliance profile lists the same gaps with their reference links and points at the conformance report for the fragments. (#435)
- Every component in the generated SBOM now carries a `bomlens:licenseClass` property with its copyleft-strength class (`network-copyleft`, `strong-copyleft`, `weak-copyleft`, `permissive`, `uncategorized`), mirroring the classification the web UI shows, and the risk report gains a per-class count table plus the network/strong-copyleft components driving the exposure. Unknown licenses are never assumed permissive. A test guard keeps the UI and scanner classifications from silently diverging. (#420)

### Fixed

- An AI-model scan whose model could not be read no longer reports success. The OWASP generator swallows a failed HuggingFace fetch, logs a warning, and fills the model card with generic defaults (`transformer`, `text-generation`, string in and out), so a `401` — or an id that does not exist at all — produced exit 0, a full artifact set, and a conformance report reading `result=pass` with 19 G7 checks satisfied, for a model nobody could open. Since that fabricated card is not empty, the existing card-present gate let it through. BomLens now inspects the generator's own log, refuses the run, deletes the output, and says the values were placeholders rather than the model; a `401` or `403` gets a hint that differs by whether a credential was supplied. A pending organizational token produces exactly this case. (#438)
- The CLI completion summary now lists the artifacts actually on disk instead of one line per requested flag, so a step that failed to deliver no longer announces a file the user does not have. Running `--spdx` or `--all` against a pre-v1.8.0 scanner image was the common case: no SPDX step exists, none runs, and the summary still named an SPDX artifact. (#425)
- `--model` no longer ships an empty security report. Both guides and the web UI state that an AI-model scan skips it because a model has no package dependencies to match CVEs against, but the CLI's risk-report defaults re-enabled security for every mode, so Trivy ran against an ML-BOM and wrote a `_security.*` set containing nothing. (#426)

### Changed

- SPDX export moved out of the New scan form and into the results. The toggle asked users to decide, before any scan ran, whether they would need SPDX later, and answering wrong meant a full rescan. A scan now always writes CycloneDX, and the SBOM card in the Artifacts section offers "Export as SPDX 2.3", which converts the finished BOM and starts the download right away; the converted file joins the artifact list and the ZIP bundle. Both paths run the same conversion helper, so the result is identical to the CLI's `--spdx`, which is unchanged along with `--all`. Signing remains CLI-only, and the button is hidden where no converter is reachable. (#439)
- The New scan form now seeds the version field with `1.0.0` when the source states no version of its own, so a first-time user who accepts the autofilled project name and presses Run no longer bounces off version validation. A version the source does carry — a docker tag, a `name-1.2.3` file, SBOM metadata — still wins, and an edit is never overwritten. (#429)
- The New scan validation summary no longer tells you to enter a project name that is already filled. Since the inline messages identify the offending fields, the line by the Run button became a neutral pointer to them, and the Korean copy lost a translationese parenthetical. (#428)
- The components table now renders large SBOMs with recycled row chunks: the whole filtered set (up to the 2,000-row server cap) is reachable by plain scrolling, offscreen rows are replaced by measured spacers so the DOM stays small, and the "Show more" button is gone. (#421)
- A failed upload or token stash on the New scan form now shows a situation-specific message (file too large, server unreachable, server error, rejected input) in both languages instead of the raw exception text; the technical detail moves to fine print. (#414)
- The nightly "macOS real scan (Colima)" job was retired: its last 19 runs all failed deterministically at Colima startup (the hosted arm64 runner boots neither the vz nor the qemu backend), so the scan never actually ran. The evidence and the re-add condition are recorded in the workflow; macOS coverage remains a maintainer-run local check. (#422)

### CI

- Example scan jobs reclaim about 25 GB of runner disk before any image work, dropping preinstalled toolchains the project never uses. The dotnet, swift and rust examples pull a language SDK image on top of the scanner image and were intermittently exhausting the runner's free space, failing with "no space left on device" before an SBOM was written. (#430)
- The Dockerfile lint (hadolint) is now blocking at error level, and the external-link check's advisory status is documented inline. (#413)
- A Korean prose style gate now lints the public docs on every PR (`scripts/ko-style/`): translation-ese patterns and the repository's terminology decisions (디렉터리/배지 spellings, 컬럼→열, 리포트→보고서, no coined words), with a self-test proving the linter still detects violations. Applying it fixed six live violations. (#417)
- The SPDX checks the Windows verification round left to a human eye — the SPDX chip and the chip addressing the `.spdx.json` artifact — are now Playwright specs, now covering the on-demand export flow that replaced the scan-form toggle. (#419)

### Documentation

- The AI-model path is now visible from the entry points. The landing intro listed inputs as source, container, binary or a received SBOM — omitting firmware and AI models entirely — so a visitor looking for a G7 or EU AI Act SBOM tool found nothing on the front page. (#427)
- The AI model guide now says where `scan-sbom.sh` comes from. It opened with `docker pull` and then invoked the script without linking any installation page, which left a reader arriving from an external guide unable to run the first command. (#440)
- Documented the SPDX export toggle in the web UI reference pages. (#436)
- The README demo GIF is now reproducible: a tagged Playwright spec drives a stubbed scan through the walkthrough and the recording is made in the same pinned container as the guide screenshots. The previous hand recording predated the regulatory crosswalk, license classification and current New scan form, and rotted silently whenever the UI moved. (#424)
- Synced the docs site and README with features shipped across v1.5–v1.8 that were undocumented, thin, or inaccurate: the web UI upload step (Dependency-Track/TRUSCA), the Maven/Node full-graph opt-outs (`BOMLENS_MAVEN_FULL_GRAPH`, `BOMLENS_NODE_FULL_GRAPH`), the conformance spec-version overrides (`CYCLONEDX_SPEC_VERSIONS`, `AI_CYCLONEDX_SPEC_VERSIONS`, `SPDX_SPEC_VERSIONS`), the `ENRICH_EOL` and `STALENESS_ENRICH` variables, the AI compliance profile card and `_ai-profile.*` artifacts, and the `--ui --mount` host-folder option. Corrected the `--all` description, which omitted the `--spdx` it also implies, and the "(CLI only)" note on `--byte-stable`, which has a web UI toggle as well. (#409)
- Added a CI gate (`scripts/check-doc-env-coverage.sh`) that fails when a user-facing environment variable in `scan-sbom.sh --help` is documented in neither the CLI nor the Docker-image reference — the code-to-docs counterpart of the existing docs-to-code drift check. Applying it documented the previously missing `SBOM_AIBOM_IMAGE` override. (#410)
- Korean pages: fixed translationese and coined terms concentrated in the web UI reference and the vendored-OSS guide, unified three drifting notations (디렉터리, 배지, 보고서), and recorded the terminology decisions in the style guide. (#415)
- English pages: a native-quality pass fixed two real defects — firmware-guide links mislabeled "(Korean)" and stale tool version pins in the architecture page — plus literal collocations, run-on passages, and naming consistency. (#418)
- Guide screenshots were regenerated in the pinned Playwright container, so the conformance section and New scan form images match the shipped UI (regulatory crosswalk, AI compliance card, SPDX toggle). (#416)

## [v1.8.2] - 2026-07-15

### Changed

- Supplier-SBOM conformance no longer fails outright on `pkg:generic` or custom PURLs. These were a mandatory check, so a single untraceable component failed the whole verdict even when every other requirement was met — common for embedded and firmware supplier SBOMs. The `no-generic` check is now advisory (a warning, not folded into the recommended-coverage warnings), the count stays visible through a new `untraceableComponents` field and a report line, and the overall pass/fail is left to the remaining mandatory checks.

### Fixed

- The SPDX conformance transitive-dependency check now counts `DEPENDENCY_OF` relationships as well as `DEPENDS_ON`. Syft writes OS-package dependency edges in SPDX as the reverse relationship `DEPENDENCY_OF` (for example `NetworkManager-libnm DEPENDENCY_OF NetworkManager`), never `DEPENDS_ON`, while the same scan's CycloneDX carries `dependsOn`. The check only asks whether dependency edges exist, so it now accepts both directions; previously every Syft-generated SPDX submission received a false transitive failure despite a fully populated dependency graph. Both the SPDX JSON and Tag-Value paths are covered; the CycloneDX path is unchanged.
- Post-processing modes now fail closed when the finished SBOM never reaches the host. The host-output verification was gated on `--generate-only`, so the default path — including ANALYZE — printed "Analysis Complete!" over an empty folder when the `/host-output` mount did not reach the host (an output directory outside Docker Desktop file sharing, or under `/tmp` on Colima, where only the home directory is shared to the VM). Every post-processing mode writes the output file, so its absence now reports the failure in all modes.
- Source-tree enrichment is confined to source-scan modes. The vendored-OSS (SCANOSS) and CocoaPods steps read the mounted source root with no mode guard, and the web UI mounts its host directory for every mode, so an ANALYZE of a supplier SBOM could discover a stray `Podfile.lock` in that tree and merge unrelated components into the result. Both steps are now gated on the scan mode, so ANALYZE, MERGE, IMAGE, BINARY, ROOTFS, FIRMWARE, and AIBOM no longer scan a mounted source tree.
- Empty file components from SPDX conversion are dropped. Syft's SPDX-to-CycloneDX conversion turns each SPDX file entry into a `file` component with no name and no PURL — an unidentifiable row with no CVE match, license, or attribution. A supplier SPDX with a large file section added thousands of these, skewing the notice count and the UI inventory. A normalize filter now drops only components that are both a file and carry neither name nor PURL; real packages and named or PURL-bearing file components are untouched.

## [v1.8.1] - 2026-07-15

### Added

- Regulatory crosswalk on the AI SBOM conformance report: each G7 minimum element that maps to a regulation is linked to the documentation obligation it touches, so a reviewer can see which regulatory requirement a missing element concerns. Two frameworks are mapped — the EU AI Act's Annex IV technical documentation (Regulation (EU) 2024/1689, Article 11(1)) and the Korean AI Framework Act (제31/32/33·34/35조). It is informational only: it never changes a check's status or the overall result, and the report states that BomLens does not certify compliance with any regulation. The mapping lives in `docker/lib/regulation-crosswalk.json`, keyed by G7 element id and validated against the registry so it cannot drift silently.
- AI compliance profile: for an AI SBOM, a one-page profile (`{prefix}_ai-profile.{json,md,html}`) re-aggregates the G7 status by cluster, the regulatory crosswalk, and the components whose license is flagged for review (AI behavioral-use or non-commercial). It runs no scan, makes no compliance determination, and is a no-op for a non-AI SBOM.
- Web UI: the Conformance section now shows the regulatory crosswalk as a sub-block (per-framework present/gap/review with the no-certification disclaimer) and a compact AI compliance summary card, and the AI profile reports are listed and downloadable.

### Changed

- The repository and tool identifiers were renamed from sbom-tools to bomlens; references across the docs, configuration, and image names were updated.

## [v1.8.0] - 2026-07-13

### Added

- Components past their published end-of-life are now flagged, offline by default. A bundled endoflife.date snapshot is matched by PURL coordinate (accuracy-first closed mapping — an unmapped component is left untouched, never guessed), and the result is surfaced in the web UI results. A runtime or framework past EOL receives no upstream fixes, so this answers a supply-chain question distinct from CVEs.
- Component version currency: the same snapshot reports when a component is behind the newest patch of its own release line (offline, default on — a safe in-cycle upgrade signal). With `STALENESS_ENRICH=true`, deps.dev is queried per package (opt-in, default off) for the absolute newest version, releases-behind, and last-release date across npm, PyPI, Maven, Go, Cargo, NuGet, and RubyGems.
- Opt-in SPDX output: `--spdx` (env `GENERATE_SPDX`, included in `--all`) additionally exports the finished BOM as SPDX 2.3 JSON (`{prefix}_bom.spdx.json`) after every enrichment step, with its own signature under `--sign` and byte-stable output under `--byte-stable`. The web UI gains an "SPDX export" toggle. CycloneDX remains the working and upload format; CycloneDX-only data (vulnerabilities, `bomlens:*` properties) is not carried over.
- The web UI can scan directories outside the launch folder — including the running host OS. `scan-sbom.sh --ui --mount <dir>` (repeatable; `SBOM_UI_MOUNT_DIR` for the Windows launcher) mounts each directory read-only and the Directory path input offers them as scan locations. The desktop app adds an in-app folder picker that persists the mounts across restarts. Scanning a live `/` excludes `/proc`, `/sys`, `/dev`, and `/run`.
- The sidebar rail and the overview jump card now show the conformance coverage figure (G7 element coverage for AI SBOMs, passed/total format checks otherwise), like the component and vulnerability counts.
- THIRD_PARTY_LICENSES.md now records the web UI's bundled fonts (Inter and JetBrains Mono, both OFL-1.1) with the attribution the license requires.

### Changed

- Supplier-SBOM conformance now enforces two more submission requirements as mandatory checks: the spec version must be in the accepted range (CycloneDX 1.3–1.6 and SPDX 2.2–2.3, overridable via `CYCLONEDX_SPEC_VERSIONS`/`SPDX_SPEC_VERSIONS`; AI SBOMs also accept CycloneDX 1.7, which the AIBOM toolchain emits), and every PURL must follow the standard `pkg:type/name@version` shape — colon coordinates, a missing `pkg:` prefix, a missing version, or raw spaces now fail with the offending PURLs listed. Previously only PURL presence and the `pkg:generic` ban were enforced, so a schema-valid SBOM with malformed PURLs passed.
- Firmware CVE matching no longer bundles cve-bin-tool's ~1.5 GB NVD database, which could not be built reliably — cve-bin-tool's NVD `api2` fetch is rate-limited into multi-hour stalls (and blocked outright from cloud runner IPs), and its `json-mirror` source is dead. cve-bin-tool now only identifies firmware binaries; their CPEs are matched against a compact index (~130 MB) distilled at build time from the NVD data feeds (`fkie-cad/nvd-json-data-feeds`, a plain git clone with no rate limit or API key). The firmware image builds on standard cloud runners again — no NVD key, no BuildKit secret, and no self-hosted runner — while offline/air-gap matching and the security-report contract are unchanged.

### Fixed

- `scan-sbom.sh --ui` no longer requires a TTY, so the documented web UI entry point works from CI, pipes, and wrappers instead of dying with `the input device is not a TTY`.
- When a zip created by PowerShell `Compress-Archive` is rejected by the container's `unzip` (backslash-separated entries), the scan now explains the cause and suggests re-zipping with Explorer instead of printing a bare `unzip failed`.
- Web UI layout defects found in a full-screen visual audit: the new-scan settings panel fits one screen again (advanced options and upload are collapsed disclosures with an enabled-count badge), large dependency graphs snap to a legible zoom instead of rendering as a dot cloud (the snap handler was attached after the synchronous initial layout and never fired), small result tables no longer pad to an empty 256px box, the overview card grid no longer leaves a lopsided empty tail, and the security artifact card no longer shows two identical "JSON" chips.

## [v1.7.0] - 2026-07-08

### Added

- iOS apps are now supported: a CocoaPods `Podfile.lock` or a Swift Package Manager `Package.resolved` is read into the SBOM with the full transitive pod/package set, and — for CocoaPods — the dependency graph reconstructed from the lockfile. Resolution is lockfile-first, so it runs offline and needs neither the `pod` CLI nor macOS. (cdxgen's own CocoaPods path requires `pod`, which the Swift image does not carry, and it aborted the scan when a `Podfile` was present.)
- The web UI can upload the generated SBOM to a Dependency-Track or TRUSCA server (previously CLI-only). New scan has an optional Upload section for the destination, server URL, API token, and — for TRUSCA — the project id. The token is stashed single-use and the server URL and token are used for that run only, never stored.
- New scan exposes a "Reproducible output" toggle in the advanced options, surfacing the byte-stable mode that was previously CLI-only. When on, re-scanning the same source produces a byte-for-byte identical SBOM. The toggle is hidden for supplier-SBOM analysis and AI model scans, where it does not apply.

### Changed

- Best-effort post-processing steps (normalize, CPE and AIBOM enrichment, conformance, vendored-OSS suggestion) no longer swallow real failures. They kept the never-abort guarantee by ending in `|| true`, which also hid genuine errors; each step now logs a WARN and stamps `bomlens:pipeline-step-failed` on the SBOM when it fails, so a degraded run is visible instead of silently incomplete.

### Fixed

- Maven source scans no longer inflate the SBOM with the test and provided toolchain (junit, lombok, etc.). The scan is scoped to the deployable runtime set using cdxgen's resolved scope tags — compile and runtime dependencies are kept, test and provided ones are dropped — the Maven analogue of the Android and npm release-scope fixes. Set `BOMLENS_MAVEN_FULL_GRAPH=1` to keep the full graph.
- Android product-flavor projects now scope to the release runtime classpath instead of silently falling back to the full build + test graph. The release-config selection dropped every candidate when a project had no plain `releaseRuntimeClasspath` (only flavored variants such as `freeReleaseRuntimeClasspath`), so flavored apps were reported with their whole toolchain. It now prefers the plain classpath and otherwise takes the first flavored release variant.
- Node.js (npm) source scans no longer inflate the SBOM with the `devDependencies` tree (jest, eslint, the Babel toolchain, etc.). The scan is scoped to the deployed `dependencies`, so build and test tooling the app never ships is excluded — the npm analogue of the Android release-scope fix. Set `BOMLENS_NODE_FULL_GRAPH=1` to keep the dev + prod superset.
- Android (AGP) source scans no longer inflate the SBOM with the build and test toolchain. The scan is scoped to the deployable release runtime classpath, so only the components shipped in the APK are recorded.
- Firmware scans no longer silently report zero CVEs from a vulnerability database that lacks NVD data. The build gate now rejects a bundled CVE database without a real NVD advisory corpus instead of shipping it.
- Native Windows source scans work under Git for Windows: docker bind mounts and the Git Bash resolution in `scan-sbom.bat` were corrected so a Windows (MSYS) shell can run a scan instead of failing at container start.
- Windows web/desktop UI source scans resolve transitive dependencies again. The cdxgen (and firmware/AIBOM) sibling containers were bind-mounted by a Windows drive path (`C:/…`) that the in-container Linux docker CLI cannot consume, so the scan silently fell back to syft (direct dependencies only). The siblings now inherit the UI container's mounts with `--volumes-from`, so they run on every host OS — verified on Windows, where UI and CLI scans now produce identical SBOMs.
- Firmware security reports are no longer empty. The bundled Trivy could not decode the firmware SBOM's `firmware` root component type and failed the whole scan; Trivy is now retried on an input copy whose root type is coerced to one it accepts, so the vulnerability report is populated while the delivered SBOM keeps its accurate `firmware` type.

## [v1.6.0] - 2026-07-03

### Added

- AI SBOM conformance now covers the full G7 minimum-elements checklist: seven clusters rendered as 51 checks, each tagged as read from the SBOM, inferred from signals, or requiring human review. The web UI groups the results by cluster, and the AI model guide explains what the checklist is, its EU AI Act context, and how to read the report.
- The desktop app checks for a newer release on startup and offers the download page.
- The desktop app recovers without a relaunch: the Docker-missing and failure screens have retry buttons, a scanner container that dies after the UI loads is detected and reported, containers left behind by a crash are cleaned up on the next start, and a second launch focuses the running window instead of starting a duplicate.
- Desktop quality of life: the version is visible on the start screen and About panel, window size and position are remembered, startup progress is written to a log file, and the start screens support light mode, a language toggle, and per-OS Docker installation guidance.
- New scan prefills the project name and version from the scan source (git URL, Docker image tag, uploaded file name, or SBOM metadata), marks required fields, and validates them inline.
- The macOS installer is universal: it now runs on Intel Macs as well as Apple Silicon.
- The desktop installers are covered by the release's `SHA256SUMS.txt`, so downloads can be integrity-checked.

### Changed

- Advanced scan option labels lead with what they do ("Per-file license scan", "Detect copied-in open source", "More vulnerability advisories"); the tool names moved into the hints.
- The desktop app pulls the documented image tag (`ghcr.io/sktelecom/bomlens`) — the same image it used before, under its current name.
- Installer code signing and notarization turn on automatically once certificates are registered as CI secrets; installers remain unsigned until then.

### Fixed

- OS package CVE matching in SBOM security scans was restored.
- syft output is pinned to CycloneDX 1.6 because Trivy 0.70 cannot read 1.7; security scans of syft-generated SBOMs work again.
- A failed security scan is now marked as failed in the report instead of silently reporting zero findings.
- PyPI version ranges no longer duplicate the installed version as a lower bound.
- The `--deep-license` image builds and runs again.

## [v1.5.5] - 2026-07-01

### Fixed

- Maven and Gradle source scans now record their direct dependencies in the SBOM dependency graph. The root component previously carried an empty `dependsOn`, so tools reading the graph classified every direct dependency as transitive. npm was unaffected.

## [v1.5.4] - 2026-06-28

### Added

- The result Overview leads with the section jump cards and shows Security and License classification side by side; clicking a band opens that section pre-filtered.
- Licenses are graded by copyleft strength (network / strong / weak / permissive), with separate review-needed and uncategorized classes; an unrecognised license is never assumed permissive.
- The home screen is now Scan management: search past scans, filter by scan type, and see total / at-risk / project counts, with the at-risk card doubling as a filter.
- Global search across components and CVEs from the top bar.
- Re-scan: re-run a finished scan with the same target and options from the top bar.
- The SCANOSS client ships in the base image, so vendored open-source identification works out of the box (still opt-in at scan time).
- Running firmware and AI scans can be cancelled.

### Changed

- New scan and Recent moved into the top bar, so the left rail is purely the current scan's sections.
- New scan's advanced analysis toggles moved into their own Advanced scan options section, with clearer copy and SCANOSS free-tier guidance.
- Generated HTML reports were restyled to match the web UI.
- The scan progress bar follows the real pipeline stages, and the Scan management table columns are sortable.
- The dependency rail badge shows the direct/transitive split.

### Fixed

- A source scan that falls back to syft is labelled "Source" instead of "SBOM", and now says so when the fallback was caused by Docker running out of disk.
- Fonts are self-hosted so the desktop content-security policy keeps the intended typography.

## [v1.5.3] - 2026-06-27

### Added

- The dependency graph view was redesigned to read like a commercial graph explorer.
- License distribution is shown as proportional bars, with the charts animating in on first render.
- Each scan now shows how it compares to the previous run of the same project.

### Changed

- Interactive result cards lift on hover, with motion that honours the operating system's reduced-motion setting.

### Fixed

- `SECURITY_ENRICH=false` now reaches the post-process container, so the EPSS and CISA KEV opt-out works from the host CLI for air-gapped runs.
- `--analyze`/`--sbom` combined with `--model` is now rejected instead of silently running in ANALYZE mode.
- AI SBOM generation fails closed when the model card cannot be collected (offline, or an unknown/private model id) instead of writing an empty stub ML-BOM as a valid output.
- Supplier SBOM analysis now produces the conformance report for well-formed SPDX Tag-Value inputs; a zero-count grep had aborted the Tag-Value checks.
- Reopening a past scan from history no longer shows an empty run-log panel.
- A release stays a draft until the release gate verifies it, so it is never published before its entry points are checked.

### Documentation

- Corrected the supplier-SBOM conversion note (SPDX is converted to CycloneDX 1.6; CycloneDX inputs keep their original spec version), removed the unimplemented drag-resizable columns claim from the UI reference, fixed the Node.js lock-file guidance, and added page descriptions to five navigation pages.

## [v1.5.2] - 2026-06-26

### Added

- Per-run output isolation: each scan now lands in its own `{Project}_{Version}/` subfolder, so the files from one run stay together and the CLI never litters the source tree it scans. New `--output-dir`/`-o` and `--timestamp` flags choose the base directory and keep repeat runs side by side.
- Release gate: a release is created as a draft and only published after its recommended entry points are verified for that exact release — the desktop installers are attached and the documented first-scan command produces a valid SBOM on the actual published image.
- Onboarding CI gates that keep the docs and the tool in step: a doc/tool drift check (flags, environment variables, image names, the desktop download name), an internal-link check for the getting-started pages, machine UX checks (no silent error exits, parity between the setup scripts, a complete `--help`), a desktop-app boot smoke on Windows and macOS, and a walkthrough that runs the documented first-scan command on the published image.

### Changed

- Scan outputs default to a `{Project}_{Version}/` subfolder of the current directory instead of being written flat. Set `SBOM_OUTPUT_FLAT=1` for the previous flat layout.

### Fixed

- `--byte-stable` is now reproducible: it no longer resolves dependency licenses over the network, a lookup whose success varied between runs and made two otherwise-identical scans differ.
- Source scans no longer leave root-owned build files (for example `node_modules`) in the scanned project folder or the git/zip ingestion temp directory on Linux; the scanned tree is handed back to the host user.
- The README pointed at a renamed desktop installer; the download links now use `BomLens-Setup.exe` and `BomLens-Setup.dmg`.
- Documented the `--ref` alias for `--branch`.

## [v1.5.1] - 2026-06-26

### Added

- Desktop app firmware and AI-model scans: the desktop app now runs firmware and AI-model (AIBOM) scans by launching the matching scanner image as a sibling container, pulling it on first use.
- Source file tree without ScanCode: source scans emit a `_files.json` file inventory, and the web UI shows a source tree from it when no ScanCode result is present.
- SBOM conformance is now a first-class result section, with per-element G7 evidence, examples and guidance links.
- Determinate firmware CVE-database download progress: a real percentage bar during the cve-bin-tool database fetch, falling back to the previous approximation when a scan reports no progress.

### Changed

- Web UI design-language refresh: a redesigned visual language, a Recent-scans home, and neutralized report wording.
- Release assets are unified under the BomLens name (for example `BomLens-Setup.*`), and the release notes link to the documentation site.
- The AI-model scan form now explains the open-source Notice option.

### Fixed

- Firmware scans matched zero CVEs because the published firmware image shipped an empty cve-bin-tool database. The image now bundles a populated database with a runtime refresh, the build fails if the database ends up empty, and the database path matches the location cve-bin-tool actually uses.

## [v1.5.0] - 2026-06-25

### Added

- Redesigned web UI: a new shell with Overview, Components, Dependencies, Vulnerabilities, Licenses, AI (Models & datasets / G7), and Artifacts sections; a single-card New scan form; and local Recent scans (list, re-open, delete; newest 20 shown). Every navigation element is a real link, so the logo, New scan, sidebar sections, recent scans and jump cards open in a new tab (Cmd/Ctrl/middle click) via URL-hash routing.
- AI-model SBOM (AIBOM): generate a CycloneDX ML-BOM for a HuggingFace model id — with G7 minimum-element conformance — from the web UI's AI model input. Published as the new `bomlens-aibom` image (legacy alias `sbom-scanner-aibom`).
- EPSS exploit probability and CISA KEV (actively exploited) surfaced on vulnerabilities.
- Component detail: click a component row to see its PURL, source/download location, copyright, licenses and vulnerabilities.
- License explorer: click a license to list its components, with copyleft/reciprocal licenses highlighted.
- Vulnerability view: click the severity bar to filter, plus a search box; all result tables are drag-resizable.
- Firmware analysis: cve-bin-tool now matches CVEs online (the firmware image bundles the vulnerability DB), and an enrichment step fills CPEs and SPDX licenses for a curated whitelist of well-known OSS (busybox, dropbear, dnsmasq, …) so Trivy and the notice can use them. Compressed firmware images (`.img.gz`, `.tar.xz`, …) can be uploaded.
- Open-source notice: per-component source/download location and copyright line, plus an optional PDF rendering (`SBOM_PDF` build).
- SCANOSS: a token input for the OSSKB endpoint (the free anonymous endpoint is rate-limited), and a result note that distinguishes "search unavailable" from "nothing found".

### Changed

- Advanced scan options (deep license / SCANOSS) appear only for source scans; AI-model scans drop the deep-license toggle and the (always-empty) security report.
- G7 conformance moved under the AI group, with per-element "what it is / how to satisfy" guidance.
- The live run log now appears only on the Overview, not under every section.
- The scan banner and UI startup logs are unified to "BomLens".

### Fixed

- SCANOSS found nothing on uploaded/cloned sources because they extract under a dot-prefixed `.uploads` path that scanoss-py skips by default (`--all-hidden`).
- The firmware component merge hit the command-line length limit on large rootfs images (jq now reads arrays from files via `--slurpfile`).
- The dependency graph drew edgeless SBOMs (e.g. firmware) as overlapping dots — it now shows a note — and framed large graphs too far out to read.
- AI scans were labelled by the generator's `job-<timestamp>` instead of the model name.
- The scan done-event listed every artifact in the output folder instead of only the current scan's.
- Leaving a running scan no longer lets the backgrounded scan finish and hijack the screen (the live SSE stream is closed on navigation).

## [v1.4.0] - 2026-06-23

### Added

- Identify open source copied (vendored) into C/C++ source that has no package manager. `--identify-vendored` matches file fingerprints against the SCANOSS/OSSKB knowledge base and records copied-in open source as named components (name, version, PURL, and a CPE where one exists), so the security report can surface their CVEs. It is off by default, with a one-line suggestion shown automatically when a scan looks like C/C++ embedded source, and is available in the web UI under Advanced. Matches are reconciled against the package-manager scan, so enabling it on a managed project does not duplicate dependencies or inflate the vulnerability count. Hardened with an adversarial CLI + UI test campaign (CPE-grammar safety, large-tree handling, over-detection, injection). (#168, #169)

### Changed

- The published `bomlens` image now bundles the (MIT-licensed) SCANOSS client, so `--identify-vendored` works out of the box without a custom build. (#168)

## [v1.3.1] - 2026-06-22

### Added

- Server delivery SBOM: scan a server's layers separately (OS rootfs and application) and combine them with `--merge`, which merges several CycloneDX SBOMs into one; the web UI accepts a rootfs directory as input. (#161)

### Changed

- GHCR package names are unified under the `bomlens` brand; `sbom-generator` and `sbom-scanner` remain aliases of the same digest. (#156)
- The Android image pull defaults to the published `bomlens` name. (#157, #158)
- Documentation is restructured by intent with English as the canonical language, sidebar labels shortened, and the landing pages use the web UI demo gif. (#154, #155, #160)

### Fixed

- Source scans no longer leak `src@latest` as the root component name, which became a non-unique codelocation in some SBOM import platforms and blocked unrelated imports. The caller's project name is now passed to cdxgen and stamped into the root component, and the pipeline fails closed if stamping does not take. (#166)
- `--merge` preserves each input's dependency graph so the merged BOM stays CycloneDX-conformant. (#164)
- Follow-ups from the v1.3.0 verification pass (V13-1/2/3). (#159)
- Corrected the first-scan link in the Korean server-delivery guide and modeled static linking as a blind spot rather than a separate layer. (#162, #163)

## [v1.3.0] - 2026-06-14

### Added

- `--trusca <project_id>` (or `--upload-target trusca`) uploads the generated SBOM to TRUSCA's native ingest endpoint as an alternative to the default Dependency-Track upload. (#148, #149)
- Vulnerability rows in the web UI expand in place to show the CVSS score and vector, the full advisory description, and reference links — surfacing data already in the Trivy report without an extra fetch.
- The components table in the web UI can now sort by name, version, or type and filter by component type and license, alongside the existing search.
- The vulnerabilities table can be filtered by severity, and the summary tab shows a license distribution (component count per license, plus unlicensed).
- The dependency graph is now interactive: click a node to see its details (version, type, licenses, direct/indirect), and search to highlight matching packages.
- Documentation site: a Release notes link in the nav (pointing at GitHub Releases) and opt-in, cookieless analytics (GoatCounter) that stays off until a site code is configured.

### Changed

- Unified the web UI's empty, loading, and error states into shared primitives so every result view looks and behaves the same, and added a retry action to the dependency and source-tree views.

### Fixed

- Dependency graph node labels were unreadable in dark mode (fixed dark text on a dark canvas); graph colors now follow the light/dark theme tokens.
- Small dependency graphs no longer over-zoom into huge, overlapping labels; zoom is capped and node spacing widened so a handful of nodes stays readable.

## [v1.2.2] - 2026-06-13

### Added

- BomLens brand identity: aperture logo, app icons, and favicon across the docs site, web UI, and desktop app. (#125, #127, #128, #130)
- Rendered documentation site (sktelecom.github.io/bomlens) with sidebar navigation, search, and a one-click Windows download, replacing repo-only docs. (#112, #113, #114, #115, #116)
- New documentation pages on the site: use the Docker image directly, architecture, and the two contributing guides, each with an English translation. (#126)
- English translations for the five previously Korean-only guides. (#117)

### Changed

- Renamed the product display name to BomLens; technical identifiers and download URLs are unchanged. (#120)
- The web UI header shows the BomLens brand with an SBOM generator descriptor. (#124)
- The post-process image is co-published as `ghcr.io/sktelecom/bomlens`; `sbom-generator` and `sbom-scanner` remain aliases of the same digest. (#121, #122)
- Reworked the Korean guides for readability and kept the synced English pages aligned; wide architecture diagrams now stack vertically. (#123, #129)
- The docs home leads with a headline, a Get started primary button, and a product screenshot; the header brand links to the home page. (#131, #132)

### Fixed

- The desktop app startup screen background matches the web UI dark token. (#118)

## [v1.2.1] - 2026-06-12

### Security

- The web UI cleanup endpoint validates the provided token before removing staged uploads, and CI workflows run with least-privilege permissions. (#106)
- Pinned base image digests so the supply chain is verifiable (Scorecard pinned-dependencies). (#107)

### Fixed

- The NOTICE dedupes appended SPDX license texts and normalizes the Expat alias to MIT, so each license text appears once. (#108)
- The SBOM stamps `metadata.component` from the input project name and version instead of leaving it unset. (#108)
- Stabilized byte-stable SBOM output and coerced null components to empty arrays, preventing spurious diffs and parse failures. (#108)

## [v1.2.0] - 2026-06-11

### Added

- Web UI source scans (current directory, Git URL, ZIP upload) now resolve transitive dependencies through cdxgen language images, matching the CLI. The web UI previously used syft, which captured only directly declared dependencies; a Spring Boot sample went from 8 to 91 components. (#95)
- Scan results gained Components and Vulnerabilities tabs with searchable, sortable tables, next to the existing summary. (#96)
- Source scans now fetch dependency licenses (`FETCH_LICENSE`, on by default), so components and the NOTICE carry real license data instead of NOASSERTION. Set `FETCH_LICENSE=false` to skip the lookups. (#98)
- The NOTICE normalizes license aliases to SPDX ids, shows component copyright when present, and appends the SPDX standard full text of each used license from a bundled set (21 common licenses, offline). (#99)
- The security report surfaces CVSS, EPSS (exploit probability) and CISA KEV (known-exploited) signals, sorting findings KEV first, then by severity, then by EPSS. Set `SECURITY_ENRICH=false` for offline runs. (#100)
- Redesigned the post-scan artifact download experience with per-format chips and a bulk ZIP download. (#102)

### Changed

- Synced the user documentation, in-app help, and screenshots with the new features. (#101, #103)

### Fixed

- Removed the redundant maven pre-resolve step in build-prep that printed a spurious NoPluginFoundForPrefix error on every Java source scan, with no effect on the resulting SBOM. (#97)

## [v1.1.1] - 2026-06-09

### Added

- Desktop startup screen is now bilingual: it follows the system locale (Korean on Korean systems, English elsewhere) and falls back to English, matching the web UI. The `SBOM_LANG` environment variable forces a language (`SBOM_LANG=en` or `ko`).

### Changed

- The main `README.md` is unified to English, with English UI screenshots. The Korean documentation table and Korean guides are kept for Korean users; the Korean screenshots stay with the Korean docs.

## [v1.1.0] - 2026-06-02

### Added

- Electron desktop app (`electron/`) that wraps the web UI with no console window: it checks Docker, pulls the scanner image, runs the `MODE=UI` container, and opens the UI on double-click.
- Desktop installers (`SBOM-Generator-*.exe` / `.dmg`) are built in CI and attached to tagged GitHub Releases, so non-developers can download them directly. Unsigned for now, so Windows SmartScreen prompts to confirm.
- License-manager quickstart (`docs/notice-quickstart.md`) and a setup-check helper (`scripts/check-setup.bat` / `scripts/check-setup.sh`) that reports Docker, image, and port status in Korean.
- Windows verification assets: an automated smoke test (`tests/windows-smoke.ps1`) and a manual e2e checklist (`tests/windows-e2e-checklist.md`).
- Desktop-app packaging study (`docs/internal/desktop-app-study.md`).
- Screenshots and a flow diagram across the user guides.
- Firmware analysis (FIRMWARE mode): unpack a firmware image and produce an SBOM and risk report.
- Supplier SBOM validation and analysis (ANALYZE mode) for SBOMs you receive from third parties.
- End-to-end support for five input forms (source folder, GitHub URL, ZIP archive, Docker image, binary/RootFS) with a risk report emitted in every mode.
- Local web UI: launch a scan, stream live logs, and download results from the browser.
- Cosign signing of generated artifacts via `--sign`, with the key and password passed into the container at runtime.
- Multi-architecture Docker images, with architecture detected at runtime for Trivy and cosign.
- Governance and community-health documents: `CODE_OF_CONDUCT.md` and `SECURITY.md`.
- Korean documentation style guide, enforced by a doc-style check.

### Changed

- `scripts/sbom-ui.bat`: results go to a dedicated `%USERPROFILE%\sbom-output` folder, the scanner image is pre-pulled on first run with progress shown, and messages are in Korean.
- README routes first-time Windows users to the easiest path up front, and the license-manager quickstart leads with the desktop app and lists expected install and download times.
- Renamed the product to SBOM Generator; the post-process image is co-published as `ghcr.io/sktelecom/sbom-generator` (the legacy `sbom-scanner` name keeps working).
- Windows-friendly onboarding: a download-and-double-click web UI flow, plus consistent Windows guidance across the supplier docs.
- The Windows release archive now bundles both launchers and the host-mounted `build-prep.sh`, so it runs without the full repo.
- Reworked the scanner into a two-stage architecture (generate, then assess risk).
- Documentation refreshed to match the current product, including the web UI flow and the two core roles.

### Fixed

- Standard squashfs images now extract correctly during firmware unpacking.
- Detection of `.csproj`-only and `.gradle`-only projects (multi-glob matching bug).
- Generated artifacts are written as the host user so the Examples CI no longer fails on root-owned files.

## [v1.0.0] - 2026-02-19

### Added

- Initial public release of SBOM Tools.
- CycloneDX SBOM generation from source code for Java (Maven/Gradle), Python, Node.js, Ruby, PHP, Rust, Go, .NET, and C/C++.
- Open-source notice (고지문) and a Trivy-based security report alongside each SBOM.
- Docker image distribution via `ghcr.io/sktelecom/sbom-scanner`.
- GitHub Actions workflows for CI (ShellCheck, hadolint, integration and example tests), image publishing, and releases.

### Security

- No publicly known vulnerabilities have been reported or fixed in this project to date.

[Unreleased]: https://github.com/sktelecom/bomlens/compare/v1.11.7...HEAD
[v1.11.7]: https://github.com/sktelecom/bomlens/releases/tag/v1.11.7
[v1.11.6]: https://github.com/sktelecom/bomlens/releases/tag/v1.11.6
[v1.11.5]: https://github.com/sktelecom/bomlens/releases/tag/v1.11.5
[v1.11.4]: https://github.com/sktelecom/bomlens/releases/tag/v1.11.4
[v1.11.3]: https://github.com/sktelecom/bomlens/releases/tag/v1.11.3
[v1.11.2]: https://github.com/sktelecom/bomlens/releases/tag/v1.11.2
[v1.11.1]: https://github.com/sktelecom/bomlens/releases/tag/v1.11.1
[v1.11.0]: https://github.com/sktelecom/bomlens/releases/tag/v1.11.0
[v1.10.5]: https://github.com/sktelecom/bomlens/releases/tag/v1.10.5
[v1.10.4]: https://github.com/sktelecom/bomlens/releases/tag/v1.10.4
[v1.10.3]: https://github.com/sktelecom/bomlens/releases/tag/v1.10.3
[v1.10.2]: https://github.com/sktelecom/bomlens/releases/tag/v1.10.2
[v1.10.1]: https://github.com/sktelecom/bomlens/releases/tag/v1.10.1
[v1.10.0]: https://github.com/sktelecom/bomlens/releases/tag/v1.10.0
[v1.9.0]: https://github.com/sktelecom/bomlens/releases/tag/v1.9.0
[v1.8.3]: https://github.com/sktelecom/bomlens/releases/tag/v1.8.3
[v1.8.2]: https://github.com/sktelecom/bomlens/releases/tag/v1.8.2
[v1.8.1]: https://github.com/sktelecom/bomlens/releases/tag/v1.8.1
[v1.8.0]: https://github.com/sktelecom/bomlens/releases/tag/v1.8.0
[v1.7.0]: https://github.com/sktelecom/bomlens/releases/tag/v1.7.0
[v1.6.0]: https://github.com/sktelecom/bomlens/releases/tag/v1.6.0
[v1.5.5]: https://github.com/sktelecom/bomlens/releases/tag/v1.5.5
[v1.5.4]: https://github.com/sktelecom/bomlens/releases/tag/v1.5.4
[v1.5.3]: https://github.com/sktelecom/bomlens/releases/tag/v1.5.3
[v1.5.2]: https://github.com/sktelecom/bomlens/releases/tag/v1.5.2
[v1.5.1]: https://github.com/sktelecom/bomlens/releases/tag/v1.5.1
[v1.5.0]: https://github.com/sktelecom/bomlens/releases/tag/v1.5.0
[v1.4.0]: https://github.com/sktelecom/bomlens/releases/tag/v1.4.0
[v1.3.1]: https://github.com/sktelecom/bomlens/releases/tag/v1.3.1
[v1.3.0]: https://github.com/sktelecom/bomlens/releases/tag/v1.3.0
[v1.2.2]: https://github.com/sktelecom/bomlens/releases/tag/v1.2.2
[v1.2.1]: https://github.com/sktelecom/bomlens/releases/tag/v1.2.1
[v1.2.0]: https://github.com/sktelecom/bomlens/releases/tag/v1.2.0
[v1.1.1]: https://github.com/sktelecom/bomlens/releases/tag/v1.1.1
[v1.1.0]: https://github.com/sktelecom/bomlens/releases/tag/v1.1.0
[v1.0.0]: https://github.com/sktelecom/bomlens/releases/tag/v1.0.0
