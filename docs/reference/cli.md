---
description: Every CLI option and environment variable for BomLens, with output locations, image pinning, and troubleshooting.
---

# CLI reference

Full options, analysis modes, CI/CD integration, and troubleshooting for BomLens.

## Options reference

```bash
./scripts/scan-sbom.sh [options]
```

> **Windows**: the commands here are for macOS/Linux. Pick one of the following. See [Getting started](../start/first-scan.md) for installation.
>
> - Replace `./scripts/scan-sbom.sh` with `scripts\scan-sbom.bat` (needs Git Bash).
> - Under WSL2, run the commands as-is.
> - To work without a command line, double-click `scripts\sbom-ui.bat`, or download the desktop app.

| Option | Default | Description |
|--------|---------|-------------|
| `--project <name>` | — | **(required)** Project name |
| `--version <version>` | — | **(required)** Project version |
| `--target <target>` | current directory | What to analyze: a directory (source tree, or an OS rootfs / staging build output), a Docker image, a binary file, or a `.zip`/`.tar.gz` archive. A Yocto build directory is recognized as such, and the image SBOM it published under `tmp/deploy/images/` is analyzed instead of the build tree being walked (see the [supplier SBOM guide](../guides/supplier-sbom.md#yocto-images)) |
| `--git <url>` | — | Shallow-clone a git/GitHub URL and analyze it as source (private repos: `GIT_TOKEN` env var) |
| `--branch <ref>` | default branch | Branch, tag, or commit of the `--git` target (alias `--ref`) |
| `--firmware` | false | Force firmware mode on the `--target` file (opt-in firmware image) |
| `--analyze <sbom>` | — | Validate and analyze a supplier SBOM (alias `--sbom`). CycloneDX/SPDX. Mutually exclusive with `--target` |
| `--model <ref>` | — | Generate an AI SBOM (CycloneDX 1.7 ML-BOM). A HuggingFace model id (`owner/name`) goes through the OWASP AIBOM Generator (opt-in `bomlens-aibom` image; fetches model-card metadata over the network). A Figshare item — its page URL, its DOI, or the item number — is described as a dataset from the public item endpoint, with no account and no opt-in image; an institutional DOI that does not carry "figshare" cannot be told apart from any other DOI, so give the item URL for those. Mutually exclusive with `--target`/`--analyze`/`--git`/`--merge` |
| `--model-file <path>` | — | Read one AI model file and describe it from its own header: GGUF, safetensors, PyTorch (`.pt`/`.pth`/`.ckpt`), pickle, npz, npy or ONNX. Offline, no HuggingFace account, and it works on a model that was never published. What can be filled depends on the format — GGUF carries a name, a license and an architecture, while safetensors usually carries only tensor shapes, and a field the file does not declare is left empty rather than guessed. A `.gguf`/`.safetensors`/`.pt`/… path passed to `--target` is read this way too. Mutually exclusive with `--target`/`--analyze`/`--git` |
| `--license <spdx-id>` | — | The outbound license the project is distributed under (e.g. `Apache-2.0`). Recorded on the SBOM's root component and used to flag dependencies whose terms clash with it. A source scan cannot infer this — cdxgen leaves the root license empty for maven and gradle — so without it no conflict verdict is produced. An existing root license (a supplier SBOM's own declaration) is never replaced |
| `--sbom-author <name>` | — | The entity that generated the SBOM — the organisation or person running the scan, not the tool and not whoever wrote the software. Recorded in `metadata.authors`, using the full name without acronyms. Nothing in a scan can discover it, so the field is left out of the SBOM when it is not given rather than filled with a placeholder |
| `--vex <file>` | — | A CycloneDX VEX document (JSON) a supplier sent for this product. The statements that apply to a component of the scanned SBOM are kept in `{Project}_{Version}_vex_imported.json`; the SBOM and the security report are not changed. Turns the security report on too (as `--deep-cve` does), because the statements are shown on its findings: open the scan folder in the web UI to see them on the vulnerability rows. A document for a different product or version, or one that is not CycloneDX VEX, is reported and skipped, and the scan still completes; a document with no applicable statement leaves an earlier `_vex_imported.json` as it was. Not offered with `--ui` (use Import VEX on the Vulnerabilities screen) or `--diff` |
| `--usage <scenario>` | — | Tailor the AI model risk assessment (`--model` and `--model-file`) to how the model will be used: `internal`, `product`, `redistribute` or `outputs-only`. Only the license conditions that bind that scenario decide the verdict, and the report states which scenario it was judged for. Unset judges against every condition |
| `--merge <a.json> <b.json> …` | — | Merge two or more CycloneDX SBOMs into one, dedupe by purl, and stamp the root component with `--project`/`--version`. Optional — for a server SBOM when an external system needs a single product BOM; otherwise keep the layers separate (see the [server SBOM guide](../guides/server-delivery.md)). Mutually exclusive with `--target`/`--analyze`/`--git` |
| `--merge-root <file>` | — | With `--merge`: keep this input's `specVersion` and root component (for example an ML-BOM's CycloneDX 1.7 root with its model card) instead of writing a fresh 1.6 root. Must be one of the `--merge` files; the preserved root is renamed to `--project`/`--version` |
| `--diff <old.json> <new.json>` | — | Compare two already-generated AI-model SBOMs (`--model` or `--model-file` output) for drift: a `bomlens:assessment:*` verdict that got worse, a changed declared license, or a SHA-256 weight-file hash that no longer matches under the same model name/purl/HuggingFace id — the last one means the artifact behind a stable name silently changed. Needs neither `--project`/`--version` nor a scan target: it only reads the two files and writes `<new>_model-diff.json` next to the newer one (or under `--output-dir`) |
| `--generate-only` | false | Save locally only, without uploading |
| `--upload-target <target>` | `dependency-track` | Upload destination: `dependency-track` (DT-compatible) or `trusca` (native ingest) |
| `--trusca <project_id>` | — | Upload to TRUSCA (= `--upload-target trusca` + project id). Needs `API_URL` and a Bearer `API_KEY` |
| `--notice` | forced on by the risk-report default | Generate the open-source notice (NOTICE, txt+html). The flag itself defaults to off; it is the risk report (on by default) that turns it on, so `--no-report`, not simply omitting `--notice`, is what skips it |
| `--security` | forced on by the risk-report default | Generate the Trivy security report (json+md+html), including CVSS, EPSS, and CISA KEV priority signals. Same mechanism as `--notice`: `--no-report` skips it, omitting the flag alone does not |
| `--spdx` | false | Also export the SBOM as SPDX 2.3 JSON (`_bom.spdx.json`), converted from the final CycloneDX output |
| `--all` | — | `--notice --security --spdx` |
| `--no-report` | false | Skip the open-source risk report (see below) |
| `--lang <en\|ko>` | `en` | Language for the human-facing conformance and AI-profile reports (`.md`/`.html`). The SBOM and the JSON reports stay English regardless |
| `--conformance-profile <default\|skt-submission>` | `default` | Conformance check strictness. `skt-submission` requires 100% PURL coverage and fails on any `pkg:generic` identifier, matching the SKT supplier submission review. The web UI's submission-review screen defaults to `skt-submission`; the CLI does not, so pair it with `--analyze` explicitly |
| `--resolve-purl` | off | `--analyze` only: ask each package repository whether the identifiers in the submitted SBOM name packages that exist, and add the answer to the conformance report as an advisory row. The only part of the check that uses the network. An identifier that resolves to nothing is reported, never failed, because a package published only to an internal repository answers the same way; `PURL_RESOLVE_IGNORE` skips namespaces you know are internal |
| `--deep-license` | false | Precise license detection with scancode (opt-in image) |
| `--deep-cve` | false | Add a second CVE-matching pass via grype's NVD CPE matcher (opt-in `bomlens-deep-cve` image, pulled automatically). Recovers NVD-only CVEs that Trivy misses, mostly for older Maven libraries, since BomLens attaches an NVD-matchable CPE to Maven components specifically; implies `--security`. Findings not verified against the live NVD version range are flagged version-unverified in the report — see the [deep CVE matching guide](../guides/reports.md) |
| `--identify-vendored` | false | Identify open source copied (vendored) into C/C++ source that has no package manager. Matches file fingerprints against the OSSKB service (included in the published image; sends hashes, not source). See the [identify bundled OSS guide](../guides/identify-vendored.md) |
| `--verify-weights` | false | With `--model`: download the repo's pickle-format weight files (`.bin`/`.pt`/`.pth`/`.ckpt` — the ones that execute code on load) and run the same local picklescan verification `--model-file` runs, instead of only trusting HuggingFace's own scan (`bomlens:hf:scan:*`). safetensors/GGUF/ONNX weights are never downloaded — they cannot execute code on load, so there is nothing for picklescan to check. Real network and disk cost (bounded by `AIBOM_VERIFY_MAX_FILES`/`AIBOM_VERIFY_MAX_BYTES`, default 5 files / 2 GiB each), unlike the metadata-only `ENRICH_HF_SECURITY` lookup, which is why this is opt-in. AI-model scans only |
| `--byte-stable` | false | Deterministic (reproducible) SBOM output |
| `--fail-on-conformance` | false | Exit 2 if this scan's own conformance report says "fail" (exit 3 if no conformance report was produced for this scan). Not offered with `--ui`. See [Exit codes](#exit-codes) |
| `--fail-on <condition>` | — | Exit 4 when this scan meets the condition, or 5 when it cannot be judged from what the scan produced. Repeat the option for several conditions. The conditions are a closed list: `vulnerability=<critical\|high\|medium\|low>` (a finding at that severity or worse; turns the security report on), `malicious-package` (a component flagged as a known malicious package), `license-conflict` (a component incompatible with the license the product is distributed under; the SBOM's root component has to record it, which `--license` does for source and rootfs scans and a supplier SBOM carries itself, otherwise it cannot be judged), `empty-result` (the scan identified no software: no component is left once operating-system and file entries are set aside, so a rootfs or image scan that names no package counts as empty), `license-coverage=<0-100>` (fewer than that percent of those same components declare a license; a license of NOASSERTION or NONE is not a declaration, and the percentage is rounded down; the value is required, has no default and takes no leading zero). Both read the scan's own conformance report, so a scan that wrote none cannot be judged, nor can one whose SBOM format the report did not measure (an SPDX 3.0 document that could not be converted). `license-coverage=` cannot be judged on a scan with no such component either (use `empty-result` for that). They leave the conformance verdict itself unchanged. Findings are counted as the security report counts them: once per package and id, with the kernel's advisories left out. `--vex` statements are not applied, so a finding the supplier declared not affected still counts. `vulnerability=` is not available for AI model and dataset inputs, which have no dependencies to scan, and neither is `empty-result`. Not offered with `--ui` or `--diff`. See [Exit codes](#exit-codes) |
| `--sign` | false | cosign signature (`COSIGN_KEY` required) |
| `--output-dir <dir>` | current directory | Base directory for outputs (alias `-o`). Each scan lands in a `{Project}_{Version}/` subfolder under it, keeping the bundle together and out of the source tree |
| `--timestamp` | false | Append `_YYYYMMDD-HHMMSS` to the run subfolder so repeat scans of the same project and version are kept side by side instead of overwritten. Folder name only; SBOM bytes are unchanged |
| `--ui` | — | Launch the local web UI |
| `--mount <dir>` | — | With `--ui`: expose an extra host directory to the web UI as a read-only target for the **Directory path** input (repeatable). Lets the UI scan an OS tree outside the launch folder — including the running host OS with `--mount /`. Results still save under the launch folder |
| `--help` | — | Print help |

**ANALYZE mode (`--analyze`) is an exception to five of these.** `--project`/`--version`/`--license`/`--sbom-author` never overwrite what a supplier's own SBOM already declares — its existing name, version, root license, and authorship are a fact about the document, not something this run has the authority to replace — and `--no-report` has no effect because the risk report is always generated for a supplier SBOM under review. When the submitted SBOM is missing one of these fields outright (no root license, no `metadata.authors`), the flag still cannot fill it in; the field stays empty and the conformance check judges accordingly.

Environment variables adjust the behavior.

| Variable | Default | Description |
|----------|---------|-------------|
| `SBOM_SCANNER_IMAGE` | `ghcr.io/sktelecom/bomlens:latest` | Override the scanner image |
| `SBOM_FIRMWARE_IMAGE` | `ghcr.io/sktelecom/bomlens-firmware:latest` | Image used for firmware analysis |
| `SBOM_AIBOM_IMAGE` | `ghcr.io/sktelecom/bomlens-aibom:latest` | Image used for AI model (ML-BOM) generation |
| `SBOM_DEEP_CVE_IMAGE` | `ghcr.io/sktelecom/bomlens-deep-cve:latest` | Image used for `--deep-cve` (grype CPE matching), and by the same toggle in the web UI |
| `SBOM_OUTPUT_FLAT` | — | Set to `1` to write artifacts flat in the output base, with no per-run subfolder (the pre-isolation layout, for CI that expects the old paths) |
| `SBOM_OUTPUT_DIR` | `~/sbom-output` | Output base for the desktop app and web UI (the CLI uses `--output-dir` instead). Each scan still lands in a `{Project}_{Version}/` subfolder under it |
| `SBOM_UI_MOUNT_DIR` | — | For the Windows launcher `sbom-ui.bat`, which takes no CLI arguments: one extra folder to expose to the web UI as a read-only Directory path target (the double-click counterpart of `--ui --mount`). Use a path without `& ^ | < >` — the launcher rejects those rather than passing a mangled mount to Docker |
| `SBOM_LANG` | system locale | `en` or `ko`, for the Windows launchers and the desktop app. Anything that is not Korean gets English |
| `SBOM_BASH` | auto-detected | For `scan-sbom.bat`: explicit path to Git Bash's `bash.exe` (e.g. `C:\Program Files\Git\bin\bash.exe`), when the launcher's own detection (deriving it from `git` on PATH) fails to find one that is not WSL's or a WindowsApps alias |
| `SBOM_PULL` | `missing` | Scanner image download policy, honored by both `scan-sbom.sh` and the Windows launcher. `missing` (default) pulls only when the image is absent, and otherwise quietly refreshes an already-present `:latest` in the background (bounded, best-effort — a stalled or offline check gives up and the run proceeds with the local image either way). `always` blocks and re-pulls every run, failing the run if the pull fails. `never` never touches the network, failing the run if the image is absent |
| `SBOM_IMAGE_TAR` | — | Path to an image tar from `docker save`. The Windows launcher loads it instead of pulling; a file named `bomlens-image.tar` next to the scripts is picked up automatically. Combined with `SBOM_PULL=never` this gives a fully offline install |
| `CVE_BIN_TOOL_MODE` | `auto` | Firmware CVE matching. `auto` uses the bundled CVE database if present, otherwise downloads from NVD when the network is reachable. `offline` matches only against the bundled database. `online` always updates from the network. `components-only` skips CVE matching and emits a component-only SBOM |
| `CVE_BIN_TOOL_HOME` | `/opt/cve-bin-tool-home` | Location of the bundled cve-bin-tool CVE database. cve-bin-tool reads `$CVE_BIN_TOOL_HOME/.cache/cve-bin-tool/cve.db` (it keys the cache off `HOME`) |
| `CVE_BIN_TOOL_DISABLE_SOURCES` | `GAD,OSV` | cve-bin-tool data sources to disable during a firmware scan. GAD (GitLab Advisory) and OSV are disabled by default so identification does not reach out over the network |
| `SCANOSS_API_URL` | OSSKB free API | Endpoint for `--identify-vendored`. Point at a SCANOSS commercial or self-hosted endpoint for air-gapped or high-volume use |
| `SCANOSS_API_KEY` | — | Credential for `SCANOSS_API_URL`, if the endpoint requires one |
| `SCANOSS_MIN_FILES` | `2` | Minimum number of files that must match a library before it is reported, to drop one-off downstream-fork noise. Set `1` to keep every single-file match |
| `GIT_TOKEN` | — | Token for cloning private git repositories |
| `HF_TOKEN` | — | HuggingFace read token for `--model` and for the dataset metadata lookups during AI SBOM analysis. Required for a private or gated repository, which is how you review a model before publishing it. `HUGGING_FACE_HUB_TOKEN` is accepted as an alias |
| `ENRICH_HF_SECURITY` | `true` | Read HuggingFace's own file-security scan results (ClamAV and picklescan, per file) for `--model` scans and record them in the ML-BOM. Metadata only, no file download. Set `false` to skip the lookup |
| `AIBOM_VERIFY_MAX_FILES` | `5` | With `--verify-weights`: maximum number of pickle-format weight files downloaded and scanned per model. Extra files beyond the cap are left unchecked, not queued |
| `AIBOM_VERIFY_MAX_BYTES` | `2147483648` (2 GiB) | With `--verify-weights`: a weight file larger than this (by the repo's declared size, or by its actual downloaded size if that differs) is skipped rather than downloaded/scanned |
| `COSIGN_KEY` | — | Path to the signing key used by `--sign` |
| `FETCH_LICENSE` | `true` | Resolve dependency licenses during source scans. Set `false` to skip the lookup and run faster |
| `GOTOOLCHAIN` | `auto` | Go source scans: which Go toolchain resolves the modules. By default, when `go.mod` asks for a newer Go than the scanner image carries, that version is downloaded. Set `local` to use only the image's own Go; dependency resolution then fails for such a project |
| `GOPROXY` | `https://proxy.golang.org,direct` | Go source scans: proxy for module and toolchain downloads, for a network that cannot reach `proxy.golang.org`. `GOSUMDB` is passed on the same way |
| `PROJECT_LICENSE` | — | Same as `--license`. The outbound license the project is distributed under, as an SPDX id. Drives the `bomlens:licenseConflict` verdicts and the risk report's conflict section |
| `SBOM_AUTHOR` | — | Same as `--sbom-author`. The entity that generated the SBOM, recorded in `metadata.authors` |
| `SECURITY_ENRICH` | `true` | Enrich the security report with EPSS and CISA KEV signals. Set `false` on air-gapped networks to skip the external lookups |
| `SECURITY_NVD_VERIFY` | `false` | With `--deep-cve`: verify each grype `nvd:cpe` finding against the live NVD version range and drop out-of-range false positives (needs `NVD_API_KEY` and network access; adds minutes). Off by default — findings are kept and flagged version-unverified |
| `NVD_API_KEY` | — | NVD API key for `SECURITY_NVD_VERIFY`. Passed to the container by name only, never inlined into the command |
| `API_URL` | — | Upload server URL (a DT server, or the TRUSCA base) |
| `API_KEY` | — | Upload credential. Used as `X-Api-Key` for DT, as a Bearer token for TRUSCA |
| `UPLOAD_TARGET` | `dependency-track` | Upload destination: `dependency-track` or `trusca` |
| `TRUSCA_PROJECT_ID` | — | TRUSCA project id (UUID). Required when `trusca` |
| `TRUSCA_REF` | `main` | Ingest ref label |
| `TRUSCA_RELEASE` | `--version` value | Ingest release label |
| `EXTERNAL_LOOKUP` | `true` | With `--ui`: enable the web UI's CVE/package lookup, which queries OSV.dev on demand. Set `false` for air-gapped runs |
| `SBOM_UPLOAD_TTL_HOURS` | `24` | With `--ui`: how long an uploaded file is kept if no scan is ever started with it (a picked-then-abandoned upload). Clamped to at least 1 |

Source-scan resolver options such as `BOMLENS_MAVEN_FULL_GRAPH` are listed under [Docker image environment variables](docker-image.md#environment-variables). Set them in the shell that runs `scan-sbom.sh` and they reach dependency resolution the same way.

On Windows, environment variables set in a command prompt do not survive a
double-click. The launchers therefore also read `UI_PORT`, `SBOM_LANG`,
`SBOM_PULL`, `SBOM_IMAGE_TAR`, `SBOM_SCANNER_IMAGE`, `SBOM_OUTPUT_DIR` and
`SBOM_UI_MOUNT_DIR` from a plain text file: copy `scripts/bomlens.settings.example.txt`
to `bomlens.settings.txt` beside the scripts (or to `%USERPROFILE%\.bomlens\settings.txt`).
A real environment variable always wins over the file.

Output flags are detailed in the [reports guide](../guides/reports.md); validating a received supplier SBOM is covered in the [supplier SBOM validation](../guides/supplier-sbom.md).

## Where outputs go

Each scan is isolated in its own `{Project}_{Version}/` subfolder, so the files from one run stay together and the CLI never litters the source tree it scans. That subfolder is created under a base directory:

- **CLI** (`scan-sbom.sh`): the base is the directory you ran the command in. Override it with `--output-dir <dir>` (alias `-o`).
- **Desktop app and web UI**: the base is `~/sbom-output` (`C:\Users\<you>\sbom-output` on Windows). Override it with the `SBOM_OUTPUT_DIR` environment variable.

For `--git` or archive ingestion the clone or extract happens in a temp directory that is cleaned up on exit, and only the output subfolder remains.

A re-scan of the same project and version overwrites its subfolder by default, keeping just the latest result. Add `--timestamp` to keep each run instead: it appends `_YYYYMMDD-HHMMSS` to the folder name, for example `MyApp_1.0.0_20260626-143000/`. The flag changes the folder name only, not the SBOM file names or bytes, so it works together with `--byte-stable`.

To restore the previous flat layout, where every file is written directly in the base with no per-run subfolder, set `SBOM_OUTPUT_FLAT=1`. This is meant for CI that expects the old paths.

`--diff` has no project or version of its own, so it writes its report directly into the base directory (current directory, or `--output-dir`) rather than a per-run subfolder.

## What the scan prints at the end

With `--generate-only`, the CLI lists the files it produced after `Analysis Complete!`. For every scan that measured software (not an AI model or dataset scan) it then states what the result holds:

```
  Components:  176 identified (purl on 100%, license declared on 96% (169 of 176))
```

The numbers come from the scan's own conformance measurement, so they match the `licenseCoverage` and `softwareComponentCount` fields of the conformance report, and the purl share counts the same packages as its purl check. The purl share is shown for CycloneDX results only. A warning line follows when something is off:

- `No software was identified`: the result has no components. Check that the scanned folder holds a manifest or lock file for a supported ecosystem.
- `No component declares a license`: no component declares one, so license checks have nothing to work with.
- `Reduced analysis`: a shallow fallback ran instead of the full analysis and only direct dependencies were identified. The line names the cause: out of disk space, out of memory, a failed download, or the dependency analyzer failing or not running.
- `Steps that failed`: post-processing steps that did not complete, by name. Details are in the log above.

The last two are not shown for `--analyze`, because they would describe the submitted document rather than this run. The summary does not change the exit code. To fail a run on these conditions, use `--fail-on empty-result` or `--fail-on license-coverage=<0-100>`. A scanner image that predates the summary prints only the file list.

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Scan succeeded |
| 1 | Scan failed (bad arguments, Docker unavailable, a required input missing, and similar) |
| 2 | `--fail-on-conformance`: the scan succeeded, but its own conformance report says "fail" |
| 3 | `--fail-on-conformance`: the scan succeeded, but produced no conformance report to judge |
| 4 | `--fail-on`: the scan succeeded, but at least one condition is met |
| 5 | `--fail-on`: the scan succeeded, but a condition could not be judged (for example the vulnerability database could not be downloaded, `license-conflict` without `--license`, or `empty-result` and `license-coverage=` when the scan wrote no conformance report or the report did not measure the SBOM's format), or the scan produced no result to judge |

2 to 5 are used only when the matching option is given; every scan that uses neither exits 0 or 1. Every `--fail-on` condition is printed with its verdict. When more than one code applies, the lowest wins: 2 and 3 (conformance) before 4, and 4 (a condition is met) before 5 (a condition could not be judged). "Could not be judged" is a failure on purpose: a scan that could not look is not a scan that found nothing, so an air-gapped run with no vulnerability database never passes a `vulnerability=` gate by accident.

## Pin the scanner image version

Override the scanner image with `SBOM_SCANNER_IMAGE`.

```bash
SBOM_SCANNER_IMAGE="ghcr.io/sktelecom/bomlens:<version>" \
  ./scripts/scan-sbom.sh --project "MyApp" --version "1.0.0" --generate-only
```

## Troubleshooting

### Windows: no outputs appear

If the scan finishes but no output files show up, check that the folder you ran from is inside a Docker file-sharing path. Anything under your home directory (`C:\Users\...`) is shared by default in both Rancher Desktop and Docker Desktop. From an unshared location the container cannot write results to the host.

### Docker permission error (Linux/WSL2)

```
Got permission denied while trying to connect to the Docker daemon
```

Does not apply on Windows/macOS with Rancher Desktop or Docker Desktop. Add your user to the `docker` group.

```bash
sudo usermod -aG docker $USER
newgrp docker
```

### Out of disk space

```
no space left on device
```

Prune the Docker cache. From a terminal:

```bash
docker system prune -f
```

With Rancher Desktop or Docker Desktop, the same cleanup is also available from the app's own Preferences screen.

### Interrupted build artifacts in the source tree

A source scan (`--target <dir>`, the web UI's folder scan, or the desktop app) runs build steps (`cargo generate-lockfile`, `go mod tidy`, `npm install`, and the like) against the scanned tree, then restores it: every file a build step changed or added is put back or removed. If that scan ends by SIGKILL, an out-of-memory kill, or a host crash, the restore never runs and the changes stay. The next scan of that same source tree restores them first, before doing anything else, once it has confirmed the earlier scan's container is no longer running.

### Leftover output-folder artifacts on re-scan

Re-scanning the same `--project`/`--version` reuses its output folder, however the earlier scan there ended. Before writing its own artifacts, the new scan removes any of BomLens's own files under that project/version that today's mode or options will not produce, so nothing from an earlier run with different options survives to be mistaken for this run's output. A file you placed in the folder yourself, or a different version's artifacts, is left alone.

### Anything else

1. Run the same command again and read the terminal output. The `[WARN]` and `[ERROR]` lines say what was skipped or what failed.
2. Update the Docker image: `docker pull ghcr.io/sktelecom/bomlens:latest`.
3. If it still fails, open a [GitHub Issue](https://github.com/sktelecom/bomlens/issues/new?template=bug_report.yml) with the command you ran and its terminal output. The issue form lists what it needs.

For how to use each mode, see the [input scenarios guide](../guides/by-input.md); for the kinds of outputs, see the [artifacts reference](artifacts.md); for language detection, see [supported ecosystems](ecosystems.md); to run scans in a pipeline, see [CI/CD integration](../guides/ci-cd.md).
