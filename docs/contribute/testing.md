---
description: The BomLens test structure — how to run the suites, write new tests, and debug failures.
---

# Testing guide

This guide explains the test structure of BomLens, how to run and write tests, and how to debug failures.

## Test structure

```
tests/
├── test-scan.sh              # Main integration suite — 15 inline test blocks, one per
│                              # language/input type (Node.js, Python, Java Maven, Ruby, PHP,
│                              # Rust, Docker image, binary file, rootfs directory, ZIP archive, ...)
├── test-e2e.sh                # Other end-to-end suites (CLI, examples, web UI, AI-BOM, ...)
├── test-examples-e2e.sh
├── test-web-e2e.sh
├── test-web-ui.sh
├── test-android-scope.sh      # Standalone regression scripts, one script per concern —
├── test-aibom.sh              # each defines its own local pass()/fail() helpers rather
├── test-firmware-unpack.sh    # than sharing a library
├── test-real-corpus.sh        # Scans pinned public repositories (see below)
├── ...
├── lib/
│   ├── snapshot-normalize.jq  # Shared jq helper used by the snapshot tests
│   └── corpus-compare.sh      # Judges a corpus run against an earlier run and fixed floors
├── corpus/                    # The repository list and the license coverage floors
├── fixtures/                  # Input fixtures used by the standalone scripts
└── snapshots/                 # Expected-output snapshots compared by test-snapshot.sh
```

There is no `tests/helpers/` or `tests/cases/` directory. `test-scan.sh` defines a small set of helper functions near the top of the file (`run_scan_with_logs`, `find_bom_file`, `assert_bom_sane`, `assert_spdx_sane`, `assert_root_has_direct_deps`, `show_failure_log`), then runs its 15 test blocks one after another in the same script. Each block is a few lines: create a fixture project under the test workspace, run a scan, and check the result with `jq` or one of those helpers.

The standalone scripts under `tests/` (`test-android-scope.sh`, `test-aibom.sh`, and the rest) don't share this machinery — each defines its own small local helpers as needed. Read an existing one before writing a new one.

## Running tests

### Run all tests

```bash
./tests/test-scan.sh
```

Example output on success (abbreviated — a real run prints 15 `[TEST]`/`[✓]` pairs):

```
==========================================
 SBOM Generator - Integration Test
 Version: 1.0.0
==========================================

[INFO] Checking prerequisites...
[✓] Docker check passed
[✓] Scan script check passed

[INFO] Starting tests...

[TEST] Test 1/15: Node.js project (npm)
[✓] Node.js project (2 components)
...
[TEST] Test 15/15: --timestamp run folder
[✓] --timestamp run folder created (./Stamped_1.0.0_.../)

==========================================
 Test Summary
==========================================

Total tests: 15
Passed: 15
Failed: 0
Success rate: 100.0%
```

### Run a single case without running the whole suite

`test-scan.sh` has no flag to run just one of its 15 blocks. To check a single language or input type in isolation, run the scan directly against the fixture or example you care about:

```bash
./scripts/scan-sbom.sh --project Test --version 1.0.0 --target examples/nodejs --generate-only
```

The standalone scripts, on the other hand, are already independent and can be run one at a time:

```bash
./tests/test-android-scope.sh
./tests/test-aibom.sh
```

## Real-repository corpus

The bundled examples are small and carry no lock files. `tests/test-real-corpus.sh` scans 17 public repositories (`tests/corpus/real-corpus.tsv`: two or more per ecosystem, each pinned to a commit) with the scanner and reports, for each one, the component count, the share of components with a purl and with a license, the exit code, the time taken and whether the scan left the checkout changed. Build output the repository itself ignores counts as a change.

Each repository ends in one of these states:

| State | Meaning |
|---|---|
| `ok` | Software was found |
| `empty` | The scan identified no software (`--fail-on empty-result`) |
| `failed` | The scan failed, or wrote no readable SBOM |
| `timeout` | The scan did not finish within `SCAN_TIMEOUT` (enforced only where GNU `timeout` or `gtimeout` is installed) |
| `undetermined` | No quality result: the repository could not be fetched, or the scan could not judge (exit 5) |

The run fails on `empty`, `failed`, `timeout`, a changed source tree, or a license coverage regression. A run where nothing could be measured also fails. Coverage is judged per ecosystem as the mean over the repositories that were `ok`, in two ways. In the workflow it is compared with the newest successful run on `main` that covered the whole corpus (a fall of 10 points or more fails, when at least two repositories were compared; locally this happens only when you pass `BASELINE_FILE`). It is also compared with the floors in `tests/corpus/license-floor.tsv`, which apply with or without an earlier run. Lowering a floor goes through review, which keeps a slow decline visible.

Run it locally with Docker running. The clones and results go to `~/.cache/bomlens-real-corpus`. If you point `WORK_DIR` elsewhere, keep it under your home directory when Docker runs in Colima:

```bash
ONLY="cobra logrus" ./tests/test-real-corpus.sh   # some repositories
ECOSYSTEMS="go rust" ./tests/test-real-corpus.sh  # some ecosystems
```

With a scanner image older than `--fail-on`, set `FAIL_ON_ARGS=""`. An empty result is then recognised from the SBOM. `SCAN_TIMEOUT` (seconds per repository, default 900; the workflow uses 1200), `WORK_DIR`, `CORPUS_FILE`, `SBOM_SCANNER_IMAGE`, `BASELINE_FILE` and `DROP_POINTS` are described in the script header.

The `Real-repository corpus` workflow (`real-corpus.yml`) runs it every night and on demand, on a runner that builds the scanner image from the commit, and takes 20 to 25 minutes. It never runs on pull requests and is not a required check. The results table is in the run summary, and `results.tsv` is kept as the `real-corpus-results` artifact of every run; the next run takes the newest successful, complete one as its baseline. To start it by hand: `gh workflow run real-corpus.yml` (the `ecosystems` input limits it; a limited run does not become a baseline).

## Execution modes

| Environment variable | Value | Effect |
|-----------|-----|----------|
| (none) | — | Prints only the `[TEST]`/`[✓]`/`[✗]` pass-fail lines; per-step output goes to a log file |
| `VERBOSE` | `true` | Also prints key progress lines filtered from the scan output (`INFO`/`WARN`/`ERROR`, `Analyzing`, `Downloading`, `components`, `cdxgen`, `syft`) |
| `DEBUG_MODE` | `true` | Streams the full scan output in real time (Docker, cdxgen, syft) and preserves the test workspace on exit instead of cleaning it up |

```bash
# Verbose mode
VERBOSE=true ./tests/test-scan.sh

# Debug mode (for troubleshooting; also preserves tests/test-workspace/)
DEBUG_MODE=true ./tests/test-scan.sh
```

Several standalone scripts (`test-android-scope.sh`, for example) also honor `VERBOSE` — check the script's own header comment for the env vars it reads.

## Writing tests

There is no per-language file to create. To add coverage for a new language or ecosystem, extend the existing suite:

1. Open `tests/test-scan.sh` and add a new block, following the pattern of an existing one (Test 3, the Java Maven block, is a good template). Create the fixture project under the test workspace, call `run_scan_with_logs`, locate the resulting BOM with `find_bom_file`, and assert on it with `jq` or with `assert_bom_sane` / `assert_spdx_sane` / `assert_root_has_direct_deps` for the checks those already cover. Increment `PASSED` or `FAILED` and call `show_failure_log` on failure, matching the surrounding blocks.
2. Each block's `print_test` label is hand-numbered ("Test N/15"). Renumber the labels after inserting a block, and update the total in the `--help` text and the summary banner at the top of the script.
3. If the case doesn't fit the source-scan pattern — an image- or rootfs-specific edge case, a reproducibility check, AI-BOM behavior, a slow network-dependent regression — add a new `tests/test-<name>.sh` script instead. Follow an existing one such as `test-android-scope.sh`: define local `pass()`/`fail()` helpers, skip early when a required tool or image is unavailable, and wire the script into the relevant CI workflow (`ci.yml` for the per-PR lane, `nightly.yml` for slow or network-dependent checks).

For the full walkthrough of adding a new language end to end — detection, build-prep, an example project, and the docs to update — see the [package manager guide](package-managers.md).

## Helper function reference

These are defined near the top of `tests/test-scan.sh` and used by its own test blocks; they aren't a shared library available to other scripts.

| Function | Checks |
|------|-------------|
| `assert_bom_sane <file> <project>` | The file is CycloneDX, `metadata.component.name` matches the input project name, and `components` is an array |
| `assert_spdx_sane <file>` | The file is a valid SPDX 2.x document (`spdxVersion` starts with `SPDX-`, `SPDXID` is `SPDXRef-DOCUMENT`, `packages` is an array) |
| `assert_root_has_direct_deps <file>` | The root component's entry in `dependencies` has a non-empty `dependsOn` |
| `find_bom_file <project> <version>` | Locates the generated BOM, across both the current per-run subfolder layout and the legacy flat layout |

Beyond these, most assertions in the suite are plain `jq -e '...'` expressions against the generated BOM — there is no broader assertion library. The standalone scripts define their own small helpers where they need one (`test-android-scope.sh`'s `count()` and `has_direct()`, for example).

### Test writing principles

**Independence.** Each test must not depend on another. Results must stay the same regardless of order.

**Cleanup.** `test-scan.sh` already removes the workspace (except logs) on exit through a single `trap cleanup EXIT` — a new block inside it doesn't need its own teardown, just `cd` back to `$TEST_DIR` when done. A standalone script is responsible for cleaning up its own workspace.

**Clear names.** The string passed to `print_test`/`print_success`/`print_error` should say what the block verifies, not just which language it covers.

**Minimal assertions.** Assert what the change is meant to guard and no more.

## Logging and debugging

### Inspecting the generated SBOM directly

```bash
# Count components
jq '.components | length' NodeExample_1.0.0_bom.json

# List all PURLs
jq '[.components[].purl]' NodeExample_1.0.0_bom.json

# List licenses
jq '[.components[].licenses[]?.license.id] | unique' NodeExample_1.0.0_bom.json
```

### Debugging a specific failure

```bash
# Preserves tests/test-workspace/ so you can inspect the fixture and the BOM after the run
DEBUG_MODE=true ./tests/test-scan.sh

# Or debug a standalone script directly
VERBOSE=true ./tests/test-android-scope.sh
```

## CI integration

### GitHub Actions

`ci.yml` runs the main suite and, on failure, uploads the logs it preserved:

```yaml
- name: Run integration tests
  run: |
    VERBOSE=true ./tests/test-scan.sh

- name: Upload test logs on failure
  if: failure()
  uses: actions/upload-artifact@v4
  with:
    name: test-logs
    path: tests/test-workspace/failed-tests-logs/
```

The standalone scripts are wired in as their own steps rather than being called from `test-scan.sh` — for example `bash tests/test-aibom.sh` runs in `ci.yml`, while the slower, network-dependent `test-android-scope.sh` runs in `nightly.yml`. The real-repository corpus has its own scheduled workflow, `real-corpus.yml`.

### What to do when tests fail

1. Rerun with `DEBUG_MODE=true` and review the detailed logs.
2. Run `scan-sbom.sh` directly in the example directory of the failing language.
3. Update the Docker image to the latest version: `docker pull ghcr.io/sktelecom/bomlens:latest`
4. If the problem persists, report it on [GitHub Issues](https://github.com/sktelecom/bomlens/issues) with your environment details and logs.

---

> **Related**: [Contributing](https://github.com/sktelecom/bomlens/blob/main/CONTRIBUTING.md) | [Architecture](../concepts/architecture.md) | [Adding a package manager](package-managers.md)
</content>
