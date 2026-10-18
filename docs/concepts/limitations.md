---
description: What BomLens does not do or does only in part, so you can judge whether it fits before you try it.
---

# What BomLens does not do

This page is the list of limits we know about. Read it before you rely on a result.

## Running it

- It needs a Docker engine (20.10 or later). The desktop app and the web UI manage the image for you; the CLI asks you to pull it. There is no hosted service.
- The Windows installer is not code-signed yet, so Windows shows a SmartScreen warning on first run. Verify the file with [the release signature](../guides/verify-release.md).
- The web UI is a single-user tool for your own machine. It has no accounts and no access control, so do not expose its port to a network.
- The scanner image bundles third-party tools (Trivy, syft, grype, cosign and others). About 200 vulnerability findings on those bundled binaries are still open on the repository's code scanning page, because their upstream projects have not yet released a build with a fixed dependency. We update the tools when a fixed release exists and dismiss a finding only with the reason written on it.

## Finding dependencies

- A source scan finds dependencies in one of two ways. When a complete lock file covers the tree (`package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml`, `bun.lock` or `gradle.lockfile`, with no other manifest below the root), it reads the lock file. Otherwise it resolves the project by running its package manager in a container, which runs the project's own build steps (`pip install`, `go mod tidy`, `gradle`) and needs network access to the registries. `--detection` chooses; see the [CLI reference](../reference/cli.md).
- A project with no lock file and no way to resolve its dependencies comes out short. The scan says so (a banner and a record in the SBOM) instead of reporting a clean result.
- Reading a lock file statically does not fill the copyright notices that a build reads from downloaded packages. That is why Rust projects are always built.
- A static read takes the dependencies as the lock file states them. It does not tell you whether the lock file matches the code.

## Binaries and firmware

- A component statically linked into a binary is found only for a few libraries whose symbols the tool knows (ncurses, readline, quagga). Others are not identified, and the result does not list them. We do not yet mark a binary as "may contain statically linked components".
- Firmware analysis unpacks the image and reads package manager data, symbols and version strings. An encrypted region or an unsupported format is left unread and reported in the result's scope note.
- Version identification of a binary component is a match against what the file says about itself, so it can be wrong or missing. A component without a usable version is listed without one.

## Vulnerabilities and licenses

- Vulnerability matching uses Trivy's databases, and optionally NVD CPE matching (`--deep-cve`). A component without a package URL or a CPE cannot be matched. A result of "no vulnerabilities" means none were found in what was identified, which is why the report also says how many components could not be checked.
- Exploit signals (EPSS, CISA KEV) and the registry lookups for licenses need network access. Offline runs skip them and say so.
- License information is what the package declares, optionally read from the files with ScanCode (`--deep-license`). The license class and the conflict check are guidance, not legal advice.
- Reachability analysis (whether vulnerable code is called) exists only for Go.

## Formats

- Output is CycloneDX 1.6 (1.7 on request), with an SPDX export and an SPDX 3.0.1 AI document for AI models. Other formats are not written.
- The conformance check measures an SBOM against the 2026 minimum elements and other profiles. It checks what an SBOM states, not whether the statements are true.

Something here out of date, or a limit we missed? Please [open an issue](https://github.com/sktelecom/bomlens/issues).
