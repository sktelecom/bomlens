<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/images/logo-dark.svg" />
    <img src="docs/images/logo.svg" alt="BomLens" width="220" />
  </picture>
</p>

<h1 align="center">BomLens</h1>

> **BomLens** is a local-first [SBOM](https://sktelecom.github.io/bomlens/concepts/what-is-sbom/) generator and open-source risk assessor. It produces a CycloneDX SBOM, an open-source notice, and a security and license risk report for a single project in seconds — from source code, a container, a binary, firmware, an SBOM you received, or a HuggingFace AI model. CLI or browser UI, no SaaS. BomLens is an [OWASP Incubator project](https://owasp.org/www-project-bomlens/).

[![GitHub release](https://img.shields.io/github/v/release/sktelecom/bomlens?style=flat-square)](https://github.com/sktelecom/bomlens/releases)
[![Container image](https://img.shields.io/badge/ghcr.io-bomlens-2496ED?style=flat-square&logo=docker&logoColor=white)](https://github.com/sktelecom/bomlens/pkgs/container/bomlens)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg?style=flat-square)](LICENSE)
[![OWASP Incubator](https://img.shields.io/badge/OWASP-Incubator-blue?style=flat-square)](https://owasp.org/www-project-bomlens/)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/13059/badge)](https://www.bestpractices.dev/projects/13059)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/sktelecom/bomlens/badge)](https://securityscorecards.dev/viewer/?uri=github.com/sktelecom/bomlens)

한국어 문서: [sktelecom.github.io/bomlens/ko](https://sktelecom.github.io/bomlens/ko/). 한국어로 질문하거나 이슈를 남겨도 됩니다.

Try it without installing anything: the [live demo](https://sktelecom.github.io/bomlens/demo/) holds one finished scan of each kind (source, container image, firmware, AI model, supplier SBOM). It is read-only and nothing is uploaded. To run your own scans, download the installer for [Windows](https://github.com/sktelecom/bomlens/releases/latest/download/BomLens-Setup.exe) or [macOS](https://github.com/sktelecom/bomlens/releases/latest/download/BomLens-Setup.dmg), or go straight to the [CLI](#cli-advanced).

<p align="center">
  <img src="docs/images/web-ui-demo.png" alt="BomLens web UI Overview screen for a finished scan: component/vulnerability/dependency/artifact counts, a needs-attention banner, and the severity and license classification distributions" width="860" />
</p>

## Why it exists

SK Telecom asks its suppliers to submit an SBOM. BomLens lets a supplier produce one that meets the [submission requirements](https://sktelecom.github.io/guide/supply-chain/for-suppliers/requirements/), see what is in its software, and act on the vulnerabilities found. The `skt-submission` conformance profile checks an SBOM against those requirements ([supplier SBOM guide](docs/guides/supplier-sbom.md)). Anyone can use it, whether or not they supply SK Telecom.

BomLens runs on one machine and does not manage a whole organization's open source. For company-wide governance SK Telecom uses [TRUSCA](https://github.com/trustedoss/trusca), an open source SCA platform that can run BomLens as its scan engine. The CycloneDX output can also be uploaded to Dependency-Track ([upload guide](docs/guides/upload.md)).

## What it does

One Docker image, two jobs. It **generates**: scan your source code, a container image, or a binary and get a CycloneDX SBOM, an open-source notice, and a security report. It also **assesses open-source risk** in what you receive, such as a supplier's finished SBOM (`--analyze`) or a firmware binary, reporting licenses and known vulnerabilities with Critical-7d / High-30d remediation deadlines. Every scan emits the risk report by default.

Languages: Java, Python, Node.js, Ruby, PHP, Rust, Go, .NET, Swift, C/C++ (Conan/vcpkg, or `--identify-vendored` without a package manager) and Modelica (direct `uses(...)` only). Inputs: a source folder, a GitHub URL, a ZIP archive, a Docker image, a binary or RootFS, an existing SBOM, a Yocto build directory, firmware, and AI models and datasets (a HuggingFace model, a model file read offline, a Figshare or HuggingFace dataset, or a model described by its publisher's declaration with `--ai-declare`). AI scans produce a CycloneDX ML-BOM checked against the [G7 minimum elements for AI](https://sktelecom.github.io/bomlens/guides/ai-model/) and an SPDX 3.0.1 document; what a scan cannot know is asked for in the web UI rather than guessed.

BomLens is under active development at SK Telecom's open source program office. Releases go out every week or two, and every change runs through CI (ShellCheck, scanner integration tests, web UI tests, and the ten example projects).

Full docs — searchable, English and Korean — live at **[sktelecom.github.io/bomlens](https://sktelecom.github.io/bomlens/)**, mirrored under [docs/](docs/):

- [First scan](docs/start/first-scan.md) ([한국어](docs/start/first-scan.ko.md)) — install through your first SBOM
- [No-CLI quick start](docs/start/no-cli.md) ([한국어](docs/start/no-cli.ko.md)) — click by click, for non-developers
- [Input scenarios](docs/guides/by-input.md) — GitHub URL, ZIP, local source, an existing SBOM, firmware
- [CLI reference](docs/reference/cli.md) — every option and environment variable
- [CI/CD integration](docs/guides/ci-cd.md) — gate a pipeline on scan results
- [Verify a release](docs/guides/verify-release.md) — check the signatures and read the SBOM that ships with the image
- [What BomLens does not do](docs/concepts/limitations.md) — the limits we know about
- Contributing to the tool itself — [CONTRIBUTING](CONTRIBUTING.md) and the [architecture](docs/concepts/architecture.md)

## Quick Start

Everything runs on a Docker engine (20.10+). The desktop app and web UI manage the image for you; only the CLI asks you to pull it. On Windows, the desktop app needs [Rancher Desktop](https://rancherdesktop.io/) (free) or Docker Desktop (licensing caveats for larger organizations). WSL2 + docker-ce also works, but for the CLI only: the desktop app cannot see a Docker engine inside WSL2.

### Desktop app — no command line (recommended)

Download the installer and double-click it: [BomLens-Setup.exe](https://github.com/sktelecom/bomlens/releases/latest/download/BomLens-Setup.exe) for Windows or [BomLens-Setup.dmg](https://github.com/sktelecom/bomlens/releases/latest/download/BomLens-Setup.dmg) for macOS. It checks Docker, pulls the image, and opens the UI — no console window. The app is unsigned for now; if Windows SmartScreen or macOS blocks it, the [no-CLI quick start](docs/start/no-cli.md) ([한국어](docs/start/no-cli.ko.md)) shows how to proceed. Build details are in [`electron/`](electron/README.md).

![BomLens web UI — name a project, pick a scan target, and choose what to generate (SBOM, open-source notice, security report)](docs/images/web-ui-en.png)

### Web UI

```bash
git clone --depth 1 https://github.com/sktelecom/bomlens.git && cd bomlens   # --depth 1: about 50 MB instead of the full history
./scripts/scan-sbom.sh --ui     # opens http://localhost:8080; results save to the current folder
#   Windows: double-click scripts\sbom-ui.bat
```

> **PowerShell**: don't paste the block above as-is — `.sh` has no default handler there, so it fails silently with no error and no output. Double-click `scripts\sbom-ui.bat` instead.

The first load can take up to a minute while the image is checked; reload the tab if it shows a connection error. Enter a project name and version, pick a scan target, click Run scan, then view or download the results. To scan a folder outside the launch directory, add `--mount <dir>` (repeatable); the desktop app has an Add folder button for the same.

### CLI (advanced)

```bash
docker pull ghcr.io/sktelecom/bomlens:latest   # aliases: sbom-generator and sbom-scanner serve the same image
./scripts/scan-sbom.sh --project MyApp --version 1.0.0 --target examples/nodejs --all --generate-only
```

**PowerShell**: `docker pull` above works as-is, but the second line does not — `./scripts/scan-sbom.sh` has no default handler in PowerShell and fails silently with no error and no output. Run the same command through `scripts\scan-sbom.bat` instead (Git for Windows required). Outputs land in a `{Project}_{Version}/` subfolder, prefixed `{Project}_{Version}_…`: `bom.json` (SBOM), `NOTICE.{txt,html}`, `risk-report.{md,html}`, and `security.{json,md,html}`; add `--spdx` for an SPDX 2.3 copy. Other inputs and every option are in the [CLI reference](docs/reference/cli.md) and the [input-scenarios guide](docs/guides/by-input.md).

## Contributing & License

Issues and PRs welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) ([한국어](CONTRIBUTING.ko.md)) and [GitHub Issues](https://github.com/sktelecom/bomlens/issues). For questions, where to ask and what to include are in [SUPPORT.md](SUPPORT.md).

Apache License 2.0 · © 2026 SK Telecom Co., Ltd. Bundled third-party tools keep their own licenses — see [NOTICE](NOTICE) and [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).
