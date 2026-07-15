<p align="center">
  <img src="docs/images/logo.svg" alt="BomLens — an SBOM generator" width="300" />
</p>

<h1 align="center">BomLens</h1>

> **BomLens** is a local-first [SBOM](https://sktelecom.github.io/bomlens/concepts/what-is-sbom/) generator and open-source risk assessor. It produces a CycloneDX SBOM, an open-source notice, and a security and license risk report for a single project in seconds — from source code, a container, a binary, firmware, an SBOM you received, or a HuggingFace AI model. CLI or browser UI, no SaaS.

[![GitHub release](https://img.shields.io/github/v/release/sktelecom/bomlens?style=flat-square)](https://github.com/sktelecom/bomlens/releases)
[![Container image](https://img.shields.io/badge/ghcr.io-bomlens-2496ED?style=flat-square&logo=docker&logoColor=white)](https://github.com/sktelecom/bomlens/pkgs/container/bomlens)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg?style=flat-square)](LICENSE)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/13059/badge)](https://www.bestpractices.dev/projects/13059)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/sktelecom/bomlens/badge)](https://securityscorecards.dev/viewer/?uri=github.com/sktelecom/bomlens)

<p align="center">
  <img src="docs/images/web-ui-demo.gif" alt="BomLens web UI showing a scan result: the Overview with counts and a severity/license summary, the Components table with filters, the Vulnerabilities list, the Dependencies as a graph and tree, and the Licenses section" width="860" />
</p>

## What it does

One Docker image, two jobs. It **generates**: scan your source code, a container image, or a binary and get a CycloneDX SBOM, an open-source notice, and a security report. It also **assesses open-source risk** in what you receive — a supplier's finished SBOM (`--analyze`) or a firmware binary — reporting licenses and known vulnerabilities with Critical-7d / High-30d remediation deadlines. Every scan emits the risk report by default. Originally built by SK Telecom for supply-chain security, now open source.

Languages: Java, Python, Node.js, Ruby, PHP, Rust, Go, .NET, Swift, C/C++ (Conan/vcpkg, or `--identify-vendored` when there is no package manager). Inputs: a source folder, a GitHub URL, a ZIP archive, a Docker image, a binary or RootFS, an existing SBOM, firmware, or a HuggingFace AI model (CycloneDX ML-BOM).

Full docs — searchable, English and Korean — live at **[sktelecom.github.io/bomlens](https://sktelecom.github.io/bomlens/)**, mirrored under [docs/](docs/):

- [First scan](docs/start/first-scan.md) ([한국어](docs/start/first-scan.ko.md)) — install through your first SBOM
- [No-CLI quick start](docs/start/no-cli.md) ([한국어](docs/start/no-cli.ko.md)) — click by click, for non-developers
- [Input scenarios](docs/guides/by-input.md) — GitHub URL, ZIP, local source, an existing SBOM, firmware
- [CLI reference](docs/reference/cli.md) — every option and environment variable
- Contributing to the tool itself — [CONTRIBUTING](CONTRIBUTING.en.md) and the [architecture](docs/concepts/architecture.md)

## Quick Start

Everything runs on a Docker engine (20.10+). The desktop app and web UI manage the image for you; only the CLI asks you to pull it. On Windows, free [Rancher Desktop](https://rancherdesktop.io/) or WSL2 + docker-ce works well; Docker Desktop also works, with licensing caveats for larger organizations.

### Desktop app — no command line (recommended)

Download the installer and double-click it: [BomLens-Setup.exe](https://github.com/sktelecom/bomlens/releases/latest/download/BomLens-Setup.exe) for Windows or [BomLens-Setup.dmg](https://github.com/sktelecom/bomlens/releases/latest/download/BomLens-Setup.dmg) for macOS. It checks Docker, pulls the image, and opens the UI — no console window. The app is unsigned for now; if Windows SmartScreen or macOS blocks it, the [no-CLI quick start](docs/start/no-cli.md) ([한국어](docs/start/no-cli.ko.md)) shows how to proceed. Build details are in [`electron/`](electron/README.md).

![BomLens web UI — name a project, pick a scan target, and choose what to generate (SBOM, open-source notice, security report)](docs/images/web-ui-en.png)

### Web UI

```bash
git clone https://github.com/sktelecom/bomlens.git && cd bomlens
./scripts/scan-sbom.sh --ui     # opens http://localhost:8080; results save to the current folder
#   Windows: double-click scripts\sbom-ui.bat
```

Enter a project name and version, pick a scan target (current folder, GitHub URL, ZIP, SBOM, firmware upload, or Docker image), click Run scan, then view or download the results; live logs stream as it runs.

### CLI (advanced)

```bash
docker pull ghcr.io/sktelecom/bomlens:latest   # aliases: sbom-generator and sbom-scanner serve the same image
./scripts/scan-sbom.sh --project MyApp --version 1.0.0 --target examples/nodejs --all --generate-only
```

On Windows, run the same command through `scripts\scan-sbom.bat` (Git for Windows required). Outputs land in a `{Project}_{Version}/` subfolder, prefixed `{Project}_{Version}_…`: `bom.json` (SBOM), `NOTICE.{txt,html}`, `risk-report.{md,html}`, and `security.{json,md,html}`; add `--spdx` for an SPDX 2.3 copy. Other inputs and every option are in the [CLI reference](docs/reference/cli.md) and the [input-scenarios guide](docs/guides/by-input.md).

## Contributing & License

Issues and PRs welcome — see [CONTRIBUTING.md](CONTRIBUTING.en.md) ([한국어](CONTRIBUTING.md)) and [GitHub Issues](https://github.com/sktelecom/bomlens/issues).

Apache License 2.0 · © 2026 SK Telecom Co., Ltd. Bundled third-party tools keep their own licenses — see [NOTICE](NOTICE) and [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).
