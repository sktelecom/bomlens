<p align="center">
  <img src="docs/images/logo.svg" alt="BomLens — an SBOM generator" width="300" />
</p>

> **BomLens** is a local-first [SBOM](https://sktelecom.github.io/sbom-tools/concepts/what-is-sbom/) generator and open-source risk assessor. It produces a CycloneDX SBOM, an open-source notice, and a security/license risk report for a single project in seconds — from source code, containers, binaries, firmware, an SBOM you received, or a HuggingFace AI model. CLI or browser UI, no SaaS.

[![GitHub release](https://img.shields.io/github/v/release/sktelecom/sbom-tools?style=flat-square)](https://github.com/sktelecom/sbom-tools/releases)
[![Container image](https://img.shields.io/badge/ghcr.io-bomlens-2496ED?style=flat-square&logo=docker&logoColor=white)](https://github.com/sktelecom/sbom-tools/pkgs/container/bomlens)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg?style=flat-square)](LICENSE)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/13059/badge)](https://www.bestpractices.dev/projects/13059)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/sktelecom/sbom-tools/badge)](https://securityscorecards.dev/viewer/?uri=github.com/sktelecom/sbom-tools)

<p align="center">
  <img src="docs/images/web-ui-demo.gif" alt="BomLens web UI showing a scan result: the Overview with counts and a severity/license summary, the Components table with filters, the Vulnerabilities list, the Dependencies as a graph and tree, and the Licenses section" width="860" />
</p>

**Where to start** — the full docs are a navigable site at **[sktelecom.github.io/sbom-tools](https://sktelecom.github.io/sbom-tools/)** (search, sidebar, English/Korean); the same content lives under [docs/](docs/):

- [First scan](docs/start/first-scan.md) ([한국어](docs/start/first-scan.ko.md)) — install and your first SBOM (desktop app, web UI, CLI)
- [No-CLI quick start](docs/start/no-cli.md) ([한국어](docs/start/no-cli.ko.md)) — no command line at all, click by click, for non-developers
- [CLI reference](docs/reference/cli.md) — every option and environment variable
- [Input scenarios](docs/guides/by-input.md) — GitHub URL, ZIP, local source, existing SBOM, firmware
- Contributing to the tool itself — [CONTRIBUTING](CONTRIBUTING.en.md) and the [architecture](docs/concepts/architecture.md); maintainer design notes live under [docs/maintainers/](docs/maintainers/) (Korean)

One Docker image, two jobs: **generate** — scan your source code (or a container image / binary) and produce a CycloneDX SBOM, an open-source notice, and a security report — and **assess open-source risk** in what you *receive*, such as a supplier's finished SBOM (`--analyze`) or a firmware binary (licenses + known vulnerabilities, with Critical-7d / High-30d remediation deadlines). Every scan emits the risk report by default. Originally built by SK Telecom for supply-chain security, now open source.

Languages: Java, Python, Node.js, Ruby, PHP, Rust, Go, .NET, Swift, C/C++ (Conan/vcpkg, or `--identify-vendored` for sources with no package manager). Inputs: source folder, GitHub URL, ZIP archive, Docker image, binary/RootFS, existing SBOM, firmware, and a HuggingFace AI model (CycloneDX ML-BOM).

![BomLens web UI — name a project, pick a scan target, and choose what to generate (SBOM, open-source notice, security report)](docs/images/web-ui-en.png)

## Quick Start

Everything runs on a Docker engine (20.10+). On Windows, free [Rancher Desktop](https://rancherdesktop.io/) works well, or WSL2 + docker-ce (fully free); Docker Desktop also works, with licensing caveats for larger organizations. The desktop app and web UI manage the image for you — only the CLI asks you to pull it.

### Desktop app — no command line (recommended)

Download the installer and double-click it — [BomLens-Setup.exe](https://github.com/sktelecom/sbom-tools/releases/latest/download/BomLens-Setup.exe) for Windows or [BomLens-Setup.dmg](https://github.com/sktelecom/sbom-tools/releases/latest/download/BomLens-Setup.dmg) for macOS. It checks Docker, pulls the image, and opens the UI — no console window. The app is unsigned for now; if Windows SmartScreen or macOS blocks it, the [no-CLI quick start](docs/start/no-cli.md) ([한국어](docs/start/no-cli.ko.md)) shows how to proceed — it also walks a non-developer through the common case of a source ZIP handed over by a dev team. Build details are in [`electron/`](electron/README.md).

![BomLens desktop app — the startup screen shows Docker checks, image download progress, and container startup](docs/images/desktop-startup-en.png)

### Web UI

Launch, scan, and download in the browser; live logs stream as it runs.

```bash
git clone https://github.com/sktelecom/sbom-tools.git && cd sbom-tools
./scripts/scan-sbom.sh --ui     # opens http://localhost:8080; results save to the current folder
#   Windows: double-click scripts\sbom-ui.bat
```

Enter a project name and version, pick a scan target (current folder, GitHub URL, ZIP, SBOM, firmware upload, or Docker image), click Run scan, then view or download the results.

![BomLens web UI — reviewing a finished scan: needs-attention, component and vulnerability counts, the severity distribution and the license summary](docs/images/web-ui-scan-en.png)

### CLI (advanced)

```bash
docker pull ghcr.io/sktelecom/bomlens:latest   # aliases: sbom-generator and sbom-scanner serve the same image
./scripts/scan-sbom.sh --project MyApp --version 1.0.0 --target examples/nodejs --all --generate-only
```

On Windows, run the same command through `scripts\scan-sbom.bat` (Git for Windows required). Other inputs — GitHub URL, source archive, Docker image, firmware — and every option are in the [input-scenarios guide](docs/guides/by-input.md) and the [CLI reference](docs/reference/cli.md).

Outputs (in a `{Project}_{Version}/` subfolder, files prefixed `{Project}_{Version}_…`): `bom.json` (SBOM), `NOTICE.{txt,html}`, `risk-report.{md,html}` (default), and `security.{json,md,html}` (Trivy). Add `--spdx` for an SPDX 2.3 copy of the SBOM (`bom.spdx.json`).

## Contributing & License

Issues and PRs welcome — see [CONTRIBUTING.md](CONTRIBUTING.en.md) ([한국어](CONTRIBUTING.md)) and [GitHub Issues](https://github.com/sktelecom/sbom-tools/issues).

Apache License 2.0 · © 2026 SK Telecom Co., Ltd. Bundled third-party tools keep their own licenses — see [NOTICE](NOTICE) and [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).
