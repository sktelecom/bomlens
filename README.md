<p align="center">
  <img src="docs/images/logo.svg" alt="BomLens — an SBOM generator" width="300" />
</p>

> **BomLens** is a local-first SBOM generator and open-source risk assessor. It produces a CycloneDX SBOM, an open-source notice, and a security/license risk report for a single project in seconds — from source code, containers, binaries, firmware, or an SBOM you received. CLI or browser UI, no SaaS.

[![GitHub release](https://img.shields.io/github/v/release/sktelecom/sbom-tools?style=flat-square)](https://github.com/sktelecom/sbom-tools/releases)
[![Container image](https://img.shields.io/badge/ghcr.io-bomlens-2496ED?style=flat-square&logo=docker&logoColor=white)](https://github.com/sktelecom/sbom-tools/pkgs/container/bomlens)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg?style=flat-square)](LICENSE)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/13059/badge)](https://www.bestpractices.dev/projects/13059)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/sktelecom/sbom-tools/badge)](https://securityscorecards.dev/viewer/?uri=github.com/sktelecom/sbom-tools)

<p align="center">
  <img src="docs/images/web-ui-demo.gif" alt="BomLens web UI reviewing a scan result: KPI cards and severity/license summary, filtering the components table, expanding a vulnerability row to its CVSS score, description and references, viewing dependencies as a graph and tree, and browsing the source tree" width="860" />
</p>

**Where to start:**

- **Using the tool** — generate an SBOM, an open-source notice, or a security report, or assess a binary or an SBOM you received. Start with [First scan](docs/start/first-scan.md) ([한국어](docs/start/first-scan.ko.md)). On Windows and prefer no command line? [Download BomLens for Windows (.exe)](https://github.com/sktelecom/sbom-tools/releases/latest/download/SBOM-Generator-Setup.exe) and double-click — the [no-CLI quick start](docs/start/no-cli.ko.md) (Korean) walks through it.
- **Contributing to the tool itself** — building the image, the pipeline internals, or adding a package manager? See [CONTRIBUTING](CONTRIBUTING.en.md) and the [architecture](docs/concepts/architecture.md).

A Docker engine is required either way; the free [Rancher Desktop](https://rancherdesktop.io/) works well on Windows.

One Docker image, two jobs:

- **Generate** — scan your source code (or a container image / binary) and produce a CycloneDX SBOM, an open-source notice, and a security report.
- **Assess open-source risk** — analyze what you *receive*, including a supplier's finished SBOM or a firmware binary, and produce an open-source risk report (licenses + known vulnerabilities, with Critical-7d / High-30d remediation deadlines).

Every scan also emits the risk report by default. Run it from the CLI or a browser UI. Originally built by SK Telecom for supply-chain security, now open source.

Languages: Java, Python, Node.js, Ruby, PHP, Rust, Go, .NET, C/C++ (Conan/vcpkg). Inputs: source folder, GitHub URL, ZIP archive, Docker image, binary/RootFS, existing SBOM, firmware.

![BomLens web UI — name a project, pick a scan target, and choose what to generate (SBOM, open-source notice, security report)](docs/images/web-ui-en.png)

## Quick Start

Prerequisite: a Docker engine, 20.10+. Free options that work on Windows: **Rancher Desktop** (GUI; supports the `.bat` double-click flow) or **WSL2 + docker-ce** (run the tool from inside WSL — fully free, no Windows named-pipe needed). Docker Desktop also works but requires a paid license for larger organizations. The Web UI needs nothing else; the Windows CLI wrapper additionally needs Git for Windows (Git Bash).

```bash
git clone https://github.com/sktelecom/sbom-tools.git && cd sbom-tools
docker pull ghcr.io/sktelecom/bomlens:latest   # aliases: sbom-generator and sbom-scanner serve the same image
```

No git installed? Download the repo as a ZIP from the GitHub page (the green Code button, then Download ZIP) and unzip it.

### Web UI — easiest (no CLI needed)

Launch, scan, and download — all in the browser. Live logs stream as it runs.

![BomLens web UI — a scan in progress with live logs](docs/images/web-ui-scan-en.png)

```bash
cd ~/sbom-output     # any folder — this is where results are saved
/path/to/sbom-tools/scripts/scan-sbom.sh --ui     # opens http://localhost:8080
#   Windows: double-click scripts\sbom-ui.bat
```

Enter the project name and version, pick a scan target (current folder, GitHub URL, ZIP, SBOM, firmware upload, or Docker image), click Run scan, then view or download the results.

#### Windows, no CLI — from a source ZIP you received

A common case: a dev team handed you a source archive and you need its SBOM. The [no-CLI quick start](docs/start/no-cli.ko.md) walks through this step by step in Korean for non-developers; the short version is below.

1. Install and start a Docker engine. **Rancher Desktop** is a free, drop-in choice for this double-click flow; Docker Desktop also works (with licensing caveats for organizations).
2. Get this repo: on the GitHub page use the green Code button, then Download ZIP, and unzip it.
3. Pick a folder for the results under your home directory, such as `C:\Users\you\sbom-output`. It must sit inside a path your Docker engine is allowed to share (file sharing); `C:\Users` is shared by default in both Rancher Desktop and Docker Desktop.
4. Double-click `scripts\sbom-ui.bat`. A browser opens at http://localhost:8080.
5. Enter a project name and version, choose ZIP upload as the scan target, upload the source ZIP you received, run the scan, then download the SBOM, the notice, and the risk report.

The [first-scan guide](docs/start/first-scan.md) covers this in more detail and shows the CLI path.

Prefer a real app over a `.bat`? A desktop app wraps this same flow with no console window — it checks Docker, pulls the image, and opens the UI on double-click. Download `SBOM-Generator-*.exe` (or `.dmg`) from the [latest release](https://github.com/sktelecom/sbom-tools/releases/latest). It is unsigned for now, so if Windows SmartScreen warns, click **More info** and then **Run anyway**. Build details are in [`electron/`](electron/README.md).

![BomLens desktop app — the startup screen shows Docker checks, image download progress, and container startup](docs/images/desktop-startup-en.png)

### CLI

```bash
# All deliverables for the current project
./scripts/scan-sbom.sh --project MyApp --version 1.0.0 --all --generate-only

# Other inputs: GitHub URL · source archive · Docker image · firmware
./scripts/scan-sbom.sh --git https://github.com/org/repo --project MyApp --version 1.0.0 --all --generate-only
./scripts/scan-sbom.sh --target ./src.zip      --project MyApp --version 1.0.0 --all --generate-only
./scripts/scan-sbom.sh --target nginx:latest   --project MyApp --version 1.0.0 --all --generate-only
./scripts/scan-sbom.sh --target dev.bin --firmware --project MyApp --version 1.0.0 --all --generate-only
```

On Windows, run the same commands through `scripts\scan-sbom.bat`, which forwards them to the script via Git Bash (Git for Windows required).

Outputs (`{Project}_{Version}_…`): `bom.json` (SBOM), `NOTICE.{txt,html}`, `risk-report.{md,html}` (default), and `security.{json,md,html}` (Trivy). Each input form is covered in the [input-scenarios guide](docs/guides/by-input.md).

## Documentation

The full docs — getting started, task guides, reference, and concepts — are a navigable site at **[sktelecom.github.io/sbom-tools](https://sktelecom.github.io/sbom-tools/)** (search, sidebar, English/Korean). The same content lives under [docs/](docs/) in this repo. The site and the web UI are bilingual, English by default with Korean available.

A few entry points:

- [First scan](docs/start/first-scan.md) — install and your first SBOM (web UI + CLI)
- [No-CLI quick start](docs/start/no-cli.ko.md) — desktop app or `.bat`, for non-developers (Korean)
- [CLI reference](docs/reference/cli.md) — every option and environment variable
- [Input scenarios](docs/guides/by-input.md) — GitHub URL, ZIP, local source, existing SBOM, firmware
- [Architecture](docs/concepts/architecture.md) — the two-stage pipeline; maintainer design notes live under [docs/internal/](docs/internal/) (Korean)

## Contributing & License

Issues and PRs welcome — see [CONTRIBUTING.md](CONTRIBUTING.en.md) ([한국어](CONTRIBUTING.md)) and [GitHub Issues](https://github.com/sktelecom/sbom-tools/issues).

Apache License 2.0 · © 2026 SK Telecom Co., Ltd. Bundled third-party tools keep their own licenses — see [NOTICE](NOTICE) and [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).
