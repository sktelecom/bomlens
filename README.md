# SBOM Generator

> Automated SBOM (CycloneDX 1.6) generation for supply chain security

[![GitHub release](https://img.shields.io/github/v/release/sktelecom/sbom-tools?style=flat-square)](https://github.com/sktelecom/sbom-tools/releases)
[![Container image](https://img.shields.io/badge/ghcr.io-sbom--generator-2496ED?style=flat-square&logo=docker&logoColor=white)](https://github.com/sktelecom/sbom-tools/pkgs/container/sbom-generator)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg?style=flat-square)](LICENSE)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/13059/badge)](https://www.bestpractices.dev/projects/13059)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/sktelecom/sbom-tools/badge)](https://securityscorecards.dev/viewer/?uri=github.com/sktelecom/sbom-tools)

> **Windows에서 명령줄 없이 시작하려면** [라이선스 담당자용 빠른 시작](docs/notice-quickstart.md)부터 보세요. 더블클릭 데스크톱 앱이나 ZIP 하나로 오픈소스 고지문과 SBOM을 만듭니다. Docker 엔진은 필요하며, 무료 [Rancher Desktop](https://rancherdesktop.io/)을 권장합니다.

One Docker image, two jobs:

- **Generate** — scan your source code (or a container image / binary) and produce a CycloneDX SBOM, an open-source notice (고지문), and a security report.
- **Assess open-source risk** — analyze what you *receive*, including a supplier's finished SBOM or a firmware binary, and produce an open-source risk report (licenses + known vulnerabilities, with Critical-7d / High-30d remediation deadlines).

Every scan also emits the risk report by default. Run it from the CLI or a browser UI. Originally built by SK Telecom for supply-chain security, now open source.

Languages: Java, Python, Node.js, Ruby, PHP, Rust, Go, .NET, C/C++ (Conan/vcpkg). Inputs: source folder, GitHub URL, ZIP archive, Docker image, binary/RootFS, existing SBOM, firmware.

![SBOM Generator web UI — name a project, pick a scan target, and choose what to generate (SBOM, open-source notice, security report)](docs/images/web-ui.png)

## Quick Start

Prerequisite: a Docker engine, 20.10+. Free options that work on Windows: **Rancher Desktop** (GUI; supports the `.bat` double-click flow) or **WSL2 + docker-ce** (run the tool from inside WSL — fully free, no Windows named-pipe needed). Docker Desktop also works but requires a paid license for larger organizations. The Web UI needs nothing else; the Windows CLI wrapper additionally needs Git for Windows (Git Bash).

```bash
git clone https://github.com/sktelecom/sbom-tools.git && cd sbom-tools
docker pull ghcr.io/sktelecom/sbom-generator:latest   # legacy alias: sbom-scanner serves the same image
```

No git installed? Download the repo as a ZIP from the GitHub page (the green Code button, then Download ZIP) and unzip it.

### Web UI — easiest (no CLI needed)

Launch, scan, and download — all in the browser. Live logs stream as it runs.

![SBOM Generator web UI — a scan in progress with live logs](docs/images/web-ui-scan.png)

```bash
cd ~/sbom-output     # any folder — this is where results are saved
/path/to/sbom-tools/scripts/scan-sbom.sh --ui     # opens http://localhost:8080
#   Windows: double-click scripts\sbom-ui.bat
```

Enter the project name and version, pick a scan target (current folder, GitHub URL, ZIP, SBOM, firmware upload, or Docker image), click Run scan, then view or download the results.

#### Windows, no CLI — from a source ZIP you received

New to all this and just need the notice? Start with the [라이선스 담당자용 빠른 시작](docs/notice-quickstart.md) — a step-by-step Korean guide written for non-developers.

The common case for an open-source PM: a dev team handed you a source archive and you need its SBOM.

1. Install and start a Docker engine. **Rancher Desktop** is a free, drop-in choice for this double-click flow; Docker Desktop also works (with licensing caveats for organizations).
2. Get this repo: on the GitHub page use the green Code button, then Download ZIP, and unzip it.
3. Pick a folder for the results under your home directory, such as `C:\Users\you\sbom-output`. It must sit inside a path your Docker engine is allowed to share (file sharing); `C:\Users` is shared by default in both Rancher Desktop and Docker Desktop.
4. Double-click `scripts\sbom-ui.bat`. A browser opens at http://localhost:8080.
5. Enter a project name and version, choose ZIP upload as the scan target, upload the source ZIP you received, run the scan, then download the SBOM, the notice, and the risk report.

The [getting-started guide](docs/getting-started.md) covers this in more detail and shows the CLI path.

Prefer a real app over a `.bat`? A desktop app wraps this same flow with no console window — it checks Docker, pulls the image, and opens the UI on double-click. Download `SBOM-Generator-*.exe` (or `.dmg`) from the [latest release](https://github.com/sktelecom/sbom-tools/releases/latest). It is unsigned for now, so if Windows SmartScreen warns, click **More info** and then **Run anyway**. Build details are in [`electron/`](electron/README.md).

![SBOM Generator desktop app — the startup screen shows Docker checks, image download progress, and container startup](docs/images/desktop-startup.png)

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

Outputs (`{Project}_{Version}_…`): `bom.json` (SBOM), `NOTICE.{txt,html}` (고지문), `risk-report.{md,html}` (위험분석, default), and `security.{json,md,html}` (Trivy). Each input form is covered in the [scenarios guide](docs/scenarios-guide.md).

## Documentation

The web UI itself is bilingual (English and Korean, English by default). Core docs are available in English; the full set of guides is in Korean.

### English

| Doc | What |
|-----|------|
| [Getting started](docs/getting-started.en.md) | Install and your first SBOM (web UI + CLI) |
| [Usage guide](docs/usage-guide.en.md) | Every option, analysis modes, CI/CD |
| [Input scenarios](docs/scenarios-guide.en.md) | GitHub URL, ZIP, local C/C++, existing SBOM, firmware |
| [Architecture](docs/architecture.md) | Two-stage pipeline (cdxgen + syft, then post-processing) — _Korean_ |

### 한국어

| 문서 | 설명 |
|------|------|
| [라이선스 담당자용 빠른 시작](docs/notice-quickstart.md) | CLI 없이 웹 UI로 오픈소스 고지문 만들기 |
| [시작하기](docs/getting-started.md) | 설치 · 첫 SBOM (웹 UI 포함) |
| [시나리오 가이드](docs/scenarios-guide.md) | 입력 형태별(GitHub·ZIP·로컬·SBOM·펌웨어) 처리 |
| [사용 가이드](docs/usage-guide.md) | 전체 옵션 · 분석 모드 · CI/CD |
| [고지문·보안·UI](docs/notice-security-ui-guide.md) | 산출물과 웹 UI 사용법 |
| [아키텍처](docs/architecture.md) | 2-stage 파이프라인(cdxgen + syft → 후처리) |

> Docker 이미지의 가치(cdxgen 대비 측정)와 설계 배경은 [방향성 조사 보고서](docs/direction-study.md), Windows 데스크톱 앱 도입 검토는 [데스크톱 앱 검토 보고서](docs/desktop-app-study.md), 전체 문서는 [docs/](docs/)를 참고하세요.

## Contributing & License

Issues and PRs welcome — see [CONTRIBUTING.md](CONTRIBUTING.en.md) ([한국어](CONTRIBUTING.md)) and [GitHub Issues](https://github.com/sktelecom/sbom-tools/issues).

Apache License 2.0 · © 2026 SK Telecom Co., Ltd. Bundled third-party tools keep their own licenses — see [NOTICE](NOTICE) and [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).
