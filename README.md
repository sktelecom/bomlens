# SBOM Tools

> Automated SBOM (CycloneDX 1.6) generation for supply chain security

[![GitHub release](https://img.shields.io/github/v/release/sktelecom/sbom-tools?style=flat-square)](https://github.com/sktelecom/sbom-tools/releases)
[![Docker Pulls](https://img.shields.io/docker/pulls/sktelecom/sbom-scanner?style=flat-square)](https://github.com/sktelecom/sbom-tools/pkgs/container/sbom-scanner)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg?style=flat-square)](LICENSE)

One Docker image generates an **SBOM** from source code, container images, binaries, or firmware — and, in the same run, an **open-source notice**, an **open-source risk report**, and a **Trivy security report**. Use the **CLI** or the **browser UI**. Originally built by SK Telecom, now open source.

Languages: Java, Python, Node.js, Ruby, PHP, Rust, Go, .NET, C/C++ (Conan/vcpkg). Also Docker images, binaries, RootFS, and firmware.

## Quick Start

Prerequisite: Docker 20.10+.

```bash
git clone https://github.com/sktelecom/sbom-tools.git && cd sbom-tools
docker pull ghcr.io/sktelecom/sbom-scanner:latest
```

### Web UI — easiest (no CLI needed)

**launch → scan → download**, in the browser. Live logs stream as it runs.

![SBOM Tools web UI — a scan in progress with live logs](docs/images/web-ui-scan.png)

```bash
cd ~/sbom-output     # any folder — this is where results are saved
/path/to/sbom-tools/scripts/scan-sbom.sh --ui     # opens http://localhost:8080
#   Windows: double-click scripts\sbom-ui.bat
```

Enter **project + version**, pick an **input type** (current directory / GitHub URL / ZIP / SBOM / firmware upload / Docker image), click **Run scan**, then view/download the results.

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

**Outputs** (`{Project}_{Version}_…`): `bom.json` (SBOM) · `NOTICE.{txt,html}` (고지문) · `risk-report.{md,html}` (위험분석, default) · `security.{json,md,html}` (Trivy). Each input form is covered in the [scenarios guide](docs/scenarios-guide.md).

## Documentation (한국어)

| 문서 | 설명 |
|------|------|
| [시작하기](docs/getting-started.md) | 설치 · 첫 SBOM (웹 UI 포함) |
| [시나리오 가이드](docs/scenarios-guide.md) | 입력 형태별(GitHub·ZIP·로컬·SBOM·펌웨어) 처리 |
| [사용 가이드](docs/usage-guide.md) | 전체 옵션 · 분석 모드 · CI/CD |
| [고지문·보안·UI](docs/notice-security-ui-guide.md) | 산출물과 웹 UI 사용법 |
| [아키텍처](docs/architecture.md) | 2-stage 파이프라인(cdxgen + syft → 후처리) |

> Docker 이미지의 가치(cdxgen 대비 측정)와 설계 배경은 [방향성 조사 보고서](docs/direction-study.md), 전체 문서는 [docs/](docs/)를 참고하세요.

## Contributing & License

Issues and PRs welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) (한국어) and [GitHub Issues](https://github.com/sktelecom/sbom-tools/issues).

Apache License 2.0 · © 2026 SK Telecom Co., Ltd. Bundled third-party tools keep their own licenses — see [NOTICE](NOTICE) and [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).
