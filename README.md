# SBOM Tools

> Automated Software Bill of Materials (SBOM) generation tool for supply chain security

[![GitHub release](https://img.shields.io/github/v/release/sktelecom/sbom-tools?style=flat-square)](https://github.com/sktelecom/sbom-tools/releases)
[![Docker Pulls](https://img.shields.io/docker/pulls/sktelecom/sbom-scanner?style=flat-square)](https://github.com/sktelecom/sbom-tools/pkgs/container/sbom-scanner)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg?style=flat-square)](LICENSE)

## Overview

SBOM Tools automatically generates Software Bill of Materials (SBOM) in [CycloneDX 1.6](https://cyclonedx.org/) format for multiple programming languages and environments, and can additionally produce an open-source notice and a Trivy-based security report. Originally developed by SK Telecom for supply chain security management, now available as open source.

### Key Features

- **Multi-language Support**: Java, Python, Node.js, Ruby, PHP, Rust, Go, .NET, C/C++ (Android opt-in)
- **Versatile Analysis Modes**: Source code, Docker images, binary files, RootFS
- **One-shot Outputs**: SBOM + open-source notice + Trivy security report (`--all`)
- **Browser UI**: `--ui` flag launches a local web interface for non-CLI users
- **Standard Format**: CycloneDX 1.6
- **Docker-based**: No language-specific runtime installation required on the host
- **Cross-platform**: Linux (AMD64, ARM64), macOS, Windows (Git Bash)

### Supported Languages & Tools

| Language | Package Managers | Analysis Tool |
|----------|-----------------|---------------|
| **Java** | Maven, Gradle | cdxgen |
| **Python** | pip, Poetry | cdxgen |
| **Node.js** | npm, Yarn, pnpm | cdxgen |
| **Ruby** | Bundler | cdxgen |
| **PHP** | Composer | cdxgen |
| **Rust** | Cargo | cdxgen |
| **Go** | Go modules | cdxgen |
| **.NET** | NuGet | cdxgen |
| **Docker Image** | — | syft |
| **Binary / RootFS** | — | syft |

## Quick Start

### Prerequisites

- Docker 20.10 or higher
- 4 GB+ available disk space

### Installation

```bash
# Clone the repository
git clone https://github.com/sktelecom/sbom-tools.git
cd sbom-tools

# Pull the scanner image
docker pull ghcr.io/sktelecom/sbom-scanner:latest
```

### Basic Usage

```bash
# Scan source code (run from project root)
./scripts/scan-sbom.sh --project "MyApp" --version "1.0.0" --generate-only

# Scan a Docker image
./scripts/scan-sbom.sh --project "MyApp" --version "1.0.0" \
  --target "nginx:latest" --generate-only

# Scan a binary file
./scripts/scan-sbom.sh --project "MyFirmware" --version "2.0.0" \
  --target "./firmware.bin" --generate-only

# Generate SBOM + open-source notice + security report in one run
./scripts/scan-sbom.sh --project "MyApp" --version "1.0.0" --all --generate-only

# Launch the browser-based UI (no CLI knowledge required)
./scripts/scan-sbom.sh --ui          # macOS/Linux
scripts\sbom-ui.bat                   # Windows (double-click)
```

Output files (CycloneDX 1.6 JSON):
- `{ProjectName}_{Version}_bom.json` — SBOM
- `{ProjectName}_{Version}_NOTICE.{txt,html}` — open-source notice (`--notice`)
- `{ProjectName}_{Version}_security.{json,md,html}` — Trivy security report (`--security`)

## Architecture

```
┌────────────────────────────────────────────────┐
│           scan-sbom.sh  (Wrapper Script)       │
│  • Parses arguments & detects target type      │
│  • Orchestrates Docker execution               │
└────────────────────────┬───────────────────────┘
                         │  docker run
                         ▼
┌────────────────────────────────────────────────┐
│        Docker Container (sbom-scanner)         │
│  ┌─────────────────────────────────────────┐   │
│  │     Multi-language Runtime Environment  │   │
│  │  JDK 17 · Python 3 · Node.js 20 · Ruby │   │
│  │  PHP · Rust · Go · .NET · Build Tools  │   │
│  └─────────────────────────────────────────┘   │
│  ┌──────────────────┐  ┌────────────────────┐  │
│  │ cdxgen           │  │ syft               │  │
│  │ (source code)    │  │ (images/binaries)  │  │
│  └──────────────────┘  └────────────────────┘  │
└────────────────────────┬───────────────────────┘
                         │
                         ▼
                  CycloneDX 1.4 SBOM (.json)
```

See [docs/architecture.md](docs/architecture.md) for details (Korean).

## Why a Docker image? (vs plain cdxgen)

Fair question: cdxgen already installs dependencies internally, so do you even need this image? We measured **cdxgen's official image** (which ships its own toolchain and resolves deps on its own) against this image, on the bundled examples (no lockfiles committed):

| Project | cdxgen official | this image | Δ |
|---------|---:|---:|---|
| dotnet · java-maven · java-gradle · php · python | same | same | — |
| nodejs | 471 | 493 | +5% |
| **go** | 3 | 19 | **+533%** |
| **ruby** | 0 | 9 | **cdxgen finds none** |
| **rust** | 5 | 180 | **+3500%** |

**For mainstream languages (Java, Python, Node, .NET, PHP), cdxgen's official image is enough** — detection is identical. The difference shows up in **go, ruby, rust**, where this image ships the toolchain cdxgen's image lacks (cargo, bundler, full go) and resolves far more (ruby: nothing → 9; rust: 36×).

So the value of this image is **(1)** broad language coverage in one pull (no picking per-language cdxgen images), **(2)** things cdxgen doesn't do at all — syft (image/binary/RootFS), OSS notice, Trivy security report, web UI — and **(3)** pinned tool versions + deterministic output. It is **not** a blanket "many× more components" claim for every language.

Reproduce it yourself:

```bash
./tests/compare-cdxgen-vs-docker.sh   # cdxgen official vs this image → tests/test-workspace/compare-result.csv
```

See [docs/direction-study.md](docs/direction-study.md) for methodology.

## Documentation (한국어)

| 문서 | 설명 |
|------|------|
| [시작하기](docs/getting-started.md) | 설치, 환경 설정, 첫 SBOM 생성 |
| [사용 가이드](docs/usage-guide.md) | 전체 옵션, 분석 모드, CI/CD 통합, 트러블슈팅 |
| [예제 가이드](docs/examples-guide.md) | 언어별 예제 프로젝트 실습 |
| [아키텍처](docs/architecture.md) | 시스템 구조 및 설계 원칙 |
| [고지문·보안·UI 가이드](docs/notice-security-ui-guide.md) | 고지문, 보안 보고서, 웹 UI 사용법 |
| [방향성 조사 보고서](docs/direction-study.md) | Docker 스캔의 가치, 커버리지, 고지문·보안보고서·UI 로드맵 |
| [테스트 가이드](docs/contributing/testing-guide.md) | 테스트 작성 및 실행 |
| [패키지 매니저 추가](docs/contributing/package-manager-guide.md) | 새로운 언어/패키지 매니저 지원 추가 |
| [기여하기](CONTRIBUTING.md) | 기여 절차 및 코딩 규칙 |

## Testing

```bash
./tests/test-scan.sh                    # 기본 실행
VERBOSE=true ./tests/test-scan.sh       # 상세 출력
DEBUG_MODE=true ./tests/test-scan.sh    # 디버그 모드
```

## Contributing

We welcome contributions of all kinds — bug fixes, new language support, documentation improvements, and more.

- **Bug reports**: [GitHub Issues](https://github.com/sktelecom/sbom-tools/issues)
- **Feature requests**: [GitHub Discussions](https://github.com/sktelecom/sbom-tools/discussions)
- **Code contributions**: [CONTRIBUTING.md](CONTRIBUTING.md) (Korean)

## License

Apache License 2.0 — Copyright 2026 SK Telecom Co., Ltd.  
See [LICENSE](LICENSE) for details.

## Acknowledgments

- [CycloneDX](https://cyclonedx.org/) — SBOM standard
- [cdxgen](https://github.com/CycloneDX/cdxgen) — Source code analysis
- [Syft](https://github.com/anchore/syft) — Container & binary analysis

---

Made by SK Telecom Open Source Team · [opensource@sktelecom.com](mailto:opensource@sktelecom.com)
