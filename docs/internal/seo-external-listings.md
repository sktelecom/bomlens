# 외부 등록 채널 (검색·AI 노출용)

작성일: 2026-06-13

BomLens를 외부 큐레이션 목록과 레지스트리에 올려 검색 노출과 AI 답변 인용, 백링크를 늘리기 위한 제출 자료입니다. 실제 제출은 메인테이너 계정으로 진행하되, 아래 스니펫을 그대로 쓰면 됩니다.

한 가지 사실관계 주의: CycloneDX Tool Center는 GitHub 토픽 `cyclonedx`만으로 자동 수집되지 않습니다. 토픽은 GitHub 내 검색 노출에만 쓰이고, Tool Center 등재는 별도 PR이 필요합니다.

## 공통 한 줄 설명 (영문 표준안)

> Local-first (no-SaaS) SBOM generator and open-source risk assessment tool. Generates CycloneDX 1.6 SBOMs, NOTICE files, and license/security risk reports from source code, container images, binaries, firmware, and ingested SBOMs. CLI and web UI. Apache-2.0.

분류: SBOM generation + Software Composition Analysis (SCA), 오픈소스 라이선스·보안 위험 보고.

## 우선순위

| 순위 | 채널 | 방법 | 난이도 | 효과 |
|------|------|------|--------|------|
| 1 | CycloneDX Tool Center | `tools/bomlens.json` 추가 PR | 낮음(스키마 준수) | 높음 — 공식 레지스트리, AI 인용 잦음 |
| 2 | awesomeSBOM/awesome-sbom | README 한 줄 PR | 낮음 | 중–높음 |
| 3 | bureado/awesome-software-supply-chain-security | README 항목 PR | 낮음 | 중–높음 |
| 4 | GitHub 토픽 | 저장소 설정에서 직접 추가 | 최저(PR 불필요) | 중 — 이미 적용됨 |
| 5 | magnologan/awesome-sca, hysnsec/awesome-sca | README 한 줄 PR | 낮음 | 중 |
| 6 | OWASP 정식 프로젝트 | New Project Request 폼 + 승인 | 높음 | 높지만 현실성 낮음(아래) |

## 1. CycloneDX Tool Center (1순위)

- 목록: <https://cyclonedx.org/tool-center/>, 저장소: <https://github.com/CycloneDX/tool-center>
- 방법: `tools.json`을 직접 고치지 말고 `tools/bomlens.json`을 추가하는 PR. `tool-center-v2.tool.schema.json` 스키마를 통과해야 함.
- 제출 전 enum 값(`functions`, `lifecycle`, `packaging` 등)을 최신 스키마(<https://cyclonedx.github.io/tool-center/>)로 한 번 검증할 것. 아래는 cdxgen 실제 엔트리 기준 초안.

```json
{
  "$schema": "https://cyclonedx.org/schema/tool-center-v2.tool.schema.json",
  "specVersion": "2.0",
  "tool": {
    "name": "BomLens",
    "publisher": "SK Telecom",
    "description": "Local-first (no-SaaS) SBOM generator and open source risk assessment tool. Produces CycloneDX 1.6 SBOMs, open source NOTICE files, and security/license risk reports from source code, container images, binaries, firmware, and ingested SBOMs. CLI and web UI.",
    "repository_url": "https://github.com/sktelecom/sbom-tools",
    "website_url": "https://github.com/sktelecom/sbom-tools",
    "capabilities": ["SBOM"],
    "availability": ["OPEN_SOURCE"],
    "functions": ["AUTHOR", "ANALYSIS"],
    "analysis": ["LICENSE_REPORTING"],
    "packaging": ["COMMAND_LINE_UTILITY", "CONTAINER_IMAGE"],
    "platform": ["LINUX", "MAC", "WINDOWS"],
    "lifecycle": ["BUILD", "POST-BUILD", "OPERATIONS"],
    "supportedStandards": ["CYCLONEDX", "PACKAGE_URL"],
    "cycloneDxVersion": ["CYCLONEDX_V1.6"],
    "supportedLanguages": ["C/C++", "GO", "JAVA", "JAVASCRIPT/TYPESCRIPT", ".NET", "NODE.JS", "PHP", "PYTHON", "RUBY", "RUST"]
  }
}
```

## 2. awesomeSBOM/awesome-sbom (2순위)

- 저장소: <https://github.com/awesomeSBOM/awesome-sbom> (README PR)
- Security Tools 또는 Community Repositories 섹션에 알파벳 순으로 한 줄 추가.

```markdown
[BomLens](https://github.com/sktelecom/sbom-tools) - Local-first SBOM generator and open source risk assessment tool that produces CycloneDX 1.6 SBOMs, NOTICE files, and license/security risk reports from source, containers, binaries, firmware, and ingested SBOMs. CLI and web UI.
```

## 3. bureado/awesome-software-supply-chain-security (3순위)

- 저장소: <https://github.com/bureado/awesome-software-supply-chain-security> (README PR)
- Dependency Intelligence 섹션. 큐레이션이 엄격하니 설명을 충실히.

```markdown
[sktelecom/sbom-tools (BomLens): local-first SBOM generator and open source risk assessment tool producing CycloneDX 1.6 SBOMs, NOTICE files, and license/security risk reports from source, containers, binaries, firmware and ingested SBOMs](https://github.com/sktelecom/sbom-tools) from [SK Telecom](https://www.sktelecom.com/)
```

## 5. awesome-sca 목록

- <https://github.com/magnologan/awesome-sca>, <https://github.com/hysnsec/awesome-sca> (각각 README PR)

```markdown
[BomLens](https://github.com/sktelecom/sbom-tools) - Local-first, open source SCA and SBOM tool generating CycloneDX 1.6 SBOMs and license/security risk reports across Java, Python, Node.js, Go, Ruby, PHP, Rust, .NET, and C/C++.
```

## 6. OWASP 정식 프로젝트 — 현실성 평가

효과는 크지만(owasp.org 백링크·신뢰도) 요건이 BomLens 성격과 충돌합니다. 신규 프로젝트는 Incubator로 시작하고, 리더 2명 이상이 **개인 자격**(회사·고용주와 결부 금지)으로 OWASP 멤버여야 하며 연 1회 릴리스 의무가 있습니다. SK Telecom이 만든 도구라는 정체성과 개인 리더십 요건이 부딪혀, 단기 노출 수단으로는 부적합합니다. 라이선스(Apache-2.0)는 OSI 승인이라 충족합니다. 대안으로, BomLens가 OWASP CycloneDX 표준을 따른다는 점을 문서에 명시하면 비용 없이 연관 검색을 얻습니다.

## 메인테이너 액션 순서

1. GitHub 토픽 — 이미 적용 완료(`sbom`, `cyclonedx`, `sca` 등 15개).
2. CycloneDX Tool Center `tools/bomlens.json` PR — 위 JSON을 최신 스키마로 검증 후 제출.
3. awesome-sbom, bureado 목록 한 줄 PR 2건.
4. awesome-sca 2곳 한 줄 PR (여력 시).
5. OWASP는 개인 자격 장기 운영 의향이 있을 때만 별건 검토.
