---
description: BomLens는 SaaS 없이 로컬에서 SBOM(CycloneDX 1.6)을 생성하고 오픈소스 리스크를 평가하는 도구입니다. 소스 코드, 컨테이너 이미지, 바이너리, 펌웨어, 받은 SBOM에서 SBOM과 오픈소스 고지문, 보안 위험 보고서를 한 번에 만듭니다.
hide:
  - toc
---

# 로컬에서 SBOM 생성과 오픈소스 위험 평가를 한 번에

SaaS 없이 로컬에서 단일 프로젝트의 [SBOM](concepts/what-is-sbom.ko.md)(CycloneDX 1.6)을 생성하고 오픈소스 리스크를 평가하는 도구입니다. 소스 코드, 컨테이너 이미지, 바이너리, 펌웨어, 받은 SBOM, HuggingFace AI 모델에서 SBOM과 오픈소스 고지문, 보안 위험 보고서를 한 번에 만듭니다. AI 모델은 CycloneDX ML-BOM을 만들고 [AI를 위한 G7 최소 요소](guides/ai-model.ko.md)로 검사합니다. 이 요소들은 EU 인공지능법(AI Act) Annex IV와 상당 부분 겹칩니다.

[시작하기](start/first-scan.ko.md){ .md-button .md-button--primary }
[데모 둘러보기](https://sktelecom.github.io/bomlens/demo/){ .md-button }
[Windows용 내려받기 (.exe)](https://github.com/sktelecom/bomlens/releases/latest/download/BomLens-Setup.exe){ .md-button }

[![최신 릴리스](https://img.shields.io/github/v/release/sktelecom/bomlens)](https://github.com/sktelecom/bomlens/releases/latest)
Windows 설치 파일은 Docker 엔진이 미리 켜져 있어야 동작합니다. 아래 [비개발자 빠른 시작](start/no-cli.ko.md)을 참고하세요.

설치하기 전에 결과가 어떤 모습인지 보고 싶다면 [데모](https://sktelecom.github.io/bomlens/demo/)를 둘러보세요. 입력 종류별로 완료된 스캔을 하나씩 담은 실제 웹 UI입니다. 소스로 스캔한 Spring Boot 프로젝트, 컨테이너 이미지, 언패킹한 기기 펌웨어 이미지, CycloneDX ML-BOM으로 만든 AI 모델, 그리고 형식 요건을 검사한 공급사 SBOM입니다. 설치할 것이 없고 아무것도 업로드되지 않습니다. 평범한 로컬 실행으로 나온 결과를 그대로 담아 둔 화면입니다.

CLI가 부담스럽다면 설치 파일을 받아 더블클릭하세요. 단계별 안내는 [비개발자 빠른 시작](start/no-cli.ko.md)에 있습니다. Docker 엔진이 필요하며, Windows에서는 무료 [Rancher Desktop](https://rancherdesktop.io/)이 잘 맞습니다.

![BomLens 웹 UI의 스캔 결과 — 수치와 심각도·라이선스 요약이 있는 개요, 필터가 있는 컴포넌트 표, 취약점 목록, 그래프와 트리로 보는 의존성, 라이선스 섹션](images/web-ui-demo.gif){ .home-shot }

## 무엇부터 볼까

<div class="grid cards" markdown>

-   :material-rocket-launch: __시작하기__

    설치부터 첫 SBOM 생성까지 (웹 UI와 CLI).

    [:octicons-arrow-right-24: 시작하기](start/first-scan.ko.md)

-   :material-cursor-default-click: __비개발자 빠른 시작__

    CLI 없이 데스크톱 앱으로 SBOM과 고지문 만들기.

    [:octicons-arrow-right-24: 빠른 시작](start/no-cli.ko.md)

-   :material-format-list-bulleted: __입력 시나리오__

    GitHub URL, ZIP, 로컬 소스, 기존 SBOM, 펌웨어별 처리.

    [:octicons-arrow-right-24: 시나리오 가이드](guides/by-input.ko.md)

-   :material-file-document-check: __공급사 SBOM 검증__

    받은 SBOM의 요구사항 충족 검증과 위험 보고서 발행.

    [:octicons-arrow-right-24: 공급사 SBOM 검증](guides/supplier-sbom.ko.md)

-   :material-robot-outline: __AI 모델 SBOM__

    HuggingFace 모델의 ML-BOM을 만들고 G7 최소 요소로 검사, EU 인공지능법과 대응.

    [:octicons-arrow-right-24: AI 모델 SBOM](guides/ai-model.ko.md)

-   :material-cog: __CLI 레퍼런스__

    전체 옵션, 분석 모드, CI/CD 연동.

    [:octicons-arrow-right-24: CLI 레퍼런스](reference/cli.ko.md)

-   :material-shield-check: __고지문과 보안 보고서__

    산출물 생성과 해석, 웹 UI 사용법.

    [:octicons-arrow-right-24: 고지문·보안 보고서](guides/reports.ko.md)

</div>
